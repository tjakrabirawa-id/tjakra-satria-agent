#!/bin/sh
# install.sh: one-command installer for the tjakra-satria patrol agent on a systemd
# Linux host. It resolves or builds the binary, installs it to /usr/local/bin,
# enrolls with the one-time token, writes the config, and installs and starts a
# systemd service. Re-running updates the unit and restarts the service.
#
# Usage:
#   sudo ./install.sh --token <ENROLL_TOKEN> --server <PLATFORM_URL> \
#     [--log-file <path>] [--enforce] [--console] [--binary <path>] \
#     [--insecure] [--re-enroll]
#
# The token is passed only to the enroll step. This script never prints it and
# never writes it to the unit, the config, or any log.

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

BIN_DEST=/usr/local/bin/tjakra-satria-agent
CONFIG_DIR=/etc/tjakra-satria-agent
CONFIG_PATH="$CONFIG_DIR/agent.json"
UNIT_PATH=/etc/systemd/system/tjakra-satria-agent.service
SERVICE=tjakra-satria-agent.service

TOKEN=""
SERVER=""
LOG_FILE=""
ENFORCE=0
CONSOLE=0
BINARY=""
INSECURE=0
RE_ENROLL=0

SRC_BIN=""
BUILD_OUT=""

cleanup() {
	if [ -n "${BUILD_OUT:-}" ] && [ -f "${BUILD_OUT:-}" ]; then
		rm -f "$BUILD_OUT"
	fi
}
trap cleanup EXIT

usage() {
	cat >&2 <<'EOF'
Usage: sudo ./install.sh --token <ENROLL_TOKEN> --server <PLATFORM_URL> [options]

Required:
  --token <token>     One-time enrollment token from the platform.
  --server <url>      Platform API base URL, e.g. https://pentest-api.tjakrabirawa.id

Options:
  --log-file <path>   Log file the agent tails and ships up.
  --enforce           Apply destructive actions (iptables, usermod). Off by default.
  --console           Enable the admin remote console (run_command). Off by default.
  --binary <path>     Use this prebuilt agent binary instead of building from source.
  --insecure          Skip TLS verification (dev only). Applies to enroll and run.
  --re-enroll         Re-run enroll even if a config already exists (needs a fresh token).

Run as root (sudo). Requires systemd. If --binary is not given, Go must be
installed so the binary can be built from this repo.
EOF
	exit 2
}

while [ $# -gt 0 ]; do
	arg="$1"
	case "$arg" in
		--token|--server|--log-file|--binary)
			if [ $# -lt 2 ]; then
				echo "option $arg needs a value" >&2
				usage
			fi
			val="$2"
			shift 2
			case "$arg" in
				--token) TOKEN="$val" ;;
				--server) SERVER="$val" ;;
				--log-file) LOG_FILE="$val" ;;
				--binary) BINARY="$val" ;;
			esac
			;;
		--enforce) ENFORCE=1; shift ;;
		--console) CONSOLE=1; shift ;;
		--insecure) INSECURE=1; shift ;;
		--re-enroll) RE_ENROLL=1; shift ;;
		-h|--help) usage ;;
		*) echo "unknown argument: $arg" >&2; usage ;;
	esac
done

if [ -z "$TOKEN" ]; then
	echo "missing required --token" >&2
	usage
fi
if [ -z "$SERVER" ]; then
	echo "missing required --server" >&2
	usage
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh must run as root; re-run with sudo" >&2
	exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
	echo "systemctl not found; this installer targets systemd hosts" >&2
	exit 1
fi

# Resolve the binary: an explicit --binary wins, otherwise build from source if
# Go is present, otherwise stop and tell the operator to provide one.
if [ -n "$BINARY" ]; then
	if [ ! -f "$BINARY" ]; then
		echo "binary not found: $BINARY" >&2
		exit 1
	fi
	SRC_BIN="$BINARY"
elif command -v go >/dev/null 2>&1; then
	echo "building the agent from source in $SCRIPT_DIR"
	BUILD_OUT=$(mktemp)
	( cd "$SCRIPT_DIR" && go build -o "$BUILD_OUT" . )
	SRC_BIN="$BUILD_OUT"
else
	echo "no --binary given and go is not installed." >&2
	echo "build the binary on a machine with Go and pass it with --binary <path>:" >&2
	echo "  GOOS=linux GOARCH=amd64 go build -o tjakra-satria-agent ." >&2
	exit 1
fi

# Stop a running instance so replacing the binary does not hit "text file busy".
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
	echo "stopping running $SERVICE before update"
	systemctl stop "$SERVICE" || true
fi

install -m 0755 "$SRC_BIN" "$BIN_DEST"
echo "installed binary to $BIN_DEST"

mkdir -p "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

# Enroll unless a config already exists. Enroll tokens are single-use, so a plain
# re-run does not try to spend the token again; pass --re-enroll with a fresh
# token to replace an existing enrollment.
if [ -s "$CONFIG_PATH" ] && [ "$RE_ENROLL" -eq 0 ]; then
	echo "config already exists at $CONFIG_PATH; skipping enroll"
	echo "(use --re-enroll with a fresh token to replace the enrollment)"
	# Reconcile the server URL. The agent reads it only from the config file, so
	# without this an operator passing --server against an existing install gets a
	# clean run and no change at all: the platform URL is silently still the old
	# one. That is the supported way to repoint an agent at a renamed host, and it
	# must not require re-enrolling, which would spend a fresh token and leave a
	# duplicate agent registered.
	if [ -n "$SERVER" ]; then
		CURRENT=$(sed -n 's/.*"server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_PATH" | head -1)
		if [ -n "$CURRENT" ] && [ "$CURRENT" != "$SERVER" ]; then
			cp "$CONFIG_PATH" "$CONFIG_PATH.bak"
			tmp=$(mktemp)
			sed "s#\"server\"[[:space:]]*:[[:space:]]*\"$CURRENT\"#\"server\": \"$SERVER\"#" "$CONFIG_PATH" > "$tmp"
			cat "$tmp" > "$CONFIG_PATH"
			rm -f "$tmp"
			chmod 0600 "$CONFIG_PATH"
			echo "repointed agent: $CURRENT -> $SERVER (previous config kept at $CONFIG_PATH.bak)"
		fi
	fi
else
	set -- enroll -server "$SERVER" -token "$TOKEN" -config "$CONFIG_PATH"
	if [ "$INSECURE" -eq 1 ]; then
		set -- "$@" -insecure
	fi
	"$BIN_DEST" "$@"
	chmod 0600 "$CONFIG_PATH"
fi

# Migrate a host installed under the pre-SATRIA identity. Without this a
# rebranded installer leaves the old unit enabled and the host ends up running
# two agents that share one enrollment, double-polling the platform.
LEGACY_SERVICE=tjakra-ap-agent.service
LEGACY_CONFIG=/etc/tjakra-ap-agent/agent.json
if [ -f "/etc/systemd/system/$LEGACY_SERVICE" ]; then
	echo "found a pre-rebrand install; migrating"
	systemctl stop "$LEGACY_SERVICE" 2>/dev/null || true
	systemctl disable "$LEGACY_SERVICE" 2>/dev/null || true
	if [ -s "$LEGACY_CONFIG" ] && [ ! -s "$CONFIG_PATH" ]; then
		install -m 0600 "$LEGACY_CONFIG" "$CONFIG_PATH"
		echo "carried the existing enrollment over; no new token needed"
	fi
	rm -f "/etc/systemd/system/$LEGACY_SERVICE" /usr/local/bin/tjakra-ap-agent
	systemctl daemon-reload 2>/dev/null || true
fi

# Build the run flags for ExecStart.
EXEC_FLAGS=""
if [ -n "$LOG_FILE" ]; then
	EXEC_FLAGS="$EXEC_FLAGS -log-file \"$LOG_FILE\""
fi
if [ "$ENFORCE" -eq 1 ]; then
	EXEC_FLAGS="$EXEC_FLAGS -enforce"
fi
if [ "$CONSOLE" -eq 1 ]; then
	EXEC_FLAGS="$EXEC_FLAGS -console"
fi
if [ "$INSECURE" -eq 1 ]; then
	EXEC_FLAGS="$EXEC_FLAGS -insecure"
fi
EXEC_FLAGS=$(printf '%s' "$EXEC_FLAGS" | sed 's/^ *//')

# Write the systemd unit. This installer writes the root variant. The standalone
# tjakra-satria-agent.service template documents the non-login-user and
# CAP_NET_ADMIN variants for a hardened setup; keep the two in sync if you edit
# either.
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=tjakra-satria patrol agent (Defence and Response)
Documentation=https://github.com/tjakrabirawa-id/tjakra-satria-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DEST run -config $CONFIG_PATH $EXEC_FLAGS
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_PATH"
echo "wrote unit to $UNIT_PATH"

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

echo
echo "tjakra-satria-agent installed and started."
systemctl --no-pager --full status "$SERVICE" || true
echo
echo "Follow logs:   journalctl -u $SERVICE -f"
echo "Confirm it is connected: on the platform (NSOC / Patrol agent list) the"
echo "agent's last check-in advances every poll interval. You can also issue a"
echo "run_collector command from the platform; it is non-destructive and returns"
echo "the host's hostname, os, and arch."
