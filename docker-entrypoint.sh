#!/bin/sh
# One-command onboarding for the tjakra-satria patrol agent in Docker.
#
# A bare `docker run ... tjakradev/tjakra-satria-agent` reads SERVER and ENROLL_TOKEN
# from the environment: on first boot, if no enrolled config exists at CONFIG, it
# enrolls (single-use token) and writes the scoped config to the data volume, then
# runs. The token is only ever read from the environment at run time; it is never
# baked into an image layer and is written nowhere but the 0600 config the binary
# creates. Run flags come from the environment too (ENFORCE, CONSOLE, LOG_FILE,
# BLOCK_CONTAINER, POLL, INSECURE).
#
# Passing an explicit subcommand (`enroll ...` or `run ...`) bypasses all of this
# and runs the binary directly, so the manual two-step flow still works.
set -eu

BIN=/usr/local/bin/tjakra-satria-agent
CONFIG="${CONFIG:-/data/agent.json}"

# Advanced/manual mode: an explicit subcommand runs the binary as-is.
if [ "${1:-}" = "enroll" ] || [ "${1:-}" = "run" ]; then
  exec "$BIN" "$@"
fi

INSECURE_FLAG=""
case "${INSECURE:-}" in
  1 | true | TRUE | yes) INSECURE_FLAG="-insecure" ;;
esac

if [ ! -f "$CONFIG" ]; then
  if [ -n "${ENROLL_TOKEN:-}" ] && [ -n "${SERVER:-}" ]; then
    echo "no config at $CONFIG; enrolling against $SERVER"
    if [ -n "$INSECURE_FLAG" ]; then
      "$BIN" enroll -server "$SERVER" -token "$ENROLL_TOKEN" -config "$CONFIG" "$INSECURE_FLAG"
    else
      "$BIN" enroll -server "$SERVER" -token "$ENROLL_TOKEN" -config "$CONFIG"
    fi
  else
    echo "no config at $CONFIG, and SERVER/ENROLL_TOKEN are not set." >&2
    echo "pass -e SERVER=<platform api url> -e ENROLL_TOKEN=<one-time token>, or mount an enrolled agent.json at $CONFIG." >&2
    exit 1
  fi
else
  # A config already exists on the data volume, so we do not re-enroll: the token
  # is single-use. But reconcile the server URL from the SERVER env, matching the
  # install.sh --server behavior. The agent reads the platform URL only from the
  # config, so a container restarted with a changed SERVER (repointed at a renamed
  # host) would otherwise keep polling the old URL silently. This repoints the
  # agent in place without spending a fresh enrollment token.
  if [ -n "${SERVER:-}" ]; then
    CURRENT=$(sed -n 's/.*"server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -1)
    if [ -n "$CURRENT" ] && [ "$CURRENT" != "$SERVER" ]; then
      cp "$CONFIG" "$CONFIG.bak"
      tmp=$(mktemp)
      sed "s#\"server\"[[:space:]]*:[[:space:]]*\"$CURRENT\"#\"server\": \"$SERVER\"#" "$CONFIG" > "$tmp"
      cat "$tmp" > "$CONFIG"
      rm -f "$tmp"
      chmod 0600 "$CONFIG"
      echo "repointed agent: $CURRENT -> $SERVER (previous config kept at $CONFIG.bak)"
    fi
  fi
fi

# Assemble the run flags from the environment.
set -- run -config "$CONFIG"
if [ -n "${LOG_FILE:-}" ]; then set -- "$@" -log-file "$LOG_FILE"; fi
case "${ENFORCE:-}" in 1 | true | TRUE | yes) set -- "$@" -enforce ;; esac
case "${CONSOLE:-}" in 1 | true | TRUE | yes) set -- "$@" -console ;; esac
if [ -n "${BLOCK_CONTAINER:-}" ]; then set -- "$@" -block-container "$BLOCK_CONTAINER"; fi
if [ -n "${POLL:-}" ]; then set -- "$@" -poll "$POLL"; fi
if [ -n "$INSECURE_FLAG" ]; then set -- "$@" "$INSECURE_FLAG"; fi

echo "starting: $BIN $*"
exec "$BIN" "$@"
