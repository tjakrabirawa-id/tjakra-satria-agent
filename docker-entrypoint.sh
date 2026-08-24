#!/bin/sh
# One-command onboarding for the tjakra-ap patrol agent in Docker.
#
# A bare `docker run ... aldovadev/tjakra-ap-agent` reads SERVER and ENROLL_TOKEN
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

BIN=/usr/local/bin/tjakra-ap-agent
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
