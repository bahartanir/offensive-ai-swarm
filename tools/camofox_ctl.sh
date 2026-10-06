#!/usr/bin/env bash
# camofox_ctl.sh — manage the local camofox-browser server lifecycle.
#
# Wraps the npm project at $CAMOFOX_DIR so agents don't deal with nohup/pkill
# directly. See docs/stealth-browsing.md for usage.
#
# Commands:
#   start   — launch server in background, wait up to 20s for /health
#   stop    — kill the server
#   status  — print running pid + /health JSON, or "stopped"
#   logs    — tail the last 100 lines of the server log

set -euo pipefail

CAMOFOX_DIR="${CAMOFOX_DIR:-/root/tools/camofox-browser}"
PID_FILE="${CAMOFOX_PID_FILE:-/tmp/camofox.pid}"
LOG_FILE="${CAMOFOX_LOG_FILE:-/tmp/camofox.log}"
HEALTH_URL="${CAMOFOX_HEALTH_URL:-http://localhost:9377/health}"

cmd="${1:-status}"

is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

case "$cmd" in
start)
  if is_running; then
    echo "already running (pid $(cat "$PID_FILE"))"
    exit 0
  fi
  if [[ ! -d "$CAMOFOX_DIR" ]]; then
    echo "CAMOFOX_DIR not found: $CAMOFOX_DIR" >&2
    exit 1
  fi
  (
    cd "$CAMOFOX_DIR" && nohup npm start >"$LOG_FILE" 2>&1 &
    echo "$!" >"$PID_FILE"
  )
  echo "started pid $(cat "$PID_FILE"), log $LOG_FILE"
  for _ in $(seq 1 20); do
    if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
      echo "ready"
      exit 0
    fi
    sleep 1
  done
  echo "timeout waiting for /health — tail $LOG_FILE" >&2
  exit 1
  ;;
stop)
  if is_running; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
  pkill -f "node server.js" 2>/dev/null || true
  echo "stopped"
  ;;
status)
  if is_running; then
    echo "running pid $(cat "$PID_FILE")"
    curl -sf "$HEALTH_URL" 2>/dev/null | jq . || echo "(health endpoint did not respond)"
  else
    echo "stopped"
  fi
  ;;
logs)
  if [[ -f "$LOG_FILE" ]]; then
    tail -n 100 "$LOG_FILE"
  else
    echo "no log file at $LOG_FILE"
  fi
  ;;
*)
  echo "usage: $0 {start|stop|status|logs}" >&2
  exit 1
  ;;
esac
