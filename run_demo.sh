#!/usr/bin/env bash
# One-command demo: starts the vulnerable AcmeCorp demo app, runs the full
# red-team attack suite against it, generates the Markdown report, then
# shuts the demo app down.
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-5001}"
TARGET="http://127.0.0.1:${PORT}"
LOG_FILE="$(mktemp)"

echo "Starting AcmeCorp demo app on ${TARGET} ..."
PORT="${PORT}" python3 demo_app/app.py > "${LOG_FILE}" 2>&1 &
APP_PID=$!

cleanup() {
  echo "Stopping demo app (pid ${APP_PID}) ..."
  kill "${APP_PID}" 2>/dev/null || true
  wait "${APP_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Waiting for the demo app to become healthy ..."
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "${TARGET}/health"; then
    break
  fi
  sleep 0.3
done

if ! curl -s -o /dev/null "${TARGET}/health"; then
  echo "Demo app failed to start. Log:"
  cat "${LOG_FILE}"
  exit 1
fi

echo "Running the red-team attack suite ..."
python3 cli.py run --target "${TARGET}" \
  --out reports/latest_report.md \
  --json reports/latest_run.json

echo
echo "Done. Report: reports/latest_report.md"
