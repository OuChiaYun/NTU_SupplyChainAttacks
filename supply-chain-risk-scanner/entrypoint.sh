#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-scan}"

if [ "$MODE" = "install-demo" ]; then
  echo "[install-demo] Running npm install in /project"
  echo "[install-demo] This mode intentionally triggers dependency lifecycle scripts."
  echo "[install-demo] If demo-malicious-tool has postinstall, it should run now."
  echo ""

  cd /project
  npm install --foreground-scripts

  echo ""
  echo "[install-demo] Finished npm install."
  echo "[install-demo] Checking demo log:"
  if [ -f /project/postinstall-demo-log.json ]; then
    cat /project/postinstall-demo-log.json
  else
    echo "postinstall-demo-log.json not found."
  fi

  exit 0
fi

python3 /scanner/main.py
