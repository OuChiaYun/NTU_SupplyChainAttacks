#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="supply-chain-risk-scanner"
PROJECT_DIR="$(pwd)/examples/demo-project"

echo "[1/3] Cleaning up previous run artifacts..."
rm -rf "$PROJECT_DIR/node_modules"
rm -f  "$PROJECT_DIR/postinstall-demo-log.json"

echo "[2/3] Building Docker image..."
docker build --no-cache -t "$IMAGE_NAME" .

echo "[3/3] Running install-time behavior demo..."
docker run --rm \
  -e MODE=install-demo \
  -v "$PROJECT_DIR:/project" \
  "$IMAGE_NAME"