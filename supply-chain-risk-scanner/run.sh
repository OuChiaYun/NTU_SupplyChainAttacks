#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="supply-chain-risk-scanner"
PROJECT_DIR="$PWD/examples/demo-project"
RESULTS_DIR="$PWD/results"

echo "[1/3] Building Docker image..."
docker build --no-cache -t "$IMAGE_NAME" .

echo "[2/3] Preparing results directory..."
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

echo "[3/3] Running scanner..."
docker run --rm \
  -v "$PROJECT_DIR:/project:ro" \
  -v "$RESULTS_DIR:/results" \
  "$IMAGE_NAME"

echo ""
echo "Scan finished."
echo "HTML report:"
echo "$RESULTS_DIR/report.html"