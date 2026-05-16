#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="npm-supply-chain-scanner"
PROJECT_DIR="${PROJECT_DIR:-$PWD/examples/demo-project}"
RESULTS_DIR="${RESULTS_DIR:-$PWD/results}"
NPQ_SCOPE="${NPQ_SCOPE:-direct}"

echo "[1/3] Building Docker image..."
docker build -t "$IMAGE_NAME" .

echo "[2/3] Preparing results directory..."
mkdir -p "$RESULTS_DIR"

echo "[3/3] Running scanner..."
docker run --rm \
  -v "$PROJECT_DIR:/project:ro" \
  -v "$RESULTS_DIR:/results" \
  "$IMAGE_NAME" \
  --project /project \
  --out /results \
  --npq-scope "$NPQ_SCOPE"

echo ""
echo "Scan finished."
echo "HTML report:"
echo "$RESULTS_DIR/report.html"