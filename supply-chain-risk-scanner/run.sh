#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="npm-supply-chain-risk-gate"
PROJECT_DIR="$(pwd)/examples/demo-project"
RESULTS_DIR="$(pwd)/results"

# ── Step 1: Build scanner image ───────────────────────────────────────────────
echo "[1/3] Building scanner Docker image..."
docker build --no-cache -t "$IMAGE_NAME" .

# ── Step 2: Prepare results dir ───────────────────────────────────────────────
echo ""
echo "[2/3] Preparing results directory..."
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# ── Step 3: Run scanner ───────────────────────────────────────────────────────
echo ""
echo "[3/3] Running scanner..."
docker run --rm \
  -v "$PROJECT_DIR:/project:ro" \
  -v "$RESULTS_DIR:/results" \
  "$IMAGE_NAME"

echo ""
echo "Scan finished."
echo "HTML report: $RESULTS_DIR/report.html"
