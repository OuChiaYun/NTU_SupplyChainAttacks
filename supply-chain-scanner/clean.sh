#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-$PWD/results}"

echo "This will delete generated scanner results:"
echo "$RESULTS_DIR"
echo ""

read -r -p "Continue? [y/N] " answer

case "$answer" in
  y|Y|yes|YES)
    rm -rf "$RESULTS_DIR"
    echo "Deleted: $RESULTS_DIR"
    ;;
  *)
    echo "Cancelled."
    ;;
esac