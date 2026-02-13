#!/usr/bin/env bash
set -euo pipefail

if [[ "${PARITY_VERIFY_ALLOW_DIRTY:-0}" != "1" ]]; then
  if ! git -C /workspace diff --quiet -- \
    "typescript-eslint-rule-parity-*.md" \
    "typescript-eslint-rule-parity-*.json" \
    "typescript-eslint-rule-parity-*.csv"; then
    echo "[parity-verify] ERROR: parity artifacts are already dirty." >&2
    echo "[parity-verify] Commit/stash parity artifact changes first, or set PARITY_VERIFY_ALLOW_DIRTY=1." >&2
    exit 1
  fi
fi

echo "[parity-verify] Rebuilding from metadata commit"
bash /workspace/scripts/rebuild_ts_eslint_parity_from_metadata.sh

echo "[parity-verify] Checking parity artifact diff is clean"
git -C /workspace diff --exit-code -- \
  "typescript-eslint-rule-parity-*.md" \
  "typescript-eslint-rule-parity-*.json" \
  "typescript-eslint-rule-parity-*.csv"

echo "[parity-verify] OK: parity artifacts are reproducible and clean."
