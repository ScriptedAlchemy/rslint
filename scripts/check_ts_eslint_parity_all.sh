#!/usr/bin/env bash
set -euo pipefail

parity_artifacts_dirty() {
  [[ -n "$(git -C /workspace status --porcelain -- \
    "typescript-eslint-rule-parity-*.md" \
    "typescript-eslint-rule-parity-*.json" \
    "typescript-eslint-rule-parity-*.csv")" ]]
}

echo "[parity-check-all] Running artifact consistency check"
python3 /workspace/scripts/check_ts_eslint_parity_artifacts.py

echo "[parity-check-all] Running tooling/docs synchronization check"
python3 /workspace/scripts/check_ts_eslint_parity_tooling_sync.py

if ! parity_artifacts_dirty; then
  echo "[parity-check-all] Running reproducibility verification"
  bash /workspace/scripts/verify_ts_eslint_parity_clean.sh
else
  if [[ "${PARITY_CHECK_ALL_REQUIRE_CLEAN:-0}" == "1" ]]; then
    echo "[parity-check-all] ERROR: parity artifacts are dirty; reproducibility verification skipped." >&2
    echo "[parity-check-all] Commit/stash parity artifact changes or unset PARITY_CHECK_ALL_REQUIRE_CLEAN." >&2
    exit 1
  fi
  echo "[parity-check-all] Skipping reproducibility verification because parity artifacts are dirty."
  echo "[parity-check-all] Tip: run with a clean tree to include verify-clean."
fi

echo "[parity-check-all] OK: all parity checks passed."
