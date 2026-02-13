#!/usr/bin/env bash
set -euo pipefail

parity_artifact_status() {
  git -C /workspace status --porcelain -- \
    "typescript-eslint-rule-parity-*.md" \
    "typescript-eslint-rule-parity-*.json" \
    "typescript-eslint-rule-parity-*.csv"
}

parity_artifacts_dirty() {
  [[ -n "$(parity_artifact_status)" ]]
}

if [[ "${PARITY_VERIFY_ALLOW_DIRTY:-0}" != "1" ]]; then
  if parity_artifacts_dirty; then
    echo "[parity-verify] ERROR: parity artifacts are already dirty." >&2
    echo "[parity-verify] Dirty parity artifact entries:" >&2
    parity_artifact_status >&2
    echo "[parity-verify] Commit/stash parity artifact changes first, or set PARITY_VERIFY_ALLOW_DIRTY=1." >&2
    exit 1
  fi
fi

echo "[parity-verify] Rebuilding from metadata commit"
bash /workspace/scripts/rebuild_ts_eslint_parity_from_metadata.sh

echo "[parity-verify] Checking parity artifact status is clean"
if parity_artifacts_dirty; then
  echo "[parity-verify] ERROR: parity artifacts changed after metadata rebuild." >&2
  parity_artifact_status >&2
  exit 1
fi

echo "[parity-verify] OK: parity artifacts are reproducible and clean."
