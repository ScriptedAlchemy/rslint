#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_DIR="/tmp/typescript-eslint"
UPSTREAM_REPO="https://github.com/typescript-eslint/typescript-eslint"

echo "==> Preparing upstream repository"
if [[ ! -d "${UPSTREAM_DIR}/.git" ]]; then
  echo "Cloning ${UPSTREAM_REPO} into ${UPSTREAM_DIR}"
  git clone --depth 1 "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
else
  echo "Updating ${UPSTREAM_DIR}"
  git -C "${UPSTREAM_DIR}" fetch --depth 1 origin main
  git -C "${UPSTREAM_DIR}" reset --hard FETCH_HEAD
fi

echo "==> Generating parity tracker artifacts"
python3 scripts/generate_ts_eslint_parity_tracker.py
python3 scripts/generate_ts_eslint_parity_worklist.py
python3 scripts/generate_ts_eslint_parity_summary.py
python3 scripts/generate_ts_eslint_parity_metadata.py

echo "==> Validating parity artifact consistency"
python3 scripts/check_ts_eslint_parity_artifacts.py

echo "==> Done"
echo "Generated files:"
echo "  - typescript-eslint-rule-parity-tracker.csv"
echo "  - typescript-eslint-rule-parity-tracker.json"
echo "  - typescript-eslint-rule-parity-worklist.md"
echo "  - typescript-eslint-rule-parity-summary.md"
echo "  - typescript-eslint-rule-parity-metadata.json"
