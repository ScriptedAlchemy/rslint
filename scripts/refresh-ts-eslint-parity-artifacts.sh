#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_DIR="/tmp/typescript-eslint"
UPSTREAM_REPO="https://github.com/typescript-eslint/typescript-eslint"
UPSTREAM_REF="${TS_ESLINT_REF:-main}"

echo "==> Preparing upstream repository"
if [[ ! -d "${UPSTREAM_DIR}/.git" ]]; then
  echo "Cloning ${UPSTREAM_REPO} into ${UPSTREAM_DIR}"
  git clone --depth 1 "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
else
  echo "Updating ${UPSTREAM_DIR}"
fi
echo "Using upstream ref: ${UPSTREAM_REF}"
git -C "${UPSTREAM_DIR}" fetch --depth 1 origin "${UPSTREAM_REF}"
git -C "${UPSTREAM_DIR}" checkout --detach FETCH_HEAD
echo "Resolved upstream commit: $(git -C "${UPSTREAM_DIR}" rev-parse HEAD)"

echo "==> Generating parity tracker artifacts"
python3 scripts/generate_ts_eslint_parity_tracker.py
python3 scripts/generate_ts_eslint_parity_worklist.py
python3 scripts/generate_ts_eslint_parity_summary.py
python3 scripts/generate_ts_eslint_parity_metadata.py
python3 scripts/generate_ts_eslint_parity_index.py
python3 scripts/generate_ts_eslint_parity_issue_plan.py

echo "==> Validating parity artifact consistency"
python3 scripts/check_ts_eslint_parity_artifacts.py

echo "==> Done"
echo "Generated files:"
echo "  - typescript-eslint-rule-parity-tracker.csv"
echo "  - typescript-eslint-rule-parity-tracker.json"
echo "  - typescript-eslint-rule-parity-worklist.md"
echo "  - typescript-eslint-rule-parity-summary.md"
echo "  - typescript-eslint-rule-parity-metadata.json"
echo "  - typescript-eslint-rule-parity-index.md"
echo "  - typescript-eslint-rule-parity-issue-plan.md"
