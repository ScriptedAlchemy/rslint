#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_DIR="/tmp/typescript-eslint"
UPSTREAM_REPO="https://github.com/typescript-eslint/typescript-eslint"
UPSTREAM_REF="${TS_ESLINT_REF:-main}"
OFFLINE_MODE="${PARITY_OFFLINE:-0}"

echo "==> Preparing upstream repository"
if [[ ! -d "${UPSTREAM_DIR}/.git" ]]; then
  if [[ "${OFFLINE_MODE}" == "1" ]]; then
    echo "[parity-refresh] ERROR: offline mode enabled but upstream repo missing at ${UPSTREAM_DIR}" >&2
    exit 1
  fi
  echo "Cloning ${UPSTREAM_REPO} into ${UPSTREAM_DIR}"
  git clone --depth 1 "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
else
  echo "Using existing upstream clone at ${UPSTREAM_DIR}"
fi

echo "Using upstream ref: ${UPSTREAM_REF}"
if [[ "${OFFLINE_MODE}" == "1" ]]; then
  echo "Offline mode enabled: skipping network fetch"
  if ! git -C "${UPSTREAM_DIR}" rev-parse --verify "${UPSTREAM_REF}^{commit}" >/dev/null 2>&1; then
    echo "[parity-refresh] ERROR: ref not available locally in offline mode: ${UPSTREAM_REF}" >&2
    exit 1
  fi
  git -C "${UPSTREAM_DIR}" checkout --detach "${UPSTREAM_REF}"
else
  git -C "${UPSTREAM_DIR}" fetch --depth 1 origin "${UPSTREAM_REF}"
  git -C "${UPSTREAM_DIR}" checkout --detach FETCH_HEAD
fi
echo "Resolved upstream commit: $(git -C "${UPSTREAM_DIR}" rev-parse HEAD)"

echo "==> Generating parity tracker artifacts"
python3 scripts/generate_ts_eslint_parity_tracker.py
python3 scripts/generate_ts_eslint_parity_worklist.py
python3 scripts/generate_ts_eslint_parity_summary.py
python3 scripts/generate_ts_eslint_parity_metadata.py
python3 scripts/generate_ts_eslint_parity_badges.py
python3 scripts/generate_ts_eslint_parity_commands.py
python3 scripts/generate_ts_eslint_parity_index.py
python3 scripts/generate_ts_eslint_parity_issue_plan.py
bash scripts/generate_ts_eslint_parity_tasklists_all.sh
bash scripts/generate_ts_eslint_parity_issue_bodies_all.sh
python3 scripts/generate_ts_eslint_parity_top.py
python3 scripts/generate_ts_eslint_parity_manifest.py

echo "==> Validating parity artifact consistency"
python3 scripts/check_ts_eslint_parity_artifacts.py
python3 scripts/check_ts_eslint_parity_tooling_sync.py

echo "==> Parity health diagnosis"
python3 scripts/generate_ts_eslint_parity_doctor.py

echo "==> Done"
echo "Generated files:"
echo "  - typescript-eslint-rule-parity-tracker.csv"
echo "  - typescript-eslint-rule-parity-tracker.json"
echo "  - typescript-eslint-rule-parity-worklist.md"
echo "  - typescript-eslint-rule-parity-summary.md"
echo "  - typescript-eslint-rule-parity-metadata.json"
echo "  - typescript-eslint-rule-parity-badges.json"
echo "  - typescript-eslint-rule-parity-commands.md"
echo "  - typescript-eslint-rule-parity-index.md"
echo "  - typescript-eslint-rule-parity-issue-plan.md"
echo "  - typescript-eslint-rule-parity-tasklist-A_critical.md"
echo "  - typescript-eslint-rule-parity-tasklist-B_high.md"
echo "  - typescript-eslint-rule-parity-tasklist-C_medium.md"
echo "  - typescript-eslint-rule-parity-tasklist-D_low.md"
echo "  - typescript-eslint-rule-parity-issue-body-A_critical.md"
echo "  - typescript-eslint-rule-parity-issue-body-B_high.md"
echo "  - typescript-eslint-rule-parity-issue-body-C_medium.md"
echo "  - typescript-eslint-rule-parity-issue-body-D_low.md"
echo "  - typescript-eslint-rule-parity-top.md"
echo "  - typescript-eslint-rule-parity-manifest.json"
