#!/usr/bin/env bash
set -euo pipefail

python3 /workspace/scripts/generate_ts_eslint_parity_issue_tasklist.py --phase A_critical
python3 /workspace/scripts/generate_ts_eslint_parity_issue_tasklist.py --phase B_high
python3 /workspace/scripts/generate_ts_eslint_parity_issue_tasklist.py --phase C_medium
python3 /workspace/scripts/generate_ts_eslint_parity_issue_tasklist.py --phase D_low
