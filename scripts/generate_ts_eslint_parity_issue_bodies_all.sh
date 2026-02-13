#!/usr/bin/env bash
set -euo pipefail

python3 /workspace/scripts/generate_ts_eslint_parity_issue_body.py --phase A_critical
python3 /workspace/scripts/generate_ts_eslint_parity_issue_body.py --phase B_high
python3 /workspace/scripts/generate_ts_eslint_parity_issue_body.py --phase C_medium
python3 /workspace/scripts/generate_ts_eslint_parity_issue_body.py --phase D_low
