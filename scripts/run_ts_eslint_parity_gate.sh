#!/usr/bin/env bash
set -euo pipefail

threshold="red"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --threshold)
      shift
      if [[ $# -eq 0 ]]; then
        echo "[parity-gate] ERROR: --threshold requires a value (red|yellow)." >&2
        exit 1
      fi
      threshold="$1"
      ;;
    *)
      echo "[parity-gate] ERROR: unknown argument: $1" >&2
      echo "[parity-gate] Usage: bash scripts/run_ts_eslint_parity_gate.sh --threshold red|yellow" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "${threshold}" != "red" && "${threshold}" != "yellow" ]]; then
  echo "[parity-gate] ERROR: invalid threshold '${threshold}'. Expected red|yellow." >&2
  exit 1
fi

echo "[parity-gate] Running strict clean parity checks"
PARITY_CHECK_ALL_REQUIRE_CLEAN=1 bash /workspace/scripts/check_ts_eslint_parity_all.sh

if [[ "${threshold}" == "red" ]]; then
  echo "[parity-gate] Applying red threshold gates"
  python3 /workspace/scripts/generate_ts_eslint_parity_status.py --fail-on-red
  python3 /workspace/scripts/generate_ts_eslint_parity_doctor.py --fail-on-critical
else
  echo "[parity-gate] Applying yellow threshold gates"
  python3 /workspace/scripts/generate_ts_eslint_parity_status.py --fail-on-yellow
  python3 /workspace/scripts/generate_ts_eslint_parity_doctor.py --fail-on-yellow
fi

echo "[parity-gate] OK: parity gate passed (threshold=${threshold})."
