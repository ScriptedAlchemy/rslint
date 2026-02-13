#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "[parity-gate] Usage: bash scripts/run_ts_eslint_parity_gate.sh [--threshold red|yellow|--threshold=red|--threshold=yellow] [--skip-checks]" >&2
}

threshold="red"
skip_checks="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --threshold)
      shift
      if [[ $# -eq 0 || "$1" == --* ]]; then
        echo "[parity-gate] ERROR: --threshold requires a value (red|yellow)." >&2
        usage
        exit 1
      fi
      threshold="$1"
      ;;
    --threshold=*)
      threshold="${1#*=}"
      if [[ -z "${threshold}" ]]; then
        echo "[parity-gate] ERROR: --threshold requires a value (red|yellow)." >&2
        usage
        exit 1
      fi
      ;;
    --skip-checks)
      skip_checks="1"
      ;;
    *)
      echo "[parity-gate] ERROR: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ "${threshold}" != "red" && "${threshold}" != "yellow" ]]; then
  echo "[parity-gate] ERROR: invalid threshold '${threshold}'. Expected red|yellow." >&2
  usage
  exit 1
fi

if [[ "${skip_checks}" == "1" ]]; then
  echo "[parity-gate] Skipping strict clean parity checks (--skip-checks)."
else
  echo "[parity-gate] Running strict clean parity checks"
  PARITY_CHECK_ALL_REQUIRE_CLEAN=1 bash /workspace/scripts/check_ts_eslint_parity_all.sh
fi

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
