#!/usr/bin/env bash
set -euo pipefail

METADATA_FILE="/workspace/typescript-eslint-rule-parity-metadata.json"

if [[ ! -f "${METADATA_FILE}" ]]; then
  echo "[parity-rebuild] ERROR: metadata file not found: ${METADATA_FILE}" >&2
  exit 1
fi

UPSTREAM_COMMIT="$(
  python3 - <<'PY'
import json
from pathlib import Path

metadata_path = Path("/workspace/typescript-eslint-rule-parity-metadata.json")
data = json.loads(metadata_path.read_text())
commit = data.get("upstream_commit", "")
if not commit:
    raise SystemExit(1)
print(commit)
PY
)"

if [[ -z "${UPSTREAM_COMMIT}" ]]; then
  echo "[parity-rebuild] ERROR: upstream_commit missing in metadata" >&2
  exit 1
fi

echo "[parity-rebuild] Rebuilding artifacts for upstream commit: ${UPSTREAM_COMMIT}"
PARITY_REPRO_MODE=1 TS_ESLINT_REF="${UPSTREAM_COMMIT}" bash /workspace/scripts/refresh-ts-eslint-parity-artifacts.sh
