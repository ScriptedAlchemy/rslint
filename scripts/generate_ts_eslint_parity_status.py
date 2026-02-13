#!/usr/bin/env python3
"""
Generate parity health status JSON from metadata.

Reads:
  - /workspace/typescript-eslint-rule-parity-metadata.json

Writes:
  - /workspace/typescript-eslint-rule-parity-status.json

Optional:
  --fail-on-red     exit non-zero if computed health is red
  --fail-on-yellow  exit non-zero if computed health is yellow or red
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from parity_health import compute_health_reason


def main() -> None:
	parser = argparse.ArgumentParser(description="Generate parity health status JSON.")
	parser.add_argument("--fail-on-red", action="store_true", help="Exit non-zero if health is red.")
	parser.add_argument("--fail-on-yellow", action="store_true", help="Exit non-zero if health is yellow or red.")
	args = parser.parse_args()

	root = pathlib.Path("/workspace")
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	output_path = root / "typescript-eslint-rule-parity-status.json"

	metadata = json.loads(metadata_path.read_text())
	summary = metadata.get("summary", {})
	phase = metadata.get("phase_counts", {})

	total = int(summary.get("total_rules", 0))
	flagged = int(summary.get("flagged_rules", 0))
	aligned = int(summary.get("aligned_rules", 0))
	critical = int(phase.get("A_critical", 0))
	high = int(phase.get("B_high", 0))
	medium = int(phase.get("C_medium", 0))
	low = int(phase.get("D_low", 0))

	health, reason = compute_health_reason(critical=critical, high=high, flagged=flagged)

	status = {
		"schema_version": 1,
		"generated_at_utc": metadata.get("generated_at_utc"),
		"upstream_ref_requested": metadata.get("upstream_ref_requested"),
		"upstream_commit": metadata.get("upstream_commit"),
		"health": health,
		"reason": reason,
		"summary": {
			"total_rules": total,
			"aligned_rules": aligned,
			"flagged_rules": flagged,
		},
		"phase_counts": {
			"A_critical": critical,
			"B_high": high,
			"C_medium": medium,
			"D_low": low,
			"aligned": int(phase.get("aligned", 0)),
		},
	}

	output_path.write_text(json.dumps(status, indent=2) + "\n")
	print(f"wrote {output_path}")

	if args.fail_on_yellow and health in {"yellow", "red"}:
		print(f"[parity-status] ERROR: health is {health} ({reason})", file=sys.stderr)
		sys.exit(3)
	if args.fail_on_red and health == "red":
		print(f"[parity-status] ERROR: health is red ({reason})", file=sys.stderr)
		sys.exit(2)


if __name__ == "__main__":
	main()
