#!/usr/bin/env python3
"""
Generate parity health status JSON from metadata.

Reads:
  - /workspace/typescript-eslint-rule-parity-metadata.json

Writes:
  - /workspace/typescript-eslint-rule-parity-status.json
"""

from __future__ import annotations

import json
import pathlib


def compute_health(critical: int, high: int, flagged: int) -> tuple[str, str]:
	if critical > 0:
		return "red", "critical backlog is non-zero"
	if high > 0:
		return "yellow", "high backlog is non-zero"
	if flagged > 0:
		return "yellow", "non-critical flagged backlog remains"
	return "green", "no flagged parity backlog"


def main() -> None:
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

	health, reason = compute_health(critical=critical, high=high, flagged=flagged)

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


if __name__ == "__main__":
	main()
