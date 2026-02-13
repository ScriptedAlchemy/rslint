#!/usr/bin/env python3
"""
Generate parity badge data JSON for dashboards/shields.

Reads:
  - /workspace/typescript-eslint-rule-parity-metadata.json

Writes:
  - /workspace/typescript-eslint-rule-parity-badges.json
"""

from __future__ import annotations

import json
import pathlib


def main() -> None:
	root = pathlib.Path("/workspace")
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	output_path = root / "typescript-eslint-rule-parity-badges.json"

	metadata = json.loads(metadata_path.read_text())
	summary = metadata.get("summary", {})
	phase = metadata.get("phase_counts", {})

	total = int(summary.get("total_rules", 0))
	flagged = int(summary.get("flagged_rules", 0))
	aligned = int(summary.get("aligned_rules", 0))
	aligned_percent = round((aligned / total * 100.0), 1) if total else 0.0

	data = {
		"schema_version": 1,
		"generated_at_utc": metadata.get("generated_at_utc"),
		"upstream_ref_requested": metadata.get("upstream_ref_requested"),
		"upstream_commit": metadata.get("upstream_commit"),
		"metrics": {
			"total_rules": total,
			"aligned_rules": aligned,
			"flagged_rules": flagged,
			"aligned_percent": aligned_percent,
			"critical_rules": int(phase.get("A_critical", 0)),
			"high_rules": int(phase.get("B_high", 0)),
			"medium_rules": int(phase.get("C_medium", 0)),
			"low_rules": int(phase.get("D_low", 0)),
		},
		"badges": {
			"parity_aligned_percent": f"{aligned_percent}%",
			"parity_flagged_rules": str(flagged),
			"parity_critical_rules": str(int(phase.get("A_critical", 0))),
		},
	}

	output_path.write_text(json.dumps(data, indent=2) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
