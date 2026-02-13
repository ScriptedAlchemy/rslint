#!/usr/bin/env python3
"""
Generate parity run metadata from tracker artifacts.

Input:
  - /workspace/typescript-eslint-rule-parity-tracker.json

Output:
  - /workspace/typescript-eslint-rule-parity-metadata.json
"""

from __future__ import annotations

import collections
import datetime
import json
import os
import pathlib
import subprocess


def get_upstream_commit(upstream_dir: pathlib.Path) -> str | None:
	if not (upstream_dir / ".git").exists():
		return None
	try:
		result = subprocess.run(
			["git", "-C", str(upstream_dir), "rev-parse", "HEAD"],
			check=True,
			capture_output=True,
			text=True,
		)
		return result.stdout.strip()
	except Exception:
		return None


def resolve_generated_at(output_json: pathlib.Path) -> str:
	if os.environ.get("PARITY_REPRO_MODE") == "1" and output_json.exists():
		try:
			existing = json.loads(output_json.read_text())
			value = existing.get("generated_at_utc")
			if value:
				return str(value)
		except Exception:
			pass
	return datetime.datetime.now(datetime.UTC).isoformat()


def main() -> None:
	root = pathlib.Path("/workspace")
	upstream_dir = pathlib.Path("/tmp/typescript-eslint")
	tracker_json = root / "typescript-eslint-rule-parity-tracker.json"
	output_json = root / "typescript-eslint-rule-parity-metadata.json"

	rows = json.loads(tracker_json.read_text())

	flag_counter = collections.Counter()
	phase_counter = collections.Counter()
	for row in rows:
		phase_counter[row.get("recommended_phase", "unknown")] += 1
		flags = row.get("flags", "")
		for flag in flags.split("|"):
			if flag:
				flag_counter[flag] += 1

	flagged = [row for row in rows if row.get("priority_score", 0) > 0]
	top_rules = sorted(flagged, key=lambda r: (-r.get("priority_score", 0), r.get("rule", "")))[:20]

	metadata = {
		"generated_at_utc": resolve_generated_at(output_json),
		"upstream_repo": "https://github.com/typescript-eslint/typescript-eslint",
		"upstream_ref_requested": os.environ.get("TS_ESLINT_REF", "main"),
		"upstream_commit": get_upstream_commit(upstream_dir),
		"tracker_file": str(tracker_json.name),
		"summary": {
			"total_rules": len(rows),
			"flagged_rules": len(flagged),
			"aligned_rules": len(rows) - len(flagged),
		},
		"phase_counts": dict(phase_counter),
		"flag_counts": dict(flag_counter),
		"top_priority_rules": [
			{
				"rule": row.get("rule"),
				"priority_score": row.get("priority_score", 0),
				"flags": row.get("flags", ""),
			}
			for row in top_rules
		],
	}

	output_json.write_text(json.dumps(metadata, indent=2) + "\n")
	print(f"wrote {output_json}")


if __name__ == "__main__":
	main()
