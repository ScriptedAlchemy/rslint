#!/usr/bin/env python3
"""
Validate consistency of generated TypeScript-ESLint parity artifacts.

Checks:
1. Required artifact files exist.
2. CSV and JSON trackers contain same rule set and row count.
3. Metadata summary/phase/flag counts match tracker JSON.
4. Metadata top-priority ordering matches tracker JSON.

Exits with non-zero status on any mismatch.
"""

from __future__ import annotations

import csv
import json
import pathlib
import sys
from collections import Counter


def fail(msg: str) -> None:
	print(f"[parity-check] ERROR: {msg}")
	sys.exit(1)


def main() -> None:
	root = pathlib.Path("/workspace")
	tracker_csv = root / "typescript-eslint-rule-parity-tracker.csv"
	tracker_json = root / "typescript-eslint-rule-parity-tracker.json"
	worklist_md = root / "typescript-eslint-rule-parity-worklist.md"
	summary_md = root / "typescript-eslint-rule-parity-summary.md"
	metadata_json = root / "typescript-eslint-rule-parity-metadata.json"

	required = [tracker_csv, tracker_json, worklist_md, summary_md, metadata_json]
	for path in required:
		if not path.exists():
			fail(f"missing artifact: {path.name}")

	tracker_rows = json.loads(tracker_json.read_text())
	if not isinstance(tracker_rows, list):
		fail("tracker JSON is not an array")

	with tracker_csv.open(newline="") as f:
		csv_rows = list(csv.DictReader(f))

	if len(csv_rows) != len(tracker_rows):
		fail(f"CSV/JSON row count mismatch: csv={len(csv_rows)} json={len(tracker_rows)}")

	json_rules = {row.get("rule", "") for row in tracker_rows}
	csv_rules = {row.get("rule", "") for row in csv_rows}
	if json_rules != csv_rules:
		missing_in_csv = sorted(json_rules - csv_rules)
		missing_in_json = sorted(csv_rules - json_rules)
		fail(f"CSV/JSON rule-set mismatch: missing_in_csv={missing_in_csv[:5]} missing_in_json={missing_in_json[:5]}")

	metadata = json.loads(metadata_json.read_text())
	summary = metadata.get("summary", {})
	phase_counts_meta = metadata.get("phase_counts", {})
	flag_counts_meta = metadata.get("flag_counts", {})
	top_meta = metadata.get("top_priority_rules", [])

	flagged = [row for row in tracker_rows if int(row.get("priority_score", 0)) > 0]
	aligned = len(tracker_rows) - len(flagged)

	if summary.get("total_rules") != len(tracker_rows):
		fail("metadata summary.total_rules mismatch")
	if summary.get("flagged_rules") != len(flagged):
		fail("metadata summary.flagged_rules mismatch")
	if summary.get("aligned_rules") != aligned:
		fail("metadata summary.aligned_rules mismatch")

	phase_counter = Counter(row.get("recommended_phase", "unknown") for row in tracker_rows)
	if dict(phase_counter) != phase_counts_meta:
		fail("metadata phase_counts mismatch")

	flag_counter = Counter()
	for row in flagged:
		raw = row.get("flags", "")
		for flag in raw.split("|"):
			if flag:
				flag_counter[flag] += 1
	if dict(flag_counter) != flag_counts_meta:
		fail("metadata flag_counts mismatch")

	expected_top = sorted(flagged, key=lambda r: (-int(r.get("priority_score", 0)), r.get("rule", "")))[: len(top_meta)]
	expected_projection = [
		{
			"rule": row.get("rule"),
			"priority_score": int(row.get("priority_score", 0)),
			"flags": row.get("flags", ""),
		}
		for row in expected_top
	]
	if expected_projection != top_meta:
		fail("metadata top_priority_rules mismatch")

	print("[parity-check] OK: all parity artifacts are consistent.")


if __name__ == "__main__":
	main()
