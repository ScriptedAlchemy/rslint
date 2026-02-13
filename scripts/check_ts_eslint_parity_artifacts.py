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
import re
import sys
from collections import Counter


def fail(msg: str) -> None:
	print(f"[parity-check] ERROR: {msg}")
	sys.exit(1)


def parse_summary_markdown(summary_text: str) -> dict:
	headline_patterns = {
		"total_rules": r"Total tracked rules:\s+\*\*(\d+)\*\*",
		"flagged_rules": r"Rules needing correction .*:\s+\*\*(\d+)\*\*",
		"aligned_rules": r"Rules currently aligned .*:\s+\*\*(\d+)\*\*",
	}

	headline = {}
	for key, pattern in headline_patterns.items():
		match = re.search(pattern, summary_text)
		if not match:
			fail(f"summary markdown missing headline metric: {key}")
		headline[key] = int(match.group(1))

	phase_counts = {}
	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		match = re.search(rf"\|\s*`{phase}`\s*\|\s*(\d+)\s*\|", summary_text)
		if not match:
			fail(f"summary markdown missing phase row: {phase}")
		phase_counts[phase] = int(match.group(1))

	top_rows = []
	for match in re.finditer(r"\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*`([^`]*)`\s*\|", summary_text):
		top_rows.append(
			{
				"rank": int(match.group(1)),
				"rule": match.group(2),
				"priority_score": int(match.group(3)),
				"flags": match.group(4),
			}
		)

	return {"headline": headline, "phase_counts": phase_counts, "top_rows": top_rows}


def parse_worklist_markdown(worklist_text: str) -> dict:
	heading_counts = {}
	for match in re.finditer(r"^##\s+([A-Za-z_]+)\s+\((\d+)\s+rules\)$", worklist_text, flags=re.MULTILINE):
		heading_counts[match.group(1)] = int(match.group(2))

	phase_items = Counter()
	current_phase = None
	for line in worklist_text.splitlines():
		head_match = re.match(r"^##\s+([A-Za-z_]+)\s+\((\d+)\s+rules\)$", line)
		if head_match:
			current_phase = head_match.group(1)
			continue
		if current_phase and line.startswith("- [ ] `"):
			phase_items[current_phase] += 1

	return {"heading_counts": heading_counts, "phase_items": dict(phase_items)}


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

	# Summary markdown checks
	summary_text = summary_md.read_text()
	summary_data = parse_summary_markdown(summary_text)

	if summary_data["headline"]["total_rules"] != len(tracker_rows):
		fail("summary markdown total_rules mismatch")
	if summary_data["headline"]["flagged_rules"] != len(flagged):
		fail("summary markdown flagged_rules mismatch")
	if summary_data["headline"]["aligned_rules"] != aligned:
		fail("summary markdown aligned_rules mismatch")
	if summary_data["phase_counts"] != dict(phase_counter):
		fail("summary markdown phase counts mismatch")

	expected_top15 = expected_projection[:15]
	actual_top15 = [
		{
			"rule": row["rule"],
			"priority_score": row["priority_score"],
			"flags": row["flags"],
		}
		for row in summary_data["top_rows"][:15]
	]
	if expected_top15 != actual_top15:
		fail("summary markdown top-15 table mismatch")

	# Worklist markdown checks
	worklist_text = worklist_md.read_text()
	worklist_data = parse_worklist_markdown(worklist_text)

	if worklist_data["heading_counts"] != dict(phase_counter):
		fail("worklist markdown phase heading counts mismatch")

	for phase, count in phase_counter.items():
		expected_items = 0 if phase == "aligned" else count
		actual_items = worklist_data["phase_items"].get(phase, 0)
		if actual_items != expected_items:
			fail(f"worklist markdown checklist item count mismatch for {phase}: expected={expected_items} actual={actual_items}")

	print("[parity-check] OK: all parity artifacts are consistent.")


if __name__ == "__main__":
	main()
