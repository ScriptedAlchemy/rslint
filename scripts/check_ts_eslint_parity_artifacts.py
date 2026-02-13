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
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from collections import Counter


def fail(msg: str) -> None:
	print(f"[parity-check] ERROR: {msg}")
	sys.exit(1)


def sha256_file(path: pathlib.Path) -> str:
	hasher = hashlib.sha256()
	with path.open("rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			hasher.update(chunk)
	return hasher.hexdigest()


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


def parse_issue_plan_markdown(issue_plan_text: str) -> dict:
	heading_counts = {}
	phase_items = Counter()
	current_phase = None

	for line in issue_plan_text.splitlines():
		head_match = re.match(r"^##\s+([A-Za-z_]+)\s+\((\d+)\s+rules\)$", line)
		if head_match:
			current_phase = head_match.group(1)
			heading_counts[current_phase] = int(head_match.group(2))
			continue

		if current_phase in {"A_critical", "B_high", "C_medium", "D_low"} and line.startswith("- [ ] `"):
			phase_items[current_phase] += 1

	return {"heading_counts": heading_counts, "phase_items": dict(phase_items)}


def parse_phase_tasklist_markdown(tasklist_text: str) -> int:
	count = 0
	for line in tasklist_text.splitlines():
		if line.startswith("- [ ] "):
			count += 1
	return count


def parse_ci_summary_markdown(summary_text: str) -> dict:
	patterns = {
		"upstream_ref": r"- Upstream ref:\s+`([^`]+)`",
		"upstream_commit": r"- Upstream commit:\s+`([^`]+)`",
		"total_rules": r"- Total rules:\s+\*\*(\d+)\*\*",
		"flagged_rules": r"- Flagged rules:\s+\*\*(\d+)\*\*",
		"aligned_rules": r"- Aligned rules:\s+\*\*(\d+)\*\*",
	}
	parsed = {}
	for key, pattern in patterns.items():
		match = re.search(pattern, summary_text)
		if not match:
			fail(f"ci summary missing field: {key}")
		value = match.group(1)
		if key in {"total_rules", "flagged_rules", "aligned_rules"}:
			parsed[key] = int(value)
		else:
			parsed[key] = value

	phase_counts = {}
	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		match = re.search(rf"\|\s*`{phase}`\s*\|\s*(\d+)\s*\|", summary_text)
		if not match:
			fail(f"ci summary missing phase row: {phase}")
		phase_counts[phase] = int(match.group(1))
	parsed["phase_counts"] = phase_counts

	return parsed


def main() -> None:
	root = pathlib.Path("/workspace")
	tracker_csv = root / "typescript-eslint-rule-parity-tracker.csv"
	tracker_json = root / "typescript-eslint-rule-parity-tracker.json"
	worklist_md = root / "typescript-eslint-rule-parity-worklist.md"
	top_md = root / "typescript-eslint-rule-parity-top.md"
	summary_md = root / "typescript-eslint-rule-parity-summary.md"
	metadata_json = root / "typescript-eslint-rule-parity-metadata.json"
	index_md = root / "typescript-eslint-rule-parity-index.md"
	issue_plan_md = root / "typescript-eslint-rule-parity-issue-plan.md"
	manifest_json = root / "typescript-eslint-rule-parity-manifest.json"
	tasklist_a_md = root / "typescript-eslint-rule-parity-tasklist-A_critical.md"
	tasklist_b_md = root / "typescript-eslint-rule-parity-tasklist-B_high.md"
	tasklist_c_md = root / "typescript-eslint-rule-parity-tasklist-C_medium.md"
	tasklist_d_md = root / "typescript-eslint-rule-parity-tasklist-D_low.md"

	required = [
		tracker_csv,
		tracker_json,
		worklist_md,
		top_md,
		summary_md,
		metadata_json,
		index_md,
		issue_plan_md,
		manifest_json,
		tasklist_a_md,
		tasklist_b_md,
		tasklist_c_md,
		tasklist_d_md,
	]
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
	if not metadata.get("upstream_ref_requested"):
		fail("metadata missing upstream_ref_requested")
	if not metadata.get("upstream_commit"):
		fail("metadata missing upstream_commit")

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

	# Issue plan markdown checks
	issue_plan_text = issue_plan_md.read_text()
	issue_plan_data = parse_issue_plan_markdown(issue_plan_text)

	for phase in ["A_critical", "B_high", "C_medium", "D_low"]:
		expected_count = phase_counter.get(phase, 0)
		head_count = issue_plan_data["heading_counts"].get(phase)
		if head_count != expected_count:
			fail(f"issue plan heading count mismatch for {phase}: expected={expected_count} actual={head_count}")

		item_count = issue_plan_data["phase_items"].get(phase, 0)
		if item_count != expected_count:
			fail(f"issue plan checklist item count mismatch for {phase}: expected={expected_count} actual={item_count}")

	# Index markdown checks
	index_text = index_md.read_text()
	index_headline_patterns = {
		"total_rules": r"Total rules:\s+\*\*(\d+)\*\*",
		"flagged_rules": r"Flagged rules:\s+\*\*(\d+)\*\*",
		"aligned_rules": r"Aligned rules:\s+\*\*(\d+)\*\*",
	}
	for key, pattern in index_headline_patterns.items():
		match = re.search(pattern, index_text)
		if not match:
			fail(f"index markdown missing metric: {key}")
		value = int(match.group(1))
		expected = summary.get(key)
		if value != expected:
			fail(f"index markdown metric mismatch for {key}: expected={expected} actual={value}")

	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		match = re.search(rf"\|\s*`{phase}`\s*\|\s*(\d+)\s*\|", index_text)
		if not match:
			fail(f"index markdown missing phase row: {phase}")
		value = int(match.group(1))
		expected = phase_counter.get(phase, 0)
		if value != expected:
			fail(f"index markdown phase count mismatch for {phase}: expected={expected} actual={value}")

	required_artifact_mentions = [
		"typescript-eslint-rule-parity-report.md",
		"typescript-eslint-rule-parity-tracker.csv",
		"typescript-eslint-rule-parity-tracker.json",
		"typescript-eslint-rule-parity-worklist.md",
		"typescript-eslint-rule-parity-top.md",
		"typescript-eslint-rule-parity-summary.md",
		"typescript-eslint-rule-parity-metadata.json",
		"typescript-eslint-rule-parity-index.md",
		"typescript-eslint-rule-parity-issue-plan.md",
		"typescript-eslint-rule-parity-tasklist-<phase>.md",
		"typescript-eslint-rule-parity-issue-body-<phase>.md",
	]
	for artifact_name in required_artifact_mentions:
		if artifact_name not in index_text:
			fail(f"index markdown missing artifact mention: {artifact_name}")

	# Manifest checksum checks
	manifest = json.loads(manifest_json.read_text())
	if manifest.get("hash_algorithm") != "sha256":
		fail("manifest hash_algorithm must be sha256")
	files = manifest.get("files", [])
	if not isinstance(files, list) or not files:
		fail("manifest files list missing or empty")

	manifest_map = {}
	for entry in files:
		path = entry.get("path")
		sha = entry.get("sha256")
		size = entry.get("bytes")
		if not path or not sha:
			fail("manifest entry missing path or sha256")
		manifest_map[path] = {"sha256": sha, "bytes": size}

	expected_manifest_paths = {
		"typescript-eslint-rule-parity-report.md",
		"typescript-eslint-rule-parity-guide.md",
		"typescript-eslint-rule-parity-index.md",
		"typescript-eslint-rule-parity-summary.md",
		"typescript-eslint-rule-parity-worklist.md",
		"typescript-eslint-rule-parity-top.md",
		"typescript-eslint-rule-parity-issue-plan.md",
		"typescript-eslint-rule-parity-tracker.csv",
		"typescript-eslint-rule-parity-tracker.json",
		"typescript-eslint-rule-parity-metadata.json",
		"typescript-eslint-rule-parity-tasklist-A_critical.md",
		"typescript-eslint-rule-parity-tasklist-B_high.md",
		"typescript-eslint-rule-parity-tasklist-C_medium.md",
		"typescript-eslint-rule-parity-tasklist-D_low.md",
	}
	if set(manifest_map) != expected_manifest_paths:
		fail("manifest path set mismatch with expected parity artifacts")

	for rel_path, values in manifest_map.items():
		path = root / rel_path
		if not path.exists():
			fail(f"manifest artifact missing on disk: {rel_path}")
		actual_sha = sha256_file(path)
		if actual_sha != values["sha256"]:
			fail(f"manifest checksum mismatch: {rel_path}")
		actual_size = path.stat().st_size
		if values.get("bytes") != actual_size:
			fail(f"manifest size mismatch: {rel_path}")

	# Phase tasklist checks
	tasklist_by_phase = {
		"A_critical": tasklist_a_md,
		"B_high": tasklist_b_md,
		"C_medium": tasklist_c_md,
		"D_low": tasklist_d_md,
	}
	for phase, path in tasklist_by_phase.items():
		text = path.read_text()
		if f"### {phase} parity tasks" not in text:
			fail(f"tasklist markdown missing phase heading for {phase}: {path.name}")
		task_count = parse_phase_tasklist_markdown(text)
		expected = phase_counter.get(phase, 0)
		if task_count != expected:
			fail(f"tasklist count mismatch for {phase}: expected={expected} actual={task_count}")

	# Top priorities markdown checks
	top_text = top_md.read_text()
	top_rows = []
	for match in re.finditer(r"\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*`([^`]*)`\s*\|", top_text):
		top_rows.append(
			{
				"rank": int(match.group(1)),
				"rule": match.group(2),
				"priority_score": int(match.group(3)),
				"phase": match.group(4),
			}
		)
	expected_top = sorted(flagged, key=lambda r: (-int(r.get("priority_score", 0)), r.get("rule", "")))[:25]
	if len(top_rows) != len(expected_top):
		fail(f"top markdown row count mismatch: expected={len(expected_top)} actual={len(top_rows)}")
	for expected, actual in zip(expected_top, top_rows):
		if expected.get("rule") != actual["rule"]:
			fail(f"top markdown rule mismatch: expected={expected.get('rule')} actual={actual['rule']}")
		if int(expected.get("priority_score", 0)) != actual["priority_score"]:
			fail(f"top markdown score mismatch for {actual['rule']}")
		if str(expected.get("recommended_phase", "")) != actual["phase"]:
			fail(f"top markdown phase mismatch for {actual['rule']}")

	# CI summary script output checks
	try:
		ci_summary_output = subprocess.run(
			["python3", str(root / "scripts/generate_ts_eslint_parity_ci_summary.py")],
			check=True,
			capture_output=True,
			text=True,
		).stdout
	except subprocess.CalledProcessError as err:
		fail(f"ci summary script failed: {err}")

	ci_summary = parse_ci_summary_markdown(ci_summary_output)
	if ci_summary["upstream_ref"] != metadata.get("upstream_ref_requested"):
		fail("ci summary upstream_ref mismatch")
	if ci_summary["upstream_commit"] != metadata.get("upstream_commit"):
		fail("ci summary upstream_commit mismatch")
	if ci_summary["total_rules"] != summary.get("total_rules"):
		fail("ci summary total_rules mismatch")
	if ci_summary["flagged_rules"] != summary.get("flagged_rules"):
		fail("ci summary flagged_rules mismatch")
	if ci_summary["aligned_rules"] != summary.get("aligned_rules"):
		fail("ci summary aligned_rules mismatch")
	if ci_summary["phase_counts"] != dict(phase_counter):
		fail("ci summary phase_counts mismatch")

	print("[parity-check] OK: all parity artifacts are consistent.")


if __name__ == "__main__":
	main()
