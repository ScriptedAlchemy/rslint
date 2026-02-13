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

from parity_health import compute_health_reason


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


def parse_issue_body_markdown(issue_body_text: str, phase: str) -> dict:
	title_match = re.search(rf"^##\s+TypeScript-ESLint Parity — {phase}$", issue_body_text, flags=re.MULTILINE)
	if not title_match:
		fail(f"issue body missing title for {phase}")

	priority = phase.split("_", 1)[1]
	priority_label_match = re.search(rf"-\s+`priority:{priority}`", issue_body_text)
	if not priority_label_match:
		fail(f"issue body missing priority label for {phase}")

	tasklist_heading_match = re.search(rf"###\s+{phase}\s+parity tasks", issue_body_text)
	if not tasklist_heading_match:
		fail(f"issue body missing tasklist heading for {phase}")

	tasklist_block_match = re.search(rf"```\[tasklist\]\s*###\s+{phase}\s+parity tasks(?P<body>.*?)```", issue_body_text, flags=re.DOTALL)
	if not tasklist_block_match:
		fail(f"issue body missing tasklist code block for {phase}")
	tasklist_block = tasklist_block_match.group("body")
	task_count = len(re.findall(r"^- \[ \] .+$", tasklist_block, flags=re.MULTILINE))
	acceptance_checks = len(
		re.findall(r"^- \[ \] (Go tests pass for touched rules\.|JS parity tests pass for touched rules\.|Parity artifacts regenerated .+|Consistency checks pass .+)$", issue_body_text, flags=re.MULTILINE)
	)

	if "### Acceptance criteria" not in issue_body_text:
		fail(f"issue body missing acceptance criteria section for {phase}")

	return {"task_count": task_count, "acceptance_checks": acceptance_checks}


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

	health_match = re.search(r"- Health:\s+\*\*([a-z]+)\*\*(?:\s+—\s+(.+))?", summary_text)
	if not health_match:
		fail("ci summary missing field: health")
	parsed["health"] = health_match.group(1)
	parsed["health_reason"] = (health_match.group(2) or "").strip()

	phase_counts = {}
	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		match = re.search(rf"\|\s*`{phase}`\s*\|\s*(\d+)\s*\|", summary_text)
		if not match:
			fail(f"ci summary missing phase row: {phase}")
		phase_counts[phase] = int(match.group(1))
	parsed["phase_counts"] = phase_counts

	diff_metrics = {}
	if "### Diff vs baseline" in summary_text:
		diff_patterns = {
			"net_flagged_change": r"- Net flagged change:\s+\*\*([+-]?\d+)\*\*",
			"improved_rules": r"- Improved rules:\s+\*\*(\d+)\*\*",
			"regressed_rules": r"- Regressed rules:\s+\*\*(\d+)\*\*",
			"resolved_rules": r"- Resolved rules:\s+\*\*(\d+)\*\*",
			"newly_flagged_rules": r"- Newly flagged rules:\s+\*\*(\d+)\*\*",
		}
		for key, pattern in diff_patterns.items():
			match = re.search(pattern, summary_text)
			if not match:
				fail(f"ci summary diff section missing field: {key}")
			diff_metrics[key] = int(match.group(1))
	parsed["diff_metrics"] = diff_metrics

	return parsed


def parse_ci_summary_json(summary_text: str) -> dict:
	try:
		parsed = json.loads(summary_text)
	except json.JSONDecodeError as err:
		fail(f"ci summary json output invalid JSON: {err}")
	if not isinstance(parsed, dict):
		fail("ci summary json output must be an object")
	if int(parsed.get("schema_version", -1)) != 1:
		fail("ci summary json schema_version must be 1")
	return parsed


def parse_diff_markdown_summary(diff_text: str) -> dict:
	patterns = {
		"net_flagged_change": r"Net flagged change:\s+\*\*([+-]?\d+)\*\*",
		"improved_rules": r"Improved rules .*:\s+\*\*(\d+)\*\*",
		"regressed_rules": r"Regressed rules .*:\s+\*\*(\d+)\*\*",
		"resolved_rules": r"Resolved rules .*:\s+\*\*(\d+)\*\*",
		"newly_flagged_rules": r"Newly flagged rules .*:\s+\*\*(\d+)\*\*",
	}
	parsed = {}
	for key, pattern in patterns.items():
		match = re.search(pattern, diff_text)
		if not match:
			fail(f"parity diff markdown missing summary field: {key}")
		parsed[key] = int(match.group(1))
	return parsed


def parse_diff_json_summary(diff_json_text: str) -> dict:
	try:
		parsed = json.loads(diff_json_text)
	except json.JSONDecodeError as err:
		fail(f"parity diff json output invalid JSON: {err}")
	if not isinstance(parsed, dict):
		fail("parity diff json output must be an object")
	if int(parsed.get("schema_version", -1)) != 1:
		fail("parity diff json schema_version must be 1")
	summary = parsed.get("summary", {})
	fields = {
		"net_flagged_change": "net_flagged_change",
		"improved_rules": "improved_rules",
		"regressed_rules": "regressed_rules",
		"resolved_rules": "resolved_rules",
		"newly_flagged_rules": "newly_flagged_rules",
	}
	out = {}
	for out_key, summary_key in fields.items():
		if summary_key not in summary:
			fail(f"parity diff json missing summary field: {summary_key}")
		out[out_key] = int(summary.get(summary_key, 0))
	return out


def parse_doctor_plain_output(text: str) -> dict:
	patterns = {
		"total_rules": r"Total rules\s*:\s*(\d+)",
		"aligned_rules": r"Aligned rules\s*:\s*(\d+)\s*\(",
		"flagged_rules": r"Flagged rules\s*:\s*(\d+)",
	}
	parsed = {}
	for key, pattern in patterns.items():
		match = re.search(pattern, text)
		if not match:
			fail(f"parity doctor plain output missing field: {key}")
		parsed[key] = int(match.group(1))

	phase_match = re.search(r"Phase load\s*:\s*A=(\d+)\s+B=(\d+)\s+C=(\d+)\s+D=(\d+)", text)
	if not phase_match:
		fail("parity doctor plain output missing phase load")
	parsed["phase_counts"] = {
		"A_critical": int(phase_match.group(1)),
		"B_high": int(phase_match.group(2)),
		"C_medium": int(phase_match.group(3)),
		"D_low": int(phase_match.group(4)),
	}

	top_match = re.search(r"Top rules\s*:\s*(.+)", text)
	if top_match:
		parsed["top_rules"] = [part.strip() for part in top_match.group(1).split(",") if part.strip()]
	else:
		parsed["top_rules"] = []

	health_match = re.search(r"Health\s*:\s*([a-z]+)\s+\((.+)\)", text)
	if not health_match:
		fail("parity doctor plain output missing health line")
	parsed["health"] = health_match.group(1)
	parsed["health_reason"] = health_match.group(2).strip()

	return parsed


def parse_doctor_markdown_output(text: str) -> dict:
	patterns = {
		"total_rules": r"- Total rules:\s+\*\*(\d+)\*\*",
		"aligned_rules": r"- Aligned rules:\s+\*\*(\d+)\*\*\s+\(",
		"flagged_rules": r"- Flagged rules:\s+\*\*(\d+)\*\*",
	}
	parsed = {}
	for key, pattern in patterns.items():
		match = re.search(pattern, text)
		if not match:
			fail(f"parity doctor markdown output missing field: {key}")
		parsed[key] = int(match.group(1))

	phase_match = re.search(r"- Phase load:\s*A=(\d+),\s*B=(\d+),\s*C=(\d+),\s*D=(\d+)", text)
	if not phase_match:
		fail("parity doctor markdown output missing phase load")
	parsed["phase_counts"] = {
		"A_critical": int(phase_match.group(1)),
		"B_high": int(phase_match.group(2)),
		"C_medium": int(phase_match.group(3)),
		"D_low": int(phase_match.group(4)),
	}

	top_match = re.search(r"- Top immediate rules:\s*(.+)", text)
	if top_match:
		parsed["top_rules"] = re.findall(r"`([^`]+)`", top_match.group(1))
	else:
		parsed["top_rules"] = []

	health_match = re.search(r"- Health:\s+\*\*([a-z]+)\*\*\s+—\s+(.+)", text)
	if not health_match:
		fail("parity doctor markdown output missing health line")
	parsed["health"] = health_match.group(1)
	parsed["health_reason"] = health_match.group(2).strip()

	return parsed


def parse_doctor_json_output(text: str) -> dict:
	try:
		parsed = json.loads(text)
	except json.JSONDecodeError as err:
		fail(f"parity doctor json output invalid JSON: {err}")
	if not isinstance(parsed, dict):
		fail("parity doctor json output must be an object")
	return parsed


def extract_status_write_lines(text: str) -> list[str]:
	return [line.strip() for line in text.splitlines() if "typescript-eslint-rule-parity-status.json" in line]


def extract_prefixed_lines(text: str, prefixes: tuple[str, ...]) -> list[str]:
	return [line.strip() for line in text.splitlines() if any(line.strip().startswith(prefix) for prefix in prefixes)]


def assert_no_pnpm_lifecycle_noise(label: str, text: str) -> None:
	if "rslint-monorepo@" in text:
		fail(f"{label} contains pnpm lifecycle banner output; expected --silent wrapper output")
	if re.search(r"^>\s", text, flags=re.MULTILINE):
		fail(f"{label} contains pnpm lifecycle command echo output; expected --silent wrapper output")


def main() -> None:
	root = pathlib.Path("/workspace")
	tracker_csv = root / "typescript-eslint-rule-parity-tracker.csv"
	tracker_json = root / "typescript-eslint-rule-parity-tracker.json"
	worklist_md = root / "typescript-eslint-rule-parity-worklist.md"
	top_md = root / "typescript-eslint-rule-parity-top.md"
	commands_md = root / "typescript-eslint-rule-parity-commands.md"
	summary_md = root / "typescript-eslint-rule-parity-summary.md"
	metadata_json = root / "typescript-eslint-rule-parity-metadata.json"
	badges_json = root / "typescript-eslint-rule-parity-badges.json"
	status_json = root / "typescript-eslint-rule-parity-status.json"
	index_md = root / "typescript-eslint-rule-parity-index.md"
	issue_plan_md = root / "typescript-eslint-rule-parity-issue-plan.md"
	manifest_json = root / "typescript-eslint-rule-parity-manifest.json"
	tasklist_a_md = root / "typescript-eslint-rule-parity-tasklist-A_critical.md"
	tasklist_b_md = root / "typescript-eslint-rule-parity-tasklist-B_high.md"
	tasklist_c_md = root / "typescript-eslint-rule-parity-tasklist-C_medium.md"
	tasklist_d_md = root / "typescript-eslint-rule-parity-tasklist-D_low.md"
	issue_body_a_md = root / "typescript-eslint-rule-parity-issue-body-A_critical.md"
	issue_body_b_md = root / "typescript-eslint-rule-parity-issue-body-B_high.md"
	issue_body_c_md = root / "typescript-eslint-rule-parity-issue-body-C_medium.md"
	issue_body_d_md = root / "typescript-eslint-rule-parity-issue-body-D_low.md"
	diff_md = root / "typescript-eslint-rule-parity-diff.md"
	diff_json = root / "typescript-eslint-rule-parity-diff.json"

	required = [
		tracker_csv,
		tracker_json,
		worklist_md,
		top_md,
		commands_md,
		summary_md,
		metadata_json,
		badges_json,
		status_json,
		index_md,
		issue_plan_md,
		manifest_json,
		tasklist_a_md,
		tasklist_b_md,
		tasklist_c_md,
		tasklist_d_md,
		issue_body_a_md,
		issue_body_b_md,
		issue_body_c_md,
		issue_body_d_md,
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
	badges = json.loads(badges_json.read_text())
	status = json.loads(status_json.read_text())
	summary = metadata.get("summary", {})
	phase_counts_meta = metadata.get("phase_counts", {})
	flag_counts_meta = metadata.get("flag_counts", {})
	top_meta = metadata.get("top_priority_rules", [])
	if not metadata.get("upstream_ref_requested"):
		fail("metadata missing upstream_ref_requested")
	if not metadata.get("upstream_commit"):
		fail("metadata missing upstream_commit")
	if int(badges.get("schema_version", -1)) != 1:
		fail("badges schema_version must be 1")
	if int(status.get("schema_version", -1)) != 1:
		fail("status schema_version must be 1")
	if badges.get("generated_at_utc") != metadata.get("generated_at_utc"):
		fail("badges generated_at_utc mismatch with metadata")
	if status.get("generated_at_utc") != metadata.get("generated_at_utc"):
		fail("status generated_at_utc mismatch with metadata")
	if badges.get("upstream_commit") != metadata.get("upstream_commit"):
		fail("badges upstream_commit mismatch with metadata")
	if badges.get("upstream_ref_requested") != metadata.get("upstream_ref_requested"):
		fail("badges upstream_ref_requested mismatch with metadata")

	# Badge data checks
	badge_metrics = badges.get("metrics", {})
	if int(badge_metrics.get("total_rules", -1)) != int(summary.get("total_rules", -2)):
		fail("badges total_rules mismatch with metadata summary")
	if int(badge_metrics.get("flagged_rules", -1)) != int(summary.get("flagged_rules", -2)):
		fail("badges flagged_rules mismatch with metadata summary")
	if int(badge_metrics.get("aligned_rules", -1)) != int(summary.get("aligned_rules", -2)):
		fail("badges aligned_rules mismatch with metadata summary")
	if int(badge_metrics.get("critical_rules", -1)) != int(metadata.get("phase_counts", {}).get("A_critical", -2)):
		fail("badges critical_rules mismatch with metadata phase counts")
	if badge_metrics.get("health", "") != status.get("health", ""):
		fail("badges health mismatch with status artifact")
	if badge_metrics.get("health_reason", "") != status.get("reason", ""):
		fail("badges health_reason mismatch with status artifact")
	badge_names = badges.get("badges", {})
	if badge_names.get("parity_health", "") != status.get("health", ""):
		fail("badges parity_health mismatch with status artifact")
	color_map = {"green": "brightgreen", "yellow": "yellow", "red": "red"}
	expected_color = color_map.get(status.get("health", ""), "lightgrey")
	badge_colors = badges.get("badge_colors", {})
	if badge_colors.get("parity_health", "") != expected_color:
		fail("badges parity_health color mismatch")

	# Status data checks
	status_summary = status.get("summary", {})
	status_phase_counts = status.get("phase_counts", {})
	if int(status_summary.get("total_rules", -1)) != int(summary.get("total_rules", -2)):
		fail("status total_rules mismatch with metadata summary")
	if int(status_summary.get("flagged_rules", -1)) != int(summary.get("flagged_rules", -2)):
		fail("status flagged_rules mismatch with metadata summary")
	if int(status_summary.get("aligned_rules", -1)) != int(summary.get("aligned_rules", -2)):
		fail("status aligned_rules mismatch with metadata summary")
	if int(status_phase_counts.get("A_critical", -1)) != int(phase_counts_meta.get("A_critical", -2)):
		fail("status A_critical mismatch with metadata phase counts")
	if int(status_phase_counts.get("B_high", -1)) != int(phase_counts_meta.get("B_high", -2)):
		fail("status B_high mismatch with metadata phase counts")
	if int(status_phase_counts.get("C_medium", -1)) != int(phase_counts_meta.get("C_medium", -2)):
		fail("status C_medium mismatch with metadata phase counts")
	if int(status_phase_counts.get("D_low", -1)) != int(phase_counts_meta.get("D_low", -2)):
		fail("status D_low mismatch with metadata phase counts")
	if int(status_phase_counts.get("aligned", -1)) != int(phase_counts_meta.get("aligned", -2)):
		fail("status aligned mismatch with metadata phase counts")
	if status.get("upstream_commit") != metadata.get("upstream_commit"):
		fail("status upstream_commit mismatch with metadata")
	if status.get("upstream_ref_requested") != metadata.get("upstream_ref_requested"):
		fail("status upstream_ref_requested mismatch with metadata")

	status_direct = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_status.py")],
		check=False,
		capture_output=True,
		text=True,
	)
	if status_direct.returncode != 0:
		fail(f"direct status script failed: exit={status_direct.returncode}")
	if "typescript-eslint-rule-parity-status.json" not in (status_direct.stdout + status_direct.stderr):
		fail("direct status script output missing status artifact path token")
	status_direct_lines = extract_status_write_lines(status_direct.stdout + status_direct.stderr)
	if not status_direct_lines:
		fail("direct status script output missing status artifact write line")

	status_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:status"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if status_cmd.returncode != 0:
		fail(f"status command failed: exit={status_cmd.returncode}")
	assert_no_pnpm_lifecycle_noise("status command stdout", status_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("status command stderr", status_cmd.stderr)
	if "typescript-eslint-rule-parity-status.json" not in (status_cmd.stdout + status_cmd.stderr):
		fail("status command output missing status artifact path token")
	status_lines = extract_status_write_lines(status_cmd.stdout + status_cmd.stderr)
	if not status_lines:
		fail("status command output missing status artifact write line")
	if status_lines != status_direct_lines:
		fail("status command write-line output mismatch with direct status script")
	status_after_cmd = json.loads(status_json.read_text())
	if status_after_cmd != status:
		fail("status command output mutated status artifact unexpectedly")

	expected_health, expected_reason = compute_health_reason(
		critical=int(phase_counts_meta.get("A_critical", 0)),
		high=int(phase_counts_meta.get("B_high", 0)),
		flagged=int(summary.get("flagged_rules", 0)),
	)
	expected_health_reason_marker = f"health is {expected_health} ({expected_reason})"
	if status.get("health") != expected_health:
		fail(f"status health mismatch: expected={expected_health} actual={status.get('health')}")
	if status.get("reason", "") != expected_reason:
		fail(f"status reason mismatch: expected={expected_reason} actual={status.get('reason', '')}")

	# Status strict-mode exit-code checks
	status_strict = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_status.py"), "--fail-on-red"],
		check=False,
		capture_output=True,
		text=True,
	)
	status_strict_yellow = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_status.py"), "--fail-on-yellow"],
		check=False,
		capture_output=True,
		text=True,
	)
	expected_status_strict_exit = 2 if expected_health == "red" else 0
	if status_strict.returncode != expected_status_strict_exit:
		fail(
			"status strict exit-code mismatch: "
			f"expected={expected_status_strict_exit} actual={status_strict.returncode}"
		)
	if expected_status_strict_exit == 2 and "[parity-status] ERROR:" not in status_strict.stderr:
		fail("status strict stderr missing parity-status error prefix")
	if expected_status_strict_exit == 2 and expected_health_reason_marker not in status_strict.stderr:
		fail("status strict stderr missing health+reason message")
	expected_status_strict_yellow_exit = 3 if expected_health in {"yellow", "red"} else 0
	if status_strict_yellow.returncode != expected_status_strict_yellow_exit:
		fail(
			"status strict-yellow exit-code mismatch: "
			f"expected={expected_status_strict_yellow_exit} actual={status_strict_yellow.returncode}"
		)
	if expected_status_strict_yellow_exit == 3 and "[parity-status] ERROR:" not in status_strict_yellow.stderr:
		fail("status strict-yellow stderr missing parity-status error prefix")
	if expected_status_strict_yellow_exit == 3 and expected_health_reason_marker not in status_strict_yellow.stderr:
		fail("status strict-yellow stderr missing health+reason message")
	status_strict_lines = extract_status_write_lines(status_strict.stdout + status_strict.stderr)
	status_strict_yellow_lines = extract_status_write_lines(status_strict_yellow.stdout + status_strict_yellow.stderr)
	if not status_strict_lines:
		fail("status strict output missing status artifact write line")
	if not status_strict_yellow_lines:
		fail("status strict-yellow output missing status artifact write line")
	if status_strict_lines != status_lines:
		fail("status strict write-line output mismatch with non-strict status command")
	if status_strict_yellow_lines != status_lines:
		fail("status strict-yellow write-line output mismatch with non-strict status command")
	status_after_direct_strict = json.loads(status_json.read_text())
	if status_after_direct_strict != status:
		fail("status strict direct checks mutated status artifact unexpectedly")

	# Status npm command wrapper checks
	status_cmd_strict = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:status:strict"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if status_cmd_strict.returncode != expected_status_strict_exit:
		fail(
			"status command strict exit-code mismatch: "
			f"expected={expected_status_strict_exit} actual={status_cmd_strict.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("status command strict stdout", status_cmd_strict.stdout)
	assert_no_pnpm_lifecycle_noise("status command strict stderr", status_cmd_strict.stderr)
	if "typescript-eslint-rule-parity-status.json" not in (status_cmd_strict.stdout + status_cmd_strict.stderr):
		fail("status command strict output missing status artifact path token")
	if expected_status_strict_exit == 2 and "[parity-status] ERROR:" not in status_cmd_strict.stderr:
		fail("status command strict stderr missing parity-status error prefix")
	if expected_status_strict_exit == 2 and expected_health_reason_marker not in status_cmd_strict.stderr:
		fail("status command strict stderr missing health+reason message")
	status_strict_prefixed_lines = extract_prefixed_lines(status_strict.stdout + status_strict.stderr, ("[parity-status]",))
	status_strict_yellow_prefixed_lines = extract_prefixed_lines(
		status_strict_yellow.stdout + status_strict_yellow.stderr, ("[parity-status]",)
	)
	status_cmd_strict_prefixed_lines = extract_prefixed_lines(status_cmd_strict.stdout + status_cmd_strict.stderr, ("[parity-status]",))
	if status_cmd_strict_prefixed_lines != status_strict_prefixed_lines:
		fail("status command strict prefixed stderr output mismatch with direct strict mode")
	status_cmd_strict_lines = extract_status_write_lines(status_cmd_strict.stdout + status_cmd_strict.stderr)
	if status_cmd_strict_lines != status_strict_lines:
		fail("status command strict write-line output mismatch with direct strict mode")
	status_after_cmd_strict = json.loads(status_json.read_text())
	if status_after_cmd_strict != status:
		fail("status command strict mutated status artifact unexpectedly")

	status_cmd_strict_yellow = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:status:strict:yellow"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if status_cmd_strict_yellow.returncode != expected_status_strict_yellow_exit:
		fail(
			"status command strict-yellow exit-code mismatch: "
			f"expected={expected_status_strict_yellow_exit} actual={status_cmd_strict_yellow.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("status command strict-yellow stdout", status_cmd_strict_yellow.stdout)
	assert_no_pnpm_lifecycle_noise("status command strict-yellow stderr", status_cmd_strict_yellow.stderr)
	if "typescript-eslint-rule-parity-status.json" not in (status_cmd_strict_yellow.stdout + status_cmd_strict_yellow.stderr):
		fail("status command strict-yellow output missing status artifact path token")
	if expected_status_strict_yellow_exit == 3 and "[parity-status] ERROR:" not in status_cmd_strict_yellow.stderr:
		fail("status command strict-yellow stderr missing parity-status error prefix")
	if expected_status_strict_yellow_exit == 3 and expected_health_reason_marker not in status_cmd_strict_yellow.stderr:
		fail("status command strict-yellow stderr missing health+reason message")
	status_cmd_strict_yellow_prefixed_lines = extract_prefixed_lines(
		status_cmd_strict_yellow.stdout + status_cmd_strict_yellow.stderr, ("[parity-status]",)
	)
	if status_cmd_strict_yellow_prefixed_lines != status_strict_yellow_prefixed_lines:
		fail("status command strict-yellow prefixed stderr output mismatch with direct strict-yellow mode")
	status_cmd_strict_yellow_lines = extract_status_write_lines(status_cmd_strict_yellow.stdout + status_cmd_strict_yellow.stderr)
	if status_cmd_strict_yellow_lines != status_strict_yellow_lines:
		fail("status command strict-yellow write-line output mismatch with direct strict-yellow mode")
	status_after_cmd_strict_yellow = json.loads(status_json.read_text())
	if status_after_cmd_strict_yellow != status:
		fail("status command strict-yellow mutated status artifact unexpectedly")

	# Unified gate script exit-code checks (skip clean-check phase to avoid recursion)
	gate_red = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold", "red", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	expected_gate_red_exit = 2 if expected_health == "red" else 0
	if gate_red.returncode != expected_gate_red_exit:
		fail(
			"parity gate red exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_red.returncode}"
		)
	if "[parity-gate] Applying red threshold gates" not in (gate_red.stdout + gate_red.stderr):
		fail("parity gate red output missing red-threshold marker")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_red.stderr:
		fail("parity gate red stderr missing health+reason message")
	if expected_gate_red_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=red)." not in (gate_red.stdout + gate_red.stderr):
		fail("parity gate red success output missing final OK message")

	gate_yellow = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold", "yellow", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	expected_gate_yellow_exit = 3 if expected_health in {"yellow", "red"} else 0
	if gate_yellow.returncode != expected_gate_yellow_exit:
		fail(
			"parity gate yellow exit-code mismatch: "
			f"expected={expected_gate_yellow_exit} actual={gate_yellow.returncode}"
		)
	if "[parity-gate] Applying yellow threshold gates" not in (gate_yellow.stdout + gate_yellow.stderr):
		fail("parity gate yellow output missing yellow-threshold marker")
	if expected_gate_yellow_exit == 3 and expected_health_reason_marker not in gate_yellow.stderr:
		fail("parity gate yellow stderr missing health+reason message")
	if expected_gate_yellow_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=yellow)." not in (gate_yellow.stdout + gate_yellow.stderr):
		fail("parity gate yellow success output missing final OK message")
	gate_red_prefixed_lines = extract_prefixed_lines(
		gate_red.stdout + gate_red.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	gate_yellow_prefixed_lines = extract_prefixed_lines(
		gate_yellow.stdout + gate_yellow.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)

	# Unified gate script argument validation checks
	usage_prefix = "Usage: bash scripts/run_ts_eslint_parity_gate.sh"
	usage_threshold_token = "--threshold=red|--threshold=yellow"
	usage_skip_checks_token = "[--skip-checks]"

	gate_help = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--help"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_help.returncode != 0:
		fail("parity gate --help exit code must be 0")
	if usage_prefix not in (gate_help.stdout + gate_help.stderr):
		fail("parity gate --help missing usage message")
	if usage_threshold_token not in (gate_help.stdout + gate_help.stderr):
		fail("parity gate --help missing threshold forms in usage message")
	if usage_skip_checks_token not in (gate_help.stdout + gate_help.stderr):
		fail("parity gate --help missing skip-checks token in usage message")
	gate_short_help = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "-h"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_short_help.returncode != 0:
		fail("parity gate -h exit code must be 0")
	if usage_prefix not in (gate_short_help.stdout + gate_short_help.stderr):
		fail("parity gate -h missing usage message")
	if usage_threshold_token not in (gate_short_help.stdout + gate_short_help.stderr):
		fail("parity gate -h missing threshold forms in usage message")
	if usage_skip_checks_token not in (gate_short_help.stdout + gate_short_help.stderr):
		fail("parity gate -h missing skip-checks token in usage message")

	gate_invalid_threshold = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold", "blue", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_invalid_threshold.returncode != 1:
		fail("parity gate invalid-threshold exit code must be 1")
	if "invalid threshold" not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing message")
	if usage_prefix not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing usage message")
	if usage_threshold_token not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing skip-checks token in usage message")

	gate_invalid_inline_threshold = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold=blue", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_invalid_inline_threshold.returncode != 1:
		fail("parity gate invalid-inline-threshold exit code must be 1")
	if "invalid threshold" not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing message")
	if usage_prefix not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing usage message")
	if usage_threshold_token not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing skip-checks token in usage message")

	gate_missing_threshold_value = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_missing_threshold_value.returncode != 1:
		fail("parity gate missing-threshold-value exit code must be 1")
	if "--threshold requires a value" not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing message")
	if usage_prefix not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing usage message")
	if usage_threshold_token not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing skip-checks token in usage message")

	gate_missing_inline_threshold_value = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold=", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_missing_inline_threshold_value.returncode != 1:
		fail("parity gate missing-inline-threshold-value exit code must be 1")
	if "--threshold requires a value" not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing message")
	if usage_prefix not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing usage message")
	if usage_threshold_token not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing skip-checks token in usage message")

	gate_duplicate_threshold = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--threshold=yellow",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold.returncode != 1:
		fail("parity gate duplicate-threshold exit code must be 1")
	if "duplicate --threshold argument" not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing message")
	if usage_prefix not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing skip-checks token in usage message")

	gate_duplicate_threshold_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--threshold",
			"yellow",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_spaced.returncode != 1:
		fail("parity gate duplicate-threshold-spaced exit code must be 1")
	if "duplicate --threshold argument" not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing message")
	if usage_prefix not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing skip-checks token in usage message")

	gate_duplicate_threshold_inline = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--threshold=yellow",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_inline.returncode != 1:
		fail("parity gate duplicate-threshold-inline exit code must be 1")
	if "duplicate --threshold argument" not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing message")
	if usage_prefix not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing skip-checks token in usage message")

	gate_inline_red = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold=red", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_inline_red.returncode != expected_gate_red_exit:
		fail(
			"parity gate inline red exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_inline_red.returncode}"
		)
	if "[parity-gate] Applying red threshold gates" not in (gate_inline_red.stdout + gate_inline_red.stderr):
		fail("parity gate inline red output missing red-threshold marker")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_inline_red.stderr:
		fail("parity gate inline red stderr missing health+reason message")
	if expected_gate_red_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=red)." not in (gate_inline_red.stdout + gate_inline_red.stderr):
		fail("parity gate inline red success output missing final OK message")
	if "[parity-gate] Running strict clean parity checks" in (gate_inline_red.stdout + gate_inline_red.stderr):
		fail("parity gate inline red should not run strict clean checks in --skip-checks mode")
	gate_inline_red_prefixed_lines = extract_prefixed_lines(
		gate_inline_red.stdout + gate_inline_red.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_inline_red_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate inline red prefixed output mismatch with direct red skip-check run")

	gate_inline_yellow = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--threshold=yellow", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_inline_yellow.returncode != expected_gate_yellow_exit:
		fail(
			"parity gate inline yellow exit-code mismatch: "
			f"expected={expected_gate_yellow_exit} actual={gate_inline_yellow.returncode}"
		)
	if "[parity-gate] Applying yellow threshold gates" not in (gate_inline_yellow.stdout + gate_inline_yellow.stderr):
		fail("parity gate inline yellow output missing yellow-threshold marker")
	if expected_gate_yellow_exit == 3 and expected_health_reason_marker not in gate_inline_yellow.stderr:
		fail("parity gate inline yellow stderr missing health+reason message")
	if expected_gate_yellow_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=yellow)." not in (gate_inline_yellow.stdout + gate_inline_yellow.stderr):
		fail("parity gate inline yellow success output missing final OK message")
	if "[parity-gate] Running strict clean parity checks" in (gate_inline_yellow.stdout + gate_inline_yellow.stderr):
		fail("parity gate inline yellow should not run strict clean checks in --skip-checks mode")
	gate_inline_yellow_prefixed_lines = extract_prefixed_lines(
		gate_inline_yellow.stdout + gate_inline_yellow.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_inline_yellow_prefixed_lines != gate_yellow_prefixed_lines:
		fail("parity gate inline yellow prefixed output mismatch with direct yellow skip-check run")

	gate_skip_only_default_red = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_skip_only_default_red.returncode != expected_gate_red_exit:
		fail(
			"parity gate skip-only default-red exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_skip_only_default_red.returncode}"
		)
	if "[parity-gate] Applying red threshold gates" not in (gate_skip_only_default_red.stdout + gate_skip_only_default_red.stderr):
		fail("parity gate skip-only default-red output missing red-threshold marker")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_skip_only_default_red.stderr:
		fail("parity gate skip-only default-red stderr missing health+reason message")
	if expected_gate_red_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=red)." not in (
		gate_skip_only_default_red.stdout + gate_skip_only_default_red.stderr
	):
		fail("parity gate skip-only default-red success output missing final OK message")
	if "[parity-gate] Running strict clean parity checks" in (gate_skip_only_default_red.stdout + gate_skip_only_default_red.stderr):
		fail("parity gate skip-only default-red should not run strict clean checks in --skip-checks mode")
	gate_skip_only_default_red_prefixed_lines = extract_prefixed_lines(
		gate_skip_only_default_red.stdout + gate_skip_only_default_red.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_skip_only_default_red_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate skip-only default-red prefixed output mismatch with direct red skip-check run")

	gate_reordered_flags = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--skip-checks", "--threshold=yellow"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_reordered_flags.returncode != expected_gate_yellow_exit:
		fail(
			"parity gate reordered-flags yellow exit-code mismatch: "
			f"expected={expected_gate_yellow_exit} actual={gate_reordered_flags.returncode}"
		)
	if "[parity-gate] Applying yellow threshold gates" not in (gate_reordered_flags.stdout + gate_reordered_flags.stderr):
		fail("parity gate reordered-flags output missing yellow-threshold marker")
	if expected_gate_yellow_exit == 3 and expected_health_reason_marker not in gate_reordered_flags.stderr:
		fail("parity gate reordered-flags yellow stderr missing health+reason message")
	if expected_gate_yellow_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=yellow)." not in (
		gate_reordered_flags.stdout + gate_reordered_flags.stderr
	):
		fail("parity gate reordered-flags yellow success output missing final OK message")
	if "[parity-gate] Running strict clean parity checks" in (gate_reordered_flags.stdout + gate_reordered_flags.stderr):
		fail("parity gate reordered-flags should not run strict clean checks in --skip-checks mode")
	gate_reordered_flags_prefixed_lines = extract_prefixed_lines(
		gate_reordered_flags.stdout + gate_reordered_flags.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_reordered_flags_prefixed_lines != gate_yellow_prefixed_lines:
		fail("parity gate reordered-flags prefixed output mismatch with direct yellow skip-check run")

	gate_unknown_arg = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--not-a-real-flag"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_unknown_arg.returncode != 1:
		fail("parity gate unknown-arg exit code must be 1")
	if "unknown argument" not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing message")
	if usage_prefix not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing usage message")
	if usage_threshold_token not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing skip-checks token in usage message")

	gate_duplicate_skip_checks = subprocess.run(
		["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--skip-checks", "--skip-checks"],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_skip_checks.returncode != 1:
		fail("parity gate duplicate-skip-checks exit code must be 1")
	if "duplicate --skip-checks argument" not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing message")
	if usage_prefix not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing skip-checks token in usage message")

	# Quick gate npm command wrappers
	gate_quick = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:gate:quick"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_quick.returncode != expected_gate_red_exit:
		fail(
			"parity gate quick exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_quick.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity gate quick stdout", gate_quick.stdout)
	assert_no_pnpm_lifecycle_noise("parity gate quick stderr", gate_quick.stderr)
	if "[parity-gate] Skipping strict clean parity checks (--skip-checks)." not in (gate_quick.stdout + gate_quick.stderr):
		fail("parity gate quick output missing skip-checks message")
	if "[parity-gate] Applying red threshold gates" not in (gate_quick.stdout + gate_quick.stderr):
		fail("parity gate quick output missing red-threshold marker")
	if "[parity-gate] Running strict clean parity checks" in (gate_quick.stdout + gate_quick.stderr):
		fail("parity gate quick should not run strict clean checks")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_quick.stderr:
		fail("parity gate quick stderr missing health+reason message")
	if expected_gate_red_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=red)." not in (gate_quick.stdout + gate_quick.stderr):
		fail("parity gate quick success output missing final OK message")
	gate_quick_prefixed_lines = extract_prefixed_lines(
		gate_quick.stdout + gate_quick.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_quick_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate quick prefixed output mismatch with direct red skip-check run")

	gate_quick_red = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:gate:quick:red"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_quick_red.returncode != expected_gate_red_exit:
		fail(
			"parity gate quick:red exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_quick_red.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity gate quick:red stdout", gate_quick_red.stdout)
	assert_no_pnpm_lifecycle_noise("parity gate quick:red stderr", gate_quick_red.stderr)
	if "[parity-gate] Skipping strict clean parity checks (--skip-checks)." not in (gate_quick_red.stdout + gate_quick_red.stderr):
		fail("parity gate quick:red output missing skip-checks message")
	if "[parity-gate] Applying red threshold gates" not in (gate_quick_red.stdout + gate_quick_red.stderr):
		fail("parity gate quick:red output missing red-threshold marker")
	if "[parity-gate] Running strict clean parity checks" in (gate_quick_red.stdout + gate_quick_red.stderr):
		fail("parity gate quick:red should not run strict clean checks")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_quick_red.stderr:
		fail("parity gate quick:red stderr missing health+reason message")
	if expected_gate_red_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=red)." not in (
		gate_quick_red.stdout + gate_quick_red.stderr
	):
		fail("parity gate quick:red success output missing final OK message")
	gate_quick_red_prefixed_lines = extract_prefixed_lines(
		gate_quick_red.stdout + gate_quick_red.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_quick_red_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate quick:red prefixed output mismatch with direct red skip-check run")

	gate_quick_yellow = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_quick_yellow.returncode != expected_gate_yellow_exit:
		fail(
			"parity gate quick:yellow exit-code mismatch: "
			f"expected={expected_gate_yellow_exit} actual={gate_quick_yellow.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity gate quick:yellow stdout", gate_quick_yellow.stdout)
	assert_no_pnpm_lifecycle_noise("parity gate quick:yellow stderr", gate_quick_yellow.stderr)
	if "[parity-gate] Skipping strict clean parity checks (--skip-checks)." not in (gate_quick_yellow.stdout + gate_quick_yellow.stderr):
		fail("parity gate quick:yellow output missing skip-checks message")
	if "[parity-gate] Applying yellow threshold gates" not in (gate_quick_yellow.stdout + gate_quick_yellow.stderr):
		fail("parity gate quick:yellow output missing yellow-threshold marker")
	if "[parity-gate] Running strict clean parity checks" in (gate_quick_yellow.stdout + gate_quick_yellow.stderr):
		fail("parity gate quick:yellow should not run strict clean checks")
	if expected_gate_yellow_exit == 3 and expected_health_reason_marker not in gate_quick_yellow.stderr:
		fail("parity gate quick:yellow stderr missing health+reason message")
	if expected_gate_yellow_exit == 0 and "[parity-gate] OK: parity gate passed (threshold=yellow)." not in (
		gate_quick_yellow.stdout + gate_quick_yellow.stderr
	):
		fail("parity gate quick:yellow success output missing final OK message")
	gate_quick_yellow_prefixed_lines = extract_prefixed_lines(
		gate_quick_yellow.stdout + gate_quick_yellow.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_quick_yellow_prefixed_lines != gate_yellow_prefixed_lines:
		fail("parity gate quick:yellow prefixed output mismatch with direct yellow skip-check run")

	flagged = [row for row in tracker_rows if int(row.get("priority_score", 0)) > 0]
	aligned = len(tracker_rows) - len(flagged)

	if summary.get("total_rules") != len(tracker_rows):
		fail("metadata summary.total_rules mismatch")
	if summary.get("flagged_rules") != len(flagged):
		fail("metadata summary.flagged_rules mismatch")
	if summary.get("aligned_rules") != aligned:
		fail("metadata summary.aligned_rules mismatch")
	if int(summary.get("aligned_rules", 0)) + int(summary.get("flagged_rules", 0)) != int(summary.get("total_rules", 0)):
		fail("metadata summary arithmetic mismatch: aligned + flagged must equal total")
	if int(status_summary.get("aligned_rules", 0)) + int(status_summary.get("flagged_rules", 0)) != int(
		status_summary.get("total_rules", 0)
	):
		fail("status summary arithmetic mismatch: aligned + flagged must equal total")
	if int(badge_metrics.get("aligned_rules", 0)) + int(badge_metrics.get("flagged_rules", 0)) != int(
		badge_metrics.get("total_rules", 0)
	):
		fail("badges metrics arithmetic mismatch: aligned + flagged must equal total")

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
		"typescript-eslint-rule-parity-commands.md",
		"typescript-eslint-rule-parity-summary.md",
		"typescript-eslint-rule-parity-metadata.json",
		"typescript-eslint-rule-parity-badges.json",
		"typescript-eslint-rule-parity-status.json",
		"typescript-eslint-rule-parity-index.md",
		"typescript-eslint-rule-parity-issue-plan.md",
		"typescript-eslint-rule-parity-diff.md",
		"typescript-eslint-rule-parity-diff.json",
		"typescript-eslint-rule-parity-tasklist-<phase>.md",
		"typescript-eslint-rule-parity-issue-body-A_critical.md",
		"typescript-eslint-rule-parity-issue-body-B_high.md",
		"typescript-eslint-rule-parity-issue-body-C_medium.md",
		"typescript-eslint-rule-parity-issue-body-D_low.md",
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
		"typescript-eslint-rule-parity-commands.md",
		"typescript-eslint-rule-parity-badges.json",
		"typescript-eslint-rule-parity-status.json",
		"typescript-eslint-rule-parity-issue-plan.md",
		"typescript-eslint-rule-parity-tracker.csv",
		"typescript-eslint-rule-parity-tracker.json",
		"typescript-eslint-rule-parity-metadata.json",
		"typescript-eslint-rule-parity-tasklist-A_critical.md",
		"typescript-eslint-rule-parity-tasklist-B_high.md",
		"typescript-eslint-rule-parity-tasklist-C_medium.md",
		"typescript-eslint-rule-parity-tasklist-D_low.md",
		"typescript-eslint-rule-parity-issue-body-A_critical.md",
		"typescript-eslint-rule-parity-issue-body-B_high.md",
		"typescript-eslint-rule-parity-issue-body-C_medium.md",
		"typescript-eslint-rule-parity-issue-body-D_low.md",
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

	# Issue body checks
	issue_body_by_phase = {
		"A_critical": issue_body_a_md,
		"B_high": issue_body_b_md,
		"C_medium": issue_body_c_md,
		"D_low": issue_body_d_md,
	}
	for phase, path in issue_body_by_phase.items():
		text = path.read_text()
		parsed = parse_issue_body_markdown(text, phase)
		expected = phase_counter.get(phase, 0)
		if parsed["task_count"] != expected:
			fail(f"issue body task count mismatch for {phase}: expected={expected} actual={parsed['task_count']}")
		if parsed["acceptance_checks"] != 4:
			fail(f"issue body acceptance checklist mismatch for {phase}: expected=4 actual={parsed['acceptance_checks']}")

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
		ci_summary_json_output = subprocess.run(
			["python3", str(root / "scripts/generate_ts_eslint_parity_ci_summary.py"), "--json"],
			check=True,
			capture_output=True,
			text=True,
		).stdout
	except subprocess.CalledProcessError as err:
		fail(f"ci summary script failed: {err}")

	ci_summary = parse_ci_summary_markdown(ci_summary_output)
	ci_summary_json = parse_ci_summary_json(ci_summary_json_output)
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
	if ci_summary["health"] != status.get("health"):
		fail("ci summary health mismatch")
	if ci_summary["health_reason"] != status.get("reason", ""):
		fail("ci summary health reason mismatch")
	if ci_summary["phase_counts"] != dict(phase_counter):
		fail("ci summary phase_counts mismatch")

	if ci_summary_json.get("upstream_ref_requested") != metadata.get("upstream_ref_requested"):
		fail("ci summary json upstream_ref mismatch")
	if ci_summary_json.get("upstream_commit") != metadata.get("upstream_commit"):
		fail("ci summary json upstream_commit mismatch")
	ci_json_summary = ci_summary_json.get("summary", {})
	for key in ("total_rules", "flagged_rules", "aligned_rules"):
		if int(ci_json_summary.get(key, -1)) != int(summary.get(key, -2)):
			fail(f"ci summary json {key} mismatch")
	if ci_summary_json.get("health") != status.get("health"):
		fail("ci summary json health mismatch")
	if ci_summary_json.get("health_reason", "") != status.get("reason", ""):
		fail("ci summary json health reason mismatch")
	if ci_summary_json.get("phase_counts", {}) != dict(phase_counter):
		fail("ci summary json phase_counts mismatch")
	diff_md_metrics = parse_diff_markdown_summary(diff_md.read_text()) if diff_md.exists() else {}
	diff_json_metrics = parse_diff_json_summary(diff_json.read_text()) if diff_json.exists() else {}
	expected_diff = diff_md_metrics or diff_json_metrics
	if diff_md_metrics and diff_json_metrics and diff_md_metrics != diff_json_metrics:
		fail("parity diff markdown/json summary mismatch")

	if expected_diff:
		if ci_summary["diff_metrics"] != expected_diff:
			fail("ci summary diff metrics mismatch with parity diff artifact")
		if ci_summary_json.get("diff_metrics", {}) != expected_diff:
			fail("ci summary json diff metrics mismatch with parity diff artifact")
	elif ci_summary["diff_metrics"]:
		fail("ci summary should not include diff metrics when parity diff artifact is absent")
	elif ci_summary_json.get("diff_metrics"):
		fail("ci summary json should not include diff metrics when parity diff artifact is absent")

	ci_summary_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:ci-summary"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if ci_summary_cmd.returncode != 0:
		fail(f"ci summary command failed: exit={ci_summary_cmd.returncode}")
	assert_no_pnpm_lifecycle_noise("ci summary command stdout", ci_summary_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("ci summary command stderr", ci_summary_cmd.stderr)
	ci_summary_cmd_parsed = parse_ci_summary_markdown(ci_summary_cmd.stdout)
	if ci_summary_cmd_parsed != ci_summary:
		fail("ci summary command output mismatch with direct script output")

	ci_summary_json_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:ci-summary:json"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if ci_summary_json_cmd.returncode != 0:
		fail(f"ci summary json command failed: exit={ci_summary_json_cmd.returncode}")
	assert_no_pnpm_lifecycle_noise("ci summary json command stdout", ci_summary_json_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("ci summary json command stderr", ci_summary_json_cmd.stderr)
	ci_summary_json_cmd_parsed = parse_ci_summary_json(ci_summary_json_cmd.stdout)
	if ci_summary_json_cmd_parsed != ci_summary_json:
		fail("ci summary json command output mismatch with direct script output")

	# CI summary strict-mode exit-code checks
	ci_summary_strict = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_ci_summary.py"), "--fail-on-red"],
		check=False,
		capture_output=True,
		text=True,
	)
	expected_ci_summary_strict_exit = 2 if status.get("health") == "red" else 0
	if ci_summary_strict.returncode != expected_ci_summary_strict_exit:
		fail(
			"ci summary strict exit-code mismatch: "
			f"expected={expected_ci_summary_strict_exit} actual={ci_summary_strict.returncode}"
		)
	if expected_ci_summary_strict_exit == 2 and "[parity-ci-summary] ERROR:" not in ci_summary_strict.stderr:
		fail("ci summary strict stderr missing parity-ci-summary error prefix")
	if expected_ci_summary_strict_exit == 2 and expected_health_reason_marker not in ci_summary_strict.stderr:
		fail("ci summary strict stderr missing health+reason message")

	ci_summary_strict_yellow = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_ci_summary.py"), "--fail-on-yellow"],
		check=False,
		capture_output=True,
		text=True,
	)
	expected_ci_summary_strict_yellow_exit = 3 if status.get("health") in {"yellow", "red"} else 0
	if ci_summary_strict_yellow.returncode != expected_ci_summary_strict_yellow_exit:
		fail(
			"ci summary strict-yellow exit-code mismatch: "
			f"expected={expected_ci_summary_strict_yellow_exit} actual={ci_summary_strict_yellow.returncode}"
		)
	if expected_ci_summary_strict_yellow_exit == 3 and "[parity-ci-summary] ERROR:" not in ci_summary_strict_yellow.stderr:
		fail("ci summary strict-yellow stderr missing parity-ci-summary error prefix")
	if expected_ci_summary_strict_yellow_exit == 3 and expected_health_reason_marker not in ci_summary_strict_yellow.stderr:
		fail("ci summary strict-yellow stderr missing health+reason message")

	# CI summary npm command wrapper checks
	ci_summary_cmd_strict = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:ci-summary:strict"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if ci_summary_cmd_strict.returncode != expected_ci_summary_strict_exit:
		fail(
			"ci summary command strict exit-code mismatch: "
			f"expected={expected_ci_summary_strict_exit} actual={ci_summary_cmd_strict.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("ci summary command strict stdout", ci_summary_cmd_strict.stdout)
	assert_no_pnpm_lifecycle_noise("ci summary command strict stderr", ci_summary_cmd_strict.stderr)
	ci_summary_cmd_strict_parsed = parse_ci_summary_markdown(ci_summary_cmd_strict.stdout)
	if ci_summary_cmd_strict_parsed != ci_summary:
		fail("ci summary command strict stdout mismatch with non-strict summary output")
	if expected_ci_summary_strict_exit == 2 and "[parity-ci-summary] ERROR:" not in ci_summary_cmd_strict.stderr:
		fail("ci summary command strict stderr missing parity-ci-summary error prefix")
	if expected_ci_summary_strict_exit == 2 and expected_health_reason_marker not in ci_summary_cmd_strict.stderr:
		fail("ci summary command strict stderr missing health+reason message")
	ci_summary_strict_prefixed_lines = extract_prefixed_lines(
		ci_summary_strict.stdout + ci_summary_strict.stderr, ("[parity-ci-summary]",)
	)
	ci_summary_cmd_strict_prefixed_lines = extract_prefixed_lines(
		ci_summary_cmd_strict.stdout + ci_summary_cmd_strict.stderr, ("[parity-ci-summary]",)
	)
	if ci_summary_cmd_strict_prefixed_lines != ci_summary_strict_prefixed_lines:
		fail("ci summary command strict prefixed stderr output mismatch with direct strict mode")

	ci_summary_cmd_strict_yellow = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:ci-summary:strict:yellow"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if ci_summary_cmd_strict_yellow.returncode != expected_ci_summary_strict_yellow_exit:
		fail(
			"ci summary command strict-yellow exit-code mismatch: "
			f"expected={expected_ci_summary_strict_yellow_exit} actual={ci_summary_cmd_strict_yellow.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("ci summary command strict-yellow stdout", ci_summary_cmd_strict_yellow.stdout)
	assert_no_pnpm_lifecycle_noise("ci summary command strict-yellow stderr", ci_summary_cmd_strict_yellow.stderr)
	ci_summary_cmd_strict_yellow_parsed = parse_ci_summary_markdown(ci_summary_cmd_strict_yellow.stdout)
	if ci_summary_cmd_strict_yellow_parsed != ci_summary:
		fail("ci summary command strict-yellow stdout mismatch with non-strict summary output")
	if expected_ci_summary_strict_yellow_exit == 3 and "[parity-ci-summary] ERROR:" not in ci_summary_cmd_strict_yellow.stderr:
		fail("ci summary command strict-yellow stderr missing parity-ci-summary error prefix")
	if expected_ci_summary_strict_yellow_exit == 3 and expected_health_reason_marker not in ci_summary_cmd_strict_yellow.stderr:
		fail("ci summary command strict-yellow stderr missing health+reason message")
	ci_summary_strict_yellow_prefixed_lines = extract_prefixed_lines(
		ci_summary_strict_yellow.stdout + ci_summary_strict_yellow.stderr, ("[parity-ci-summary]",)
	)
	ci_summary_cmd_strict_yellow_prefixed_lines = extract_prefixed_lines(
		ci_summary_cmd_strict_yellow.stdout + ci_summary_cmd_strict_yellow.stderr, ("[parity-ci-summary]",)
	)
	if ci_summary_cmd_strict_yellow_prefixed_lines != ci_summary_strict_yellow_prefixed_lines:
		fail("ci summary command strict-yellow prefixed stderr output mismatch with direct strict-yellow mode")

	# Parity doctor output checks
	try:
		doctor_plain = subprocess.run(
			["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py")],
			check=True,
			capture_output=True,
			text=True,
		).stdout
		doctor_md = subprocess.run(
			["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py"), "--markdown"],
			check=True,
			capture_output=True,
			text=True,
		).stdout
		doctor_json = subprocess.run(
			["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py"), "--json"],
			check=True,
			capture_output=True,
			text=True,
		).stdout
	except subprocess.CalledProcessError as err:
		fail(f"parity doctor script failed: {err}")

	if "Parity Doctor" not in doctor_plain:
		fail("parity doctor plain output missing title")
	if "### Parity Doctor" not in doctor_md:
		fail("parity doctor markdown output missing heading")

	doctor_plain_data = parse_doctor_plain_output(doctor_plain)
	doctor_md_data = parse_doctor_markdown_output(doctor_md)
	doctor_json_data = parse_doctor_json_output(doctor_json)

	for key in ("total_rules", "aligned_rules", "flagged_rules"):
		expected = int(summary.get(key, -1))
		if doctor_plain_data[key] != expected:
			fail(f"parity doctor plain output mismatch for {key}")
		if doctor_md_data[key] != expected:
			fail(f"parity doctor markdown output mismatch for {key}")

	expected_doctor_phases = {
		"A_critical": int(phase_counter.get("A_critical", 0)),
		"B_high": int(phase_counter.get("B_high", 0)),
		"C_medium": int(phase_counter.get("C_medium", 0)),
		"D_low": int(phase_counter.get("D_low", 0)),
	}
	if doctor_plain_data["phase_counts"] != expected_doctor_phases:
		fail("parity doctor plain phase counts mismatch")
	if doctor_md_data["phase_counts"] != expected_doctor_phases:
		fail("parity doctor markdown phase counts mismatch")
	doctor_json_phases = doctor_json_data.get("phase_counts", {})
	if doctor_json_phases != expected_doctor_phases:
		fail("parity doctor json phase counts mismatch")

	expected_doctor_top = [row.get("rule", "") for row in expected_top[:5]]
	if doctor_plain_data["top_rules"] != expected_doctor_top:
		fail("parity doctor plain top rules mismatch")
	if doctor_md_data["top_rules"] != expected_doctor_top:
		fail("parity doctor markdown top rules mismatch")
	if doctor_json_data.get("top_rules", []) != expected_doctor_top:
		fail("parity doctor json top rules mismatch")

	if doctor_plain_data.get("health") != status.get("health"):
		fail("parity doctor plain health mismatch")
	if doctor_md_data.get("health") != status.get("health"):
		fail("parity doctor markdown health mismatch")
	if doctor_json_data.get("health") != status.get("health"):
		fail("parity doctor json health mismatch")
	if doctor_plain_data.get("health_reason", "") != status.get("reason", ""):
		fail("parity doctor plain health reason mismatch")
	if doctor_md_data.get("health_reason", "") != status.get("reason", ""):
		fail("parity doctor markdown health reason mismatch")
	if doctor_json_data.get("reason", "") != status.get("reason", ""):
		fail("parity doctor json health reason mismatch")

	if int(doctor_json_data.get("schema_version", -1)) != 1:
		fail("parity doctor json schema_version must be 1")
	if doctor_json_data.get("generated_at_utc") != metadata.get("generated_at_utc"):
		fail("parity doctor json generated_at_utc mismatch")
	if doctor_json_data.get("upstream_ref_requested") != metadata.get("upstream_ref_requested"):
		fail("parity doctor json upstream_ref_requested mismatch")
	if doctor_json_data.get("upstream_commit") != metadata.get("upstream_commit"):
		fail("parity doctor json upstream_commit mismatch")

	doctor_json_summary = doctor_json_data.get("summary", {})
	for key in ("total_rules", "aligned_rules", "flagged_rules"):
		expected = int(summary.get(key, -1))
		if int(doctor_json_summary.get(key, -2)) != expected:
			fail(f"parity doctor json summary mismatch for {key}")

	doctor_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_cmd.returncode != 0:
		fail(f"parity doctor command failed: exit={doctor_cmd.returncode}")
	assert_no_pnpm_lifecycle_noise("parity doctor command stdout", doctor_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor command stderr", doctor_cmd.stderr)
	if parse_doctor_plain_output(doctor_cmd.stdout) != doctor_plain_data:
		fail("parity doctor command output mismatch with direct script output")

	doctor_markdown_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor:markdown"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_markdown_cmd.returncode != 0:
		fail(f"parity doctor markdown command failed: exit={doctor_markdown_cmd.returncode}")
	assert_no_pnpm_lifecycle_noise("parity doctor markdown command stdout", doctor_markdown_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor markdown command stderr", doctor_markdown_cmd.stderr)
	if parse_doctor_markdown_output(doctor_markdown_cmd.stdout) != doctor_md_data:
		fail("parity doctor markdown command output mismatch with direct script output")

	doctor_json_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor:json"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_json_cmd.returncode != 0:
		fail(f"parity doctor json command failed: exit={doctor_json_cmd.returncode}")
	assert_no_pnpm_lifecycle_noise("parity doctor json command stdout", doctor_json_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor json command stderr", doctor_json_cmd.stderr)
	if parse_doctor_json_output(doctor_json_cmd.stdout) != doctor_json_data:
		fail("parity doctor json command output mismatch with direct script output")

	# Parity doctor strict-mode exit-code checks
	doctor_strict = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py"), "--fail-on-critical"],
		check=False,
		capture_output=True,
		text=True,
	)
	doctor_json_strict = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py"), "--json", "--fail-on-critical"],
		check=False,
		capture_output=True,
		text=True,
	)
	doctor_yellow_strict = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py"), "--fail-on-yellow"],
		check=False,
		capture_output=True,
		text=True,
	)
	doctor_json_yellow_strict = subprocess.run(
		["python3", str(root / "scripts/generate_ts_eslint_parity_doctor.py"), "--json", "--fail-on-yellow"],
		check=False,
		capture_output=True,
		text=True,
	)
	expected_strict_exit = 2 if int(phase_counter.get("A_critical", 0)) > 0 else 0
	if doctor_strict.returncode != expected_strict_exit:
		fail(
			"parity doctor strict exit-code mismatch: "
			f"expected={expected_strict_exit} actual={doctor_strict.returncode}"
		)
	if doctor_json_strict.returncode != expected_strict_exit:
		fail(
			"parity doctor json strict exit-code mismatch: "
			f"expected={expected_strict_exit} actual={doctor_json_strict.returncode}"
		)
	if expected_strict_exit == 2 and "[parity-doctor] ERROR:" not in doctor_strict.stderr:
		fail("parity doctor strict stderr missing parity-doctor error prefix")
	if expected_strict_exit == 2 and "[parity-doctor] ERROR:" not in doctor_json_strict.stderr:
		fail("parity doctor json strict stderr missing parity-doctor error prefix")
	if expected_strict_exit == 2 and "A_critical backlog is non-zero" not in doctor_strict.stderr:
		fail("parity doctor strict stderr missing critical backlog message")
	if expected_strict_exit == 2 and "A_critical backlog is non-zero" not in doctor_json_strict.stderr:
		fail("parity doctor json strict stderr missing critical backlog message")
	expected_yellow_strict_exit = 3 if expected_health in {"yellow", "red"} else 0
	if doctor_yellow_strict.returncode != expected_yellow_strict_exit:
		fail(
			"parity doctor strict-yellow exit-code mismatch: "
			f"expected={expected_yellow_strict_exit} actual={doctor_yellow_strict.returncode}"
		)
	if doctor_json_yellow_strict.returncode != expected_yellow_strict_exit:
		fail(
			"parity doctor json strict-yellow exit-code mismatch: "
			f"expected={expected_yellow_strict_exit} actual={doctor_json_yellow_strict.returncode}"
		)
	if expected_yellow_strict_exit == 3 and "[parity-doctor] ERROR:" not in doctor_yellow_strict.stderr:
		fail("parity doctor strict-yellow stderr missing parity-doctor error prefix")
	if expected_yellow_strict_exit == 3 and "[parity-doctor] ERROR:" not in doctor_json_yellow_strict.stderr:
		fail("parity doctor json strict-yellow stderr missing parity-doctor error prefix")
	if expected_yellow_strict_exit == 3 and expected_health_reason_marker not in doctor_yellow_strict.stderr:
		fail("parity doctor strict-yellow stderr missing health+reason message")
	if expected_yellow_strict_exit == 3 and expected_health_reason_marker not in doctor_json_yellow_strict.stderr:
		fail("parity doctor json strict-yellow stderr missing health+reason message")

	# Doctor npm command wrapper checks
	doctor_cmd_strict = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor:strict"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_cmd_strict.returncode != expected_strict_exit:
		fail(
			"parity doctor command strict exit-code mismatch: "
			f"expected={expected_strict_exit} actual={doctor_cmd_strict.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity doctor command strict stdout", doctor_cmd_strict.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor command strict stderr", doctor_cmd_strict.stderr)
	if parse_doctor_plain_output(doctor_cmd_strict.stdout) != doctor_plain_data:
		fail("parity doctor command strict stdout mismatch with non-strict plain output")
	if expected_strict_exit == 2 and "[parity-doctor] ERROR:" not in doctor_cmd_strict.stderr:
		fail("parity doctor command strict stderr missing parity-doctor error prefix")
	if expected_strict_exit == 2 and "A_critical backlog is non-zero" not in doctor_cmd_strict.stderr:
		fail("parity doctor command strict stderr missing critical backlog message")
	doctor_strict_prefixed_lines = extract_prefixed_lines(doctor_strict.stdout + doctor_strict.stderr, ("[parity-doctor]",))
	doctor_cmd_strict_prefixed_lines = extract_prefixed_lines(
		doctor_cmd_strict.stdout + doctor_cmd_strict.stderr, ("[parity-doctor]",)
	)
	if doctor_cmd_strict_prefixed_lines != doctor_strict_prefixed_lines:
		fail("parity doctor command strict prefixed stderr output mismatch with direct strict mode")

	doctor_cmd_strict_yellow = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor:strict:yellow"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_cmd_strict_yellow.returncode != expected_yellow_strict_exit:
		fail(
			"parity doctor command strict-yellow exit-code mismatch: "
			f"expected={expected_yellow_strict_exit} actual={doctor_cmd_strict_yellow.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity doctor command strict-yellow stdout", doctor_cmd_strict_yellow.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor command strict-yellow stderr", doctor_cmd_strict_yellow.stderr)
	if parse_doctor_plain_output(doctor_cmd_strict_yellow.stdout) != doctor_plain_data:
		fail("parity doctor command strict-yellow stdout mismatch with non-strict plain output")
	if expected_yellow_strict_exit == 3 and "[parity-doctor] ERROR:" not in doctor_cmd_strict_yellow.stderr:
		fail("parity doctor command strict-yellow stderr missing parity-doctor error prefix")
	if expected_yellow_strict_exit == 3 and expected_health_reason_marker not in doctor_cmd_strict_yellow.stderr:
		fail("parity doctor command strict-yellow stderr missing health+reason message")
	doctor_yellow_strict_prefixed_lines = extract_prefixed_lines(
		doctor_yellow_strict.stdout + doctor_yellow_strict.stderr, ("[parity-doctor]",)
	)
	doctor_cmd_strict_yellow_prefixed_lines = extract_prefixed_lines(
		doctor_cmd_strict_yellow.stdout + doctor_cmd_strict_yellow.stderr, ("[parity-doctor]",)
	)
	if doctor_cmd_strict_yellow_prefixed_lines != doctor_yellow_strict_prefixed_lines:
		fail("parity doctor command strict-yellow prefixed stderr output mismatch with direct strict-yellow mode")

	doctor_cmd_json_strict = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor:json:strict"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_cmd_json_strict.returncode != expected_strict_exit:
		fail(
			"parity doctor command json strict exit-code mismatch: "
			f"expected={expected_strict_exit} actual={doctor_cmd_json_strict.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity doctor command json strict stdout", doctor_cmd_json_strict.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor command json strict stderr", doctor_cmd_json_strict.stderr)
	if parse_doctor_json_output(doctor_cmd_json_strict.stdout) != doctor_json_data:
		fail("parity doctor command json strict stdout mismatch with non-strict json output")
	if expected_strict_exit == 2 and "[parity-doctor] ERROR:" not in doctor_cmd_json_strict.stderr:
		fail("parity doctor command json strict stderr missing parity-doctor error prefix")
	if expected_strict_exit == 2 and "A_critical backlog is non-zero" not in doctor_cmd_json_strict.stderr:
		fail("parity doctor command json strict stderr missing critical backlog message")
	doctor_json_strict_prefixed_lines = extract_prefixed_lines(
		doctor_json_strict.stdout + doctor_json_strict.stderr, ("[parity-doctor]",)
	)
	doctor_cmd_json_strict_prefixed_lines = extract_prefixed_lines(
		doctor_cmd_json_strict.stdout + doctor_cmd_json_strict.stderr, ("[parity-doctor]",)
	)
	if doctor_cmd_json_strict_prefixed_lines != doctor_json_strict_prefixed_lines:
		fail("parity doctor command json strict prefixed stderr output mismatch with direct json strict mode")

	doctor_cmd_json_strict_yellow = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:doctor:json:strict:yellow"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if doctor_cmd_json_strict_yellow.returncode != expected_yellow_strict_exit:
		fail(
			"parity doctor command json strict-yellow exit-code mismatch: "
			f"expected={expected_yellow_strict_exit} actual={doctor_cmd_json_strict_yellow.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity doctor command json strict-yellow stdout", doctor_cmd_json_strict_yellow.stdout)
	assert_no_pnpm_lifecycle_noise("parity doctor command json strict-yellow stderr", doctor_cmd_json_strict_yellow.stderr)
	if parse_doctor_json_output(doctor_cmd_json_strict_yellow.stdout) != doctor_json_data:
		fail("parity doctor command json strict-yellow stdout mismatch with non-strict json output")
	if expected_yellow_strict_exit == 3 and "[parity-doctor] ERROR:" not in doctor_cmd_json_strict_yellow.stderr:
		fail("parity doctor command json strict-yellow stderr missing parity-doctor error prefix")
	if expected_yellow_strict_exit == 3 and expected_health_reason_marker not in doctor_cmd_json_strict_yellow.stderr:
		fail("parity doctor command json strict-yellow stderr missing health+reason message")
	doctor_json_yellow_strict_prefixed_lines = extract_prefixed_lines(
		doctor_json_yellow_strict.stdout + doctor_json_yellow_strict.stderr, ("[parity-doctor]",)
	)
	doctor_cmd_json_strict_yellow_prefixed_lines = extract_prefixed_lines(
		doctor_cmd_json_strict_yellow.stdout + doctor_cmd_json_strict_yellow.stderr, ("[parity-doctor]",)
	)
	if doctor_cmd_json_strict_yellow_prefixed_lines != doctor_json_yellow_strict_prefixed_lines:
		fail("parity doctor command json strict-yellow prefixed stderr output mismatch with direct json strict-yellow mode")

	doctor_json_strict_data = parse_doctor_json_output(doctor_json_strict.stdout)
	doctor_json_yellow_strict_data = parse_doctor_json_output(doctor_json_yellow_strict.stdout)
	if doctor_json_strict_data.get("summary") != doctor_json_data.get("summary"):
		fail("parity doctor json strict summary mismatch with json mode")
	if doctor_json_strict_data.get("phase_counts") != doctor_json_data.get("phase_counts"):
		fail("parity doctor json strict phase counts mismatch with json mode")
	if doctor_json_strict_data.get("top_rules") != doctor_json_data.get("top_rules"):
		fail("parity doctor json strict top rules mismatch with json mode")
	if doctor_json_strict_data.get("health") != doctor_json_data.get("health"):
		fail("parity doctor json strict health mismatch with json mode")
	if doctor_json_strict_data.get("reason") != doctor_json_data.get("reason"):
		fail("parity doctor json strict reason mismatch with json mode")
	if doctor_json_yellow_strict_data.get("summary") != doctor_json_data.get("summary"):
		fail("parity doctor json strict-yellow summary mismatch with json mode")
	if doctor_json_yellow_strict_data.get("phase_counts") != doctor_json_data.get("phase_counts"):
		fail("parity doctor json strict-yellow phase counts mismatch with json mode")
	if doctor_json_yellow_strict_data.get("top_rules") != doctor_json_data.get("top_rules"):
		fail("parity doctor json strict-yellow top rules mismatch with json mode")
	if doctor_json_yellow_strict_data.get("health") != doctor_json_data.get("health"):
		fail("parity doctor json strict-yellow health mismatch with json mode")
	if doctor_json_yellow_strict_data.get("reason") != doctor_json_data.get("reason"):
		fail("parity doctor json strict-yellow reason mismatch with json mode")

	print("[parity-check] OK: all parity artifacts are consistent.")


if __name__ == "__main__":
	main()
