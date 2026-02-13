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


def extract_nonempty_lines(text: str) -> list[str]:
	return [line.strip() for line in text.splitlines() if line.strip()]


def assert_no_pnpm_lifecycle_noise(label: str, text: str) -> None:
	if "rslint-monorepo@" in text:
		fail(f"{label} contains pnpm lifecycle banner output; expected --silent wrapper output")
	if re.search(r"^>\s", text, flags=re.MULTILINE):
		fail(f"{label} contains pnpm lifecycle command echo output; expected --silent wrapper output")


def assert_exact_nonempty_lines(label: str, text: str, expected_lines: list[str]) -> None:
	actual_lines = extract_nonempty_lines(text)
	if actual_lines != expected_lines:
		fail(f"{label} line mismatch: expected={expected_lines} actual={actual_lines}")


def assert_line_occurs_once(label: str, text: str, expected_line: str) -> None:
	lines = [line.strip() for line in text.splitlines()]
	count = sum(1 for line in lines if line == expected_line)
	if count != 1:
		fail(f"{label} expected usage line once: count={count} line={expected_line}")


def assert_exact_error_plus_usage(label: str, text: str, expected_error_line: str, expected_usage_line: str) -> None:
	assert_exact_nonempty_lines(label, text, [expected_error_line, expected_usage_line])


def assert_gate_success_contract(label: str, proc: subprocess.CompletedProcess[str], threshold: str, expected_exit: int) -> None:
	ok_line = f"[parity-gate] OK: parity gate passed (threshold={threshold})."
	combined = proc.stdout + proc.stderr
	if expected_exit == 0:
		if ok_line not in combined:
			fail(f"{label} success output missing final OK message")
		if proc.stderr.strip():
			fail(f"{label} stderr must be empty on success")
	else:
		if ok_line in combined:
			fail(f"{label} failing output must not include final OK message")


def assert_gate_wrapper_help_contract(
	label: str, proc: subprocess.CompletedProcess[str], expected_usage_line: str
) -> list[str]:
	if proc.returncode != 0:
		fail(f"{label} exit code must be 0")
	assert_no_pnpm_lifecycle_noise(f"{label} stdout", proc.stdout)
	assert_no_pnpm_lifecycle_noise(f"{label} stderr", proc.stderr)
	if proc.stdout.strip():
		fail(f"{label} stdout must be empty")
	assert_exact_nonempty_lines(f"{label} stderr", proc.stderr, [expected_usage_line])
	return extract_nonempty_lines(proc.stderr)


def assert_gate_wrapper_unknown_arg_contract(
	label: str,
	proc: subprocess.CompletedProcess[str],
	expected_error_line: str,
	expected_usage_line: str,
) -> list[str]:
	if proc.returncode != 1:
		fail(f"{label} exit code must be 1")
	assert_no_pnpm_lifecycle_noise(f"{label} stdout", proc.stdout)
	assert_no_pnpm_lifecycle_noise(f"{label} stderr", proc.stderr)
	if proc.stdout.strip():
		fail(f"{label} stdout must be empty")
	assert_line_occurs_once(f"{label} stderr", proc.stderr, expected_usage_line)
	assert_exact_error_plus_usage(f"{label} stderr", proc.stderr, expected_error_line, expected_usage_line)
	return extract_nonempty_lines(proc.stderr)


def assert_argparse_help_contract(label: str, proc: subprocess.CompletedProcess[str]) -> list[str]:
	if proc.returncode != 0:
		fail(f"{label} exit code must be 0")
	assert_no_pnpm_lifecycle_noise(f"{label} stdout", proc.stdout)
	assert_no_pnpm_lifecycle_noise(f"{label} stderr", proc.stderr)
	if proc.stderr.strip():
		fail(f"{label} stderr must be empty")
	lines = extract_nonempty_lines(proc.stdout)
	if not lines:
		fail(f"{label} stdout must include argparse help text")
	if not lines[0].startswith("usage: "):
		fail(f"{label} first help line must start with usage:")
	return lines


def assert_argparse_unknown_contract(
	label: str, proc: subprocess.CompletedProcess[str], expected_error_line: str
) -> list[str]:
	if proc.returncode != 2:
		fail(f"{label} exit code must be 2")
	assert_no_pnpm_lifecycle_noise(f"{label} stdout", proc.stdout)
	assert_no_pnpm_lifecycle_noise(f"{label} stderr", proc.stderr)
	if proc.stdout.strip():
		fail(f"{label} stdout must be empty")
	lines = extract_nonempty_lines(proc.stderr)
	if len(lines) < 2:
		fail(f"{label} stderr must include usage and error lines")
	if not lines[0].startswith("usage: "):
		fail(f"{label} first stderr line must start with usage:")
	if lines[-1] != expected_error_line:
		fail(f"{label} unknown-arg error mismatch: expected={expected_error_line} actual={lines[-1]}")
	return lines


def assert_wrapper_argparse_forwarding_contracts(
	root: pathlib.Path,
	script_path: pathlib.Path,
	contracts: list[tuple[str, list[str], list[str]]],
) -> None:
	help_precedence_cases = [
		("help-then-unknown", ["--help", "--not-a-real-flag"]),
		("unknown-then-help", ["--not-a-real-flag", "--help"]),
		("short-help-then-unknown", ["-h", "--not-a-real-flag"]),
		("unknown-then-short-help", ["--not-a-real-flag", "-h"]),
	]
	help_alias_cases = [
		("help-then-short-help", ["--help", "-h"]),
		("short-help-then-help", ["-h", "--help"]),
		("duplicate-help", ["--help", "--help"]),
		("duplicate-short-help", ["-h", "-h"]),
	]
	help_alias_precedence_cases = [
		("help-short-help-then-unknown", ["--help", "-h", "--not-a-real-flag"]),
		("short-help-help-then-unknown", ["-h", "--help", "--not-a-real-flag"]),
		("unknown-then-help-short-help", ["--not-a-real-flag", "--help", "-h"]),
		("unknown-then-short-help-help", ["--not-a-real-flag", "-h", "--help"]),
	]
	for wrapper_label, direct_args, wrapper_command in contracts:
		direct_help = subprocess.run(
			["python3", str(script_path), *direct_args, "--help"],
			check=False,
			capture_output=True,
			text=True,
		)
		direct_help_lines = assert_argparse_help_contract(f"direct {wrapper_label} help", direct_help)
		wrapper_help = subprocess.run(
			[*wrapper_command, "--help"],
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		wrapper_help_lines = assert_argparse_help_contract(f"{wrapper_label} help", wrapper_help)
		if wrapper_help_lines != direct_help_lines:
			fail(f"{wrapper_label} help output mismatch with direct script help baseline")

		direct_short_help = subprocess.run(
			["python3", str(script_path), *direct_args, "-h"],
			check=False,
			capture_output=True,
			text=True,
		)
		direct_short_help_lines = assert_argparse_help_contract(f"direct {wrapper_label} short-help", direct_short_help)
		if direct_short_help_lines != direct_help_lines:
			fail(f"direct {wrapper_label} short-help output mismatch with long-help baseline")
		wrapper_short_help = subprocess.run(
			[*wrapper_command, "-h"],
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		wrapper_short_help_lines = assert_argparse_help_contract(f"{wrapper_label} short-help", wrapper_short_help)
		if wrapper_short_help_lines != wrapper_help_lines:
			fail(f"{wrapper_label} short-help output mismatch with long-help baseline")
		for alias_label, alias_args in help_alias_cases:
			direct_help_alias = subprocess.run(
				["python3", str(script_path), *direct_args, *alias_args],
				check=False,
				capture_output=True,
				text=True,
			)
			direct_help_alias_lines = assert_argparse_help_contract(
				f"direct {wrapper_label} {alias_label}",
				direct_help_alias,
			)
			if direct_help_alias_lines != direct_help_lines:
				fail(f"direct {wrapper_label} {alias_label} output mismatch with help baseline")
			wrapper_help_alias = subprocess.run(
				[*wrapper_command, *alias_args],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			wrapper_help_alias_lines = assert_argparse_help_contract(
				f"{wrapper_label} {alias_label}",
				wrapper_help_alias,
			)
			if wrapper_help_alias_lines != wrapper_help_lines:
				fail(f"{wrapper_label} {alias_label} output mismatch with help baseline")
		for precedence_label, precedence_args in help_alias_precedence_cases:
			direct_alias_precedence = subprocess.run(
				["python3", str(script_path), *direct_args, *precedence_args],
				check=False,
				capture_output=True,
				text=True,
			)
			direct_alias_precedence_lines = assert_argparse_help_contract(
				f"direct {wrapper_label} {precedence_label}",
				direct_alias_precedence,
			)
			if direct_alias_precedence_lines != direct_help_lines:
				fail(f"direct {wrapper_label} {precedence_label} output mismatch with help baseline")
			wrapper_alias_precedence = subprocess.run(
				[*wrapper_command, *precedence_args],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			wrapper_alias_precedence_lines = assert_argparse_help_contract(
				f"{wrapper_label} {precedence_label}",
				wrapper_alias_precedence,
			)
			if wrapper_alias_precedence_lines != wrapper_help_lines:
				fail(f"{wrapper_label} {precedence_label} output mismatch with help baseline")

		for precedence_label, precedence_args in help_precedence_cases:
			direct_help_precedence = subprocess.run(
				["python3", str(script_path), *direct_args, *precedence_args],
				check=False,
				capture_output=True,
				text=True,
			)
			direct_help_precedence_lines = assert_argparse_help_contract(
				f"direct {wrapper_label} {precedence_label}",
				direct_help_precedence,
			)
			if direct_help_precedence_lines != direct_help_lines:
				fail(f"direct {wrapper_label} {precedence_label} output mismatch with help baseline")
			wrapper_help_precedence = subprocess.run(
				[*wrapper_command, *precedence_args],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			wrapper_help_precedence_lines = assert_argparse_help_contract(
				f"{wrapper_label} {precedence_label}",
				wrapper_help_precedence,
			)
			if wrapper_help_precedence_lines != wrapper_help_lines:
				fail(f"{wrapper_label} {precedence_label} output mismatch with help baseline")

		unknown_variant_cases = [
			("single-unknown", ["--not-a-real-flag"]),
			("duplicate-unknown-same-token", ["--not-a-real-flag", "--not-a-real-flag"]),
			("duplicate-unknown-distinct-tokens", ["--not-a-real-flag", "--still-not-a-real-flag"]),
			("duplicate-unknown-distinct-reordered", ["--still-not-a-real-flag", "--not-a-real-flag"]),
		]
		for unknown_label, unknown_forwarded_args in unknown_variant_cases:
			direct_unknown = subprocess.run(
				["python3", str(script_path), *direct_args, *unknown_forwarded_args],
				check=False,
				capture_output=True,
				text=True,
			)
			direct_unknown_lines = extract_nonempty_lines(direct_unknown.stderr)
			if not direct_unknown_lines:
				fail(f"direct {wrapper_label} {unknown_label} stderr must not be empty")
			direct_unknown_error_line = direct_unknown_lines[-1]
			direct_unknown_lines = assert_argparse_unknown_contract(
				f"direct {wrapper_label} {unknown_label}",
				direct_unknown,
				direct_unknown_error_line,
			)
			wrapper_unknown = subprocess.run(
				[*wrapper_command, *unknown_forwarded_args],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			wrapper_unknown_lines = assert_argparse_unknown_contract(
				f"{wrapper_label} {unknown_label}",
				wrapper_unknown,
				direct_unknown_error_line,
			)
			if wrapper_unknown_lines != direct_unknown_lines:
				fail(f"{wrapper_label} {unknown_label} stderr mismatch with direct script baseline")


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
	expected_status_write_line = f"wrote {status_json}"

	status_script = root / "scripts/generate_ts_eslint_parity_status.py"
	status_direct = subprocess.run(
		["python3", str(status_script)],
		check=False,
		capture_output=True,
		text=True,
	)
	if status_direct.returncode != 0:
		fail(f"direct status script failed: exit={status_direct.returncode}")
	if status_direct.stderr.strip():
		fail("direct status script stderr must be empty in non-strict mode")
	if "typescript-eslint-rule-parity-status.json" not in (status_direct.stdout + status_direct.stderr):
		fail("direct status script output missing status artifact path token")
	status_direct_lines = extract_status_write_lines(status_direct.stdout + status_direct.stderr)
	if not status_direct_lines:
		fail("direct status script output missing status artifact write line")
	if status_direct_lines != [expected_status_write_line]:
		fail("direct status script write-line output format mismatch")
	assert_exact_nonempty_lines("direct status script stdout", status_direct.stdout, [expected_status_write_line])

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
	if status_cmd.stderr.strip():
		fail("status command stderr must be empty in non-strict mode")
	if "typescript-eslint-rule-parity-status.json" not in (status_cmd.stdout + status_cmd.stderr):
		fail("status command output missing status artifact path token")
	status_lines = extract_status_write_lines(status_cmd.stdout + status_cmd.stderr)
	if not status_lines:
		fail("status command output missing status artifact write line")
	if status_lines != [expected_status_write_line]:
		fail("status command write-line output format mismatch")
	if status_lines != status_direct_lines:
		fail("status command write-line output mismatch with direct status script")
	assert_exact_nonempty_lines("status command stdout", status_cmd.stdout, [expected_status_write_line])
	status_after_cmd = json.loads(status_json.read_text())
	if status_after_cmd != status:
		fail("status command output mutated status artifact unexpectedly")
	status_cli_contracts = [
		(
			"status command",
			[],
			["pnpm", "--silent", "parity:ts-eslint:status"],
		),
		(
			"status command strict",
			["--fail-on-red"],
			["pnpm", "--silent", "parity:ts-eslint:status:strict"],
		),
		(
			"status command strict-yellow",
			["--fail-on-yellow"],
			["pnpm", "--silent", "parity:ts-eslint:status:strict:yellow"],
		),
	]
	assert_wrapper_argparse_forwarding_contracts(root, status_script, status_cli_contracts)

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
	if expected_status_strict_exit == 0 and status_strict.stderr.strip():
		fail("status strict stderr must be empty on success")
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
	if expected_status_strict_yellow_exit == 0 and status_strict_yellow.stderr.strip():
		fail("status strict-yellow stderr must be empty on success")
	status_strict_stderr_lines = extract_nonempty_lines(status_strict.stderr)
	status_strict_yellow_stderr_lines = extract_nonempty_lines(status_strict_yellow.stderr)
	status_strict_lines = extract_status_write_lines(status_strict.stdout + status_strict.stderr)
	status_strict_yellow_lines = extract_status_write_lines(status_strict_yellow.stdout + status_strict_yellow.stderr)
	if not status_strict_lines:
		fail("status strict output missing status artifact write line")
	if not status_strict_yellow_lines:
		fail("status strict-yellow output missing status artifact write line")
	if status_strict_lines != [expected_status_write_line]:
		fail("status strict write-line output format mismatch")
	if status_strict_yellow_lines != [expected_status_write_line]:
		fail("status strict-yellow write-line output format mismatch")
	assert_exact_nonempty_lines("status strict stdout", status_strict.stdout, [expected_status_write_line])
	assert_exact_nonempty_lines("status strict-yellow stdout", status_strict_yellow.stdout, [expected_status_write_line])
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
	if expected_status_strict_exit == 0 and status_cmd_strict.stderr.strip():
		fail("status command strict stderr must be empty on success")
	if "typescript-eslint-rule-parity-status.json" not in (status_cmd_strict.stdout + status_cmd_strict.stderr):
		fail("status command strict output missing status artifact path token")
	if expected_status_strict_exit == 2 and "[parity-status] ERROR:" not in status_cmd_strict.stderr:
		fail("status command strict stderr missing parity-status error prefix")
	if expected_status_strict_exit == 2 and expected_health_reason_marker not in status_cmd_strict.stderr:
		fail("status command strict stderr missing health+reason message")
	assert_exact_nonempty_lines("status command strict stderr", status_cmd_strict.stderr, status_strict_stderr_lines)
	status_strict_prefixed_lines = extract_prefixed_lines(status_strict.stdout + status_strict.stderr, ("[parity-status]",))
	status_strict_yellow_prefixed_lines = extract_prefixed_lines(
		status_strict_yellow.stdout + status_strict_yellow.stderr, ("[parity-status]",)
	)
	status_cmd_strict_prefixed_lines = extract_prefixed_lines(status_cmd_strict.stdout + status_cmd_strict.stderr, ("[parity-status]",))
	if status_cmd_strict_prefixed_lines != status_strict_prefixed_lines:
		fail("status command strict prefixed stderr output mismatch with direct strict mode")
	status_cmd_strict_lines = extract_status_write_lines(status_cmd_strict.stdout + status_cmd_strict.stderr)
	if status_cmd_strict_lines != [expected_status_write_line]:
		fail("status command strict write-line output format mismatch")
	assert_exact_nonempty_lines("status command strict stdout", status_cmd_strict.stdout, [expected_status_write_line])
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
	if expected_status_strict_yellow_exit == 0 and status_cmd_strict_yellow.stderr.strip():
		fail("status command strict-yellow stderr must be empty on success")
	if "typescript-eslint-rule-parity-status.json" not in (status_cmd_strict_yellow.stdout + status_cmd_strict_yellow.stderr):
		fail("status command strict-yellow output missing status artifact path token")
	if expected_status_strict_yellow_exit == 3 and "[parity-status] ERROR:" not in status_cmd_strict_yellow.stderr:
		fail("status command strict-yellow stderr missing parity-status error prefix")
	if expected_status_strict_yellow_exit == 3 and expected_health_reason_marker not in status_cmd_strict_yellow.stderr:
		fail("status command strict-yellow stderr missing health+reason message")
	assert_exact_nonempty_lines(
		"status command strict-yellow stderr",
		status_cmd_strict_yellow.stderr,
		status_strict_yellow_stderr_lines,
	)
	status_cmd_strict_yellow_prefixed_lines = extract_prefixed_lines(
		status_cmd_strict_yellow.stdout + status_cmd_strict_yellow.stderr, ("[parity-status]",)
	)
	if status_cmd_strict_yellow_prefixed_lines != status_strict_yellow_prefixed_lines:
		fail("status command strict-yellow prefixed stderr output mismatch with direct strict-yellow mode")
	status_cmd_strict_yellow_lines = extract_status_write_lines(status_cmd_strict_yellow.stdout + status_cmd_strict_yellow.stderr)
	if status_cmd_strict_yellow_lines != [expected_status_write_line]:
		fail("status command strict-yellow write-line output format mismatch")
	assert_exact_nonempty_lines("status command strict-yellow stdout", status_cmd_strict_yellow.stdout, [expected_status_write_line])
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
	assert_gate_success_contract("parity gate red", gate_red, "red", expected_gate_red_exit)

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
	assert_gate_success_contract("parity gate yellow", gate_yellow, "yellow", expected_gate_yellow_exit)
	gate_red_lines = extract_nonempty_lines(gate_red.stdout + gate_red.stderr)
	gate_yellow_lines = extract_nonempty_lines(gate_yellow.stdout + gate_yellow.stderr)
	gate_red_stdout_lines = extract_nonempty_lines(gate_red.stdout)
	gate_red_stderr_lines = extract_nonempty_lines(gate_red.stderr)
	gate_yellow_stdout_lines = extract_nonempty_lines(gate_yellow.stdout)
	gate_yellow_stderr_lines = extract_nonempty_lines(gate_yellow.stderr)
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
	expected_gate_usage_line = (
		"[parity-gate] Usage: bash scripts/run_ts_eslint_parity_gate.sh "
		"[--threshold red|yellow|--threshold=red|--threshold=yellow] [--skip-checks]"
	)
	expected_gate_missing_threshold_line = "[parity-gate] ERROR: --threshold requires a value (red|yellow)."
	expected_gate_invalid_threshold_line = "[parity-gate] ERROR: invalid threshold 'blue'. Expected red|yellow."
	expected_gate_duplicate_threshold_line = "[parity-gate] ERROR: duplicate --threshold argument."
	expected_gate_unknown_arg_line = "[parity-gate] ERROR: unknown argument: --not-a-real-flag"
	expected_gate_duplicate_skip_checks_line = "[parity-gate] ERROR: duplicate --skip-checks argument."

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
	if gate_help.stdout.strip():
		fail("parity gate --help stdout must be empty")
	assert_exact_nonempty_lines("parity gate --help stderr", gate_help.stderr, [expected_gate_usage_line])
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
	if gate_short_help.stdout.strip():
		fail("parity gate -h stdout must be empty")
	assert_exact_nonempty_lines("parity gate -h stderr", gate_short_help.stderr, [expected_gate_usage_line])
	gate_help_lines = extract_nonempty_lines(gate_help.stderr)
	if extract_nonempty_lines(gate_short_help.stderr) != gate_help_lines:
		fail("parity gate -h stderr output mismatch with --help")

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
	if expected_gate_invalid_threshold_line not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing exact error line")
	if usage_prefix not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing usage message")
	if usage_threshold_token not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_invalid_threshold.stderr:
		fail("parity gate invalid-threshold stderr missing skip-checks token in usage message")
	if gate_invalid_threshold.stdout.strip():
		fail("parity gate invalid-threshold stdout must be empty")
	assert_line_occurs_once("parity gate invalid-threshold stderr", gate_invalid_threshold.stderr, expected_gate_usage_line)
	assert_exact_error_plus_usage(
		"parity gate invalid-threshold stderr",
		gate_invalid_threshold.stderr,
		expected_gate_invalid_threshold_line,
		expected_gate_usage_line,
	)
	gate_invalid_threshold_lines = extract_nonempty_lines(gate_invalid_threshold.stderr)

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
	if expected_gate_invalid_threshold_line not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing exact error line")
	if usage_prefix not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing usage message")
	if usage_threshold_token not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_invalid_inline_threshold.stderr:
		fail("parity gate invalid-inline-threshold stderr missing skip-checks token in usage message")
	if gate_invalid_inline_threshold.stdout.strip():
		fail("parity gate invalid-inline-threshold stdout must be empty")
	assert_line_occurs_once(
		"parity gate invalid-inline-threshold stderr", gate_invalid_inline_threshold.stderr, expected_gate_usage_line
	)
	assert_exact_error_plus_usage(
		"parity gate invalid-inline-threshold stderr",
		gate_invalid_inline_threshold.stderr,
		expected_gate_invalid_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_invalid_inline_threshold.stderr) != gate_invalid_threshold_lines:
		fail("parity gate invalid-inline-threshold stderr mismatch with invalid-threshold stderr")

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
	if expected_gate_missing_threshold_line not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing exact error line")
	if usage_prefix not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing usage message")
	if usage_threshold_token not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_missing_threshold_value.stderr:
		fail("parity gate missing-threshold-value stderr missing skip-checks token in usage message")
	if gate_missing_threshold_value.stdout.strip():
		fail("parity gate missing-threshold-value stdout must be empty")
	assert_line_occurs_once(
		"parity gate missing-threshold-value stderr", gate_missing_threshold_value.stderr, expected_gate_usage_line
	)
	assert_exact_error_plus_usage(
		"parity gate missing-threshold-value stderr",
		gate_missing_threshold_value.stderr,
		expected_gate_missing_threshold_line,
		expected_gate_usage_line,
	)
	gate_missing_threshold_lines = extract_nonempty_lines(gate_missing_threshold_value.stderr)

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
	if expected_gate_missing_threshold_line not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing exact error line")
	if usage_prefix not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing usage message")
	if usage_threshold_token not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_missing_inline_threshold_value.stderr:
		fail("parity gate missing-inline-threshold-value stderr missing skip-checks token in usage message")
	if gate_missing_inline_threshold_value.stdout.strip():
		fail("parity gate missing-inline-threshold-value stdout must be empty")
	assert_line_occurs_once(
		"parity gate missing-inline-threshold-value stderr",
		gate_missing_inline_threshold_value.stderr,
		expected_gate_usage_line,
	)
	assert_exact_error_plus_usage(
		"parity gate missing-inline-threshold-value stderr",
		gate_missing_inline_threshold_value.stderr,
		expected_gate_missing_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_missing_inline_threshold_value.stderr) != gate_missing_threshold_lines:
		fail("parity gate missing-inline-threshold-value stderr mismatch with missing-threshold-value stderr")

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
	if expected_gate_duplicate_threshold_line not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing exact error line")
	if usage_prefix not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_threshold.stderr:
		fail("parity gate duplicate-threshold stderr missing skip-checks token in usage message")
	if gate_duplicate_threshold.stdout.strip():
		fail("parity gate duplicate-threshold stdout must be empty")
	assert_line_occurs_once("parity gate duplicate-threshold stderr", gate_duplicate_threshold.stderr, expected_gate_usage_line)
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold stderr",
		gate_duplicate_threshold.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	gate_duplicate_threshold_lines = extract_nonempty_lines(gate_duplicate_threshold.stderr)

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
	if expected_gate_duplicate_threshold_line not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing exact error line")
	if usage_prefix not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_threshold_spaced.stderr:
		fail("parity gate duplicate-threshold-spaced stderr missing skip-checks token in usage message")
	if gate_duplicate_threshold_spaced.stdout.strip():
		fail("parity gate duplicate-threshold-spaced stdout must be empty")
	assert_line_occurs_once(
		"parity gate duplicate-threshold-spaced stderr", gate_duplicate_threshold_spaced.stderr, expected_gate_usage_line
	)
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-spaced stderr",
		gate_duplicate_threshold_spaced.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_spaced.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-spaced stderr mismatch with duplicate-threshold stderr")

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
	if expected_gate_duplicate_threshold_line not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing exact error line")
	if usage_prefix not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_threshold_inline.stderr:
		fail("parity gate duplicate-threshold-inline stderr missing skip-checks token in usage message")
	if gate_duplicate_threshold_inline.stdout.strip():
		fail("parity gate duplicate-threshold-inline stdout must be empty")
	assert_line_occurs_once(
		"parity gate duplicate-threshold-inline stderr", gate_duplicate_threshold_inline.stderr, expected_gate_usage_line
	)
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-inline stderr",
		gate_duplicate_threshold_inline.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_inline.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-inline stderr mismatch with duplicate-threshold stderr")
	gate_duplicate_threshold_invalid_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--threshold",
			"blue",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_invalid_spaced.returncode != 1:
		fail("parity gate duplicate-threshold-invalid-spaced exit code must be 1")
	if gate_duplicate_threshold_invalid_spaced.stdout.strip():
		fail("parity gate duplicate-threshold-invalid-spaced stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-invalid-spaced stderr",
		gate_duplicate_threshold_invalid_spaced.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_invalid_spaced.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-invalid-spaced stderr mismatch with duplicate-threshold stderr")

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
	assert_gate_success_contract("parity gate inline red", gate_inline_red, "red", expected_gate_red_exit)
	if "[parity-gate] Running strict clean parity checks" in (gate_inline_red.stdout + gate_inline_red.stderr):
		fail("parity gate inline red should not run strict clean checks in --skip-checks mode")
	assert_exact_nonempty_lines("parity gate inline red combined output", gate_inline_red.stdout + gate_inline_red.stderr, gate_red_lines)
	assert_exact_nonempty_lines("parity gate inline red stdout", gate_inline_red.stdout, gate_red_stdout_lines)
	assert_exact_nonempty_lines("parity gate inline red stderr", gate_inline_red.stderr, gate_red_stderr_lines)
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
	assert_gate_success_contract("parity gate inline yellow", gate_inline_yellow, "yellow", expected_gate_yellow_exit)
	if "[parity-gate] Running strict clean parity checks" in (gate_inline_yellow.stdout + gate_inline_yellow.stderr):
		fail("parity gate inline yellow should not run strict clean checks in --skip-checks mode")
	assert_exact_nonempty_lines(
		"parity gate inline yellow combined output",
		gate_inline_yellow.stdout + gate_inline_yellow.stderr,
		gate_yellow_lines,
	)
	assert_exact_nonempty_lines("parity gate inline yellow stdout", gate_inline_yellow.stdout, gate_yellow_stdout_lines)
	assert_exact_nonempty_lines("parity gate inline yellow stderr", gate_inline_yellow.stderr, gate_yellow_stderr_lines)
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
	assert_gate_success_contract(
		"parity gate skip-only default-red", gate_skip_only_default_red, "red", expected_gate_red_exit
	)
	if "[parity-gate] Running strict clean parity checks" in (gate_skip_only_default_red.stdout + gate_skip_only_default_red.stderr):
		fail("parity gate skip-only default-red should not run strict clean checks in --skip-checks mode")
	assert_exact_nonempty_lines(
		"parity gate skip-only default-red combined output",
		gate_skip_only_default_red.stdout + gate_skip_only_default_red.stderr,
		gate_red_lines,
	)
	assert_exact_nonempty_lines("parity gate skip-only default-red stdout", gate_skip_only_default_red.stdout, gate_red_stdout_lines)
	assert_exact_nonempty_lines("parity gate skip-only default-red stderr", gate_skip_only_default_red.stderr, gate_red_stderr_lines)
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
	assert_gate_success_contract("parity gate reordered-flags", gate_reordered_flags, "yellow", expected_gate_yellow_exit)
	if "[parity-gate] Running strict clean parity checks" in (gate_reordered_flags.stdout + gate_reordered_flags.stderr):
		fail("parity gate reordered-flags should not run strict clean checks in --skip-checks mode")
	assert_exact_nonempty_lines(
		"parity gate reordered-flags combined output",
		gate_reordered_flags.stdout + gate_reordered_flags.stderr,
		gate_yellow_lines,
	)
	assert_exact_nonempty_lines("parity gate reordered-flags stdout", gate_reordered_flags.stdout, gate_yellow_stdout_lines)
	assert_exact_nonempty_lines("parity gate reordered-flags stderr", gate_reordered_flags.stderr, gate_yellow_stderr_lines)
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
	if expected_gate_unknown_arg_line not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing exact error line")
	if usage_prefix not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing usage message")
	if usage_threshold_token not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_unknown_arg.stderr:
		fail("parity gate unknown-arg stderr missing skip-checks token in usage message")
	if gate_unknown_arg.stdout.strip():
		fail("parity gate unknown-arg stdout must be empty")
	assert_line_occurs_once("parity gate unknown-arg stderr", gate_unknown_arg.stderr, expected_gate_usage_line)
	assert_exact_error_plus_usage(
		"parity gate unknown-arg stderr",
		gate_unknown_arg.stderr,
		expected_gate_unknown_arg_line,
		expected_gate_usage_line,
	)
	gate_unknown_arg_lines = extract_nonempty_lines(gate_unknown_arg.stderr)

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
	if expected_gate_duplicate_skip_checks_line not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing exact error line")
	if usage_prefix not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing usage message")
	if usage_threshold_token not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing threshold forms in usage message")
	if usage_skip_checks_token not in gate_duplicate_skip_checks.stderr:
		fail("parity gate duplicate-skip-checks stderr missing skip-checks token in usage message")
	if gate_duplicate_skip_checks.stdout.strip():
		fail("parity gate duplicate-skip-checks stdout must be empty")
	assert_line_occurs_once(
		"parity gate duplicate-skip-checks stderr", gate_duplicate_skip_checks.stderr, expected_gate_usage_line
	)
	assert_exact_error_plus_usage(
		"parity gate duplicate-skip-checks stderr",
		gate_duplicate_skip_checks.stderr,
		expected_gate_duplicate_skip_checks_line,
		expected_gate_usage_line,
	)
	gate_duplicate_skip_checks_lines = extract_nonempty_lines(gate_duplicate_skip_checks.stderr)

	gate_help_then_unknown = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--help",
			"--not-a-real-flag",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_help_then_unknown.returncode != 0:
		fail("parity gate help-then-unknown exit code must be 0")
	if gate_help_then_unknown.stdout.strip():
		fail("parity gate help-then-unknown stdout must be empty")
	assert_exact_nonempty_lines("parity gate help-then-unknown stderr", gate_help_then_unknown.stderr, [expected_gate_usage_line])
	if extract_nonempty_lines(gate_help_then_unknown.stderr) != gate_help_lines:
		fail("parity gate help-then-unknown stderr mismatch with help baseline")
	gate_short_help_then_unknown = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"-h",
			"--not-a-real-flag",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_short_help_then_unknown.returncode != 0:
		fail("parity gate short-help-then-unknown exit code must be 0")
	if gate_short_help_then_unknown.stdout.strip():
		fail("parity gate short-help-then-unknown stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate short-help-then-unknown stderr", gate_short_help_then_unknown.stderr, [expected_gate_usage_line]
	)
	if extract_nonempty_lines(gate_short_help_then_unknown.stderr) != gate_help_lines:
		fail("parity gate short-help-then-unknown stderr mismatch with help baseline")
	gate_help_then_duplicate_threshold = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--help",
			"--threshold=blue",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_help_then_duplicate_threshold.returncode != 0:
		fail("parity gate help-then-duplicate-threshold exit code must be 0")
	if gate_help_then_duplicate_threshold.stdout.strip():
		fail("parity gate help-then-duplicate-threshold stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate help-then-duplicate-threshold stderr", gate_help_then_duplicate_threshold.stderr, [expected_gate_usage_line]
	)
	if extract_nonempty_lines(gate_help_then_duplicate_threshold.stderr) != gate_help_lines:
		fail("parity gate help-then-duplicate-threshold stderr mismatch with help baseline")
	gate_help_then_duplicate_threshold_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--help",
			"--threshold",
			"blue",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_help_then_duplicate_threshold_spaced.returncode != 0:
		fail("parity gate help-then-duplicate-threshold-spaced exit code must be 0")
	if gate_help_then_duplicate_threshold_spaced.stdout.strip():
		fail("parity gate help-then-duplicate-threshold-spaced stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate help-then-duplicate-threshold-spaced stderr",
		gate_help_then_duplicate_threshold_spaced.stderr,
		[expected_gate_usage_line],
	)
	if extract_nonempty_lines(gate_help_then_duplicate_threshold_spaced.stderr) != gate_help_lines:
		fail("parity gate help-then-duplicate-threshold-spaced stderr mismatch with help baseline")
	gate_short_help_then_duplicate_threshold = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"-h",
			"--threshold=blue",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_short_help_then_duplicate_threshold.returncode != 0:
		fail("parity gate short-help-then-duplicate-threshold exit code must be 0")
	if gate_short_help_then_duplicate_threshold.stdout.strip():
		fail("parity gate short-help-then-duplicate-threshold stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate short-help-then-duplicate-threshold stderr",
		gate_short_help_then_duplicate_threshold.stderr,
		[expected_gate_usage_line],
	)
	if extract_nonempty_lines(gate_short_help_then_duplicate_threshold.stderr) != gate_help_lines:
		fail("parity gate short-help-then-duplicate-threshold stderr mismatch with help baseline")
	gate_short_help_then_duplicate_threshold_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"-h",
			"--threshold",
			"blue",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_short_help_then_duplicate_threshold_spaced.returncode != 0:
		fail("parity gate short-help-then-duplicate-threshold-spaced exit code must be 0")
	if gate_short_help_then_duplicate_threshold_spaced.stdout.strip():
		fail("parity gate short-help-then-duplicate-threshold-spaced stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate short-help-then-duplicate-threshold-spaced stderr",
		gate_short_help_then_duplicate_threshold_spaced.stderr,
		[expected_gate_usage_line],
	)
	if extract_nonempty_lines(gate_short_help_then_duplicate_threshold_spaced.stderr) != gate_help_lines:
		fail("parity gate short-help-then-duplicate-threshold-spaced stderr mismatch with help baseline")
	gate_help_then_duplicate_skip_checks = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--help",
			"--skip-checks",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_help_then_duplicate_skip_checks.returncode != 0:
		fail("parity gate help-then-duplicate-skip-checks exit code must be 0")
	if gate_help_then_duplicate_skip_checks.stdout.strip():
		fail("parity gate help-then-duplicate-skip-checks stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate help-then-duplicate-skip-checks stderr",
		gate_help_then_duplicate_skip_checks.stderr,
		[expected_gate_usage_line],
	)
	if extract_nonempty_lines(gate_help_then_duplicate_skip_checks.stderr) != gate_help_lines:
		fail("parity gate help-then-duplicate-skip-checks stderr mismatch with help baseline")
	gate_short_help_then_duplicate_skip_checks = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"-h",
			"--skip-checks",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_short_help_then_duplicate_skip_checks.returncode != 0:
		fail("parity gate short-help-then-duplicate-skip-checks exit code must be 0")
	if gate_short_help_then_duplicate_skip_checks.stdout.strip():
		fail("parity gate short-help-then-duplicate-skip-checks stdout must be empty")
	assert_exact_nonempty_lines(
		"parity gate short-help-then-duplicate-skip-checks stderr",
		gate_short_help_then_duplicate_skip_checks.stderr,
		[expected_gate_usage_line],
	)
	if extract_nonempty_lines(gate_short_help_then_duplicate_skip_checks.stderr) != gate_help_lines:
		fail("parity gate short-help-then-duplicate-skip-checks stderr mismatch with help baseline")
	gate_help_then_malformed_threshold_suffixes = [
		("missing-threshold", ["--threshold"]),
		("empty-threshold", ["--threshold="]),
		("missing-threshold with trailing skip-checks", ["--threshold", "--skip-checks"]),
		("invalid-threshold-inline", ["--threshold=blue"]),
		("invalid-threshold-spaced", ["--threshold", "blue"]),
		("invalid-threshold-inline with trailing skip-checks", ["--threshold=blue", "--skip-checks"]),
		("invalid-threshold-spaced with trailing skip-checks", ["--threshold", "blue", "--skip-checks"]),
	]
	for suffix_label, suffix_tokens in gate_help_then_malformed_threshold_suffixes:
		help_proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--help", *suffix_tokens],
			check=False,
			capture_output=True,
			text=True,
		)
		if help_proc.returncode != 0:
			fail(f"parity gate help-then-{suffix_label} exit code must be 0")
		if help_proc.stdout.strip():
			fail(f"parity gate help-then-{suffix_label} stdout must be empty")
		assert_exact_nonempty_lines(
			f"parity gate help-then-{suffix_label} stderr",
			help_proc.stderr,
			[expected_gate_usage_line],
		)
		if extract_nonempty_lines(help_proc.stderr) != gate_help_lines:
			fail(f"parity gate help-then-{suffix_label} stderr mismatch with help baseline")

		short_help_proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "-h", *suffix_tokens],
			check=False,
			capture_output=True,
			text=True,
		)
		if short_help_proc.returncode != 0:
			fail(f"parity gate short-help-then-{suffix_label} exit code must be 0")
		if short_help_proc.stdout.strip():
			fail(f"parity gate short-help-then-{suffix_label} stdout must be empty")
		assert_exact_nonempty_lines(
			f"parity gate short-help-then-{suffix_label} stderr",
			short_help_proc.stderr,
			[expected_gate_usage_line],
		)
		if extract_nonempty_lines(short_help_proc.stderr) != gate_help_lines:
			fail(f"parity gate short-help-then-{suffix_label} stderr mismatch with help baseline")

	gate_unknown_then_help = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--not-a-real-flag",
			"--help",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_unknown_then_help.returncode != 1:
		fail("parity gate unknown-then-help exit code must be 1")
	if gate_unknown_then_help.stdout.strip():
		fail("parity gate unknown-then-help stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate unknown-then-help stderr",
		gate_unknown_then_help.stderr,
		expected_gate_unknown_arg_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_unknown_then_help.stderr) != gate_unknown_arg_lines:
		fail("parity gate unknown-then-help stderr mismatch with unknown-arg baseline")
	gate_unknown_then_short_help = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--not-a-real-flag",
			"-h",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_unknown_then_short_help.returncode != 1:
		fail("parity gate unknown-then-short-help exit code must be 1")
	if gate_unknown_then_short_help.stdout.strip():
		fail("parity gate unknown-then-short-help stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate unknown-then-short-help stderr",
		gate_unknown_then_short_help.stderr,
		expected_gate_unknown_arg_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_unknown_then_short_help.stderr) != gate_unknown_arg_lines:
		fail("parity gate unknown-then-short-help stderr mismatch with unknown-arg baseline")
	for suffix_label, suffix_tokens in gate_help_then_malformed_threshold_suffixes:
		unknown_proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--not-a-real-flag", *suffix_tokens],
			check=False,
			capture_output=True,
			text=True,
		)
		if unknown_proc.returncode != 1:
			fail(f"parity gate unknown-then-{suffix_label} exit code must be 1")
		if unknown_proc.stdout.strip():
			fail(f"parity gate unknown-then-{suffix_label} stdout must be empty")
		assert_exact_error_plus_usage(
			f"parity gate unknown-then-{suffix_label} stderr",
			unknown_proc.stderr,
			expected_gate_unknown_arg_line,
			expected_gate_usage_line,
		)
		if extract_nonempty_lines(unknown_proc.stderr) != gate_unknown_arg_lines:
			fail(f"parity gate unknown-then-{suffix_label} stderr mismatch with unknown-arg baseline")
		for help_flag, help_flag_label in [("--help", "help"), ("-h", "short-help")]:
			unknown_then_help_proc = subprocess.run(
				["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), "--not-a-real-flag", *suffix_tokens, help_flag],
				check=False,
				capture_output=True,
				text=True,
			)
			if unknown_then_help_proc.returncode != 1:
				fail(f"parity gate unknown-then-{suffix_label}-then-{help_flag_label} exit code must be 1")
			if unknown_then_help_proc.stdout.strip():
				fail(f"parity gate unknown-then-{suffix_label}-then-{help_flag_label} stdout must be empty")
			assert_exact_error_plus_usage(
				f"parity gate unknown-then-{suffix_label}-then-{help_flag_label} stderr",
				unknown_then_help_proc.stderr,
				expected_gate_unknown_arg_line,
				expected_gate_usage_line,
			)
			if extract_nonempty_lines(unknown_then_help_proc.stderr) != gate_unknown_arg_lines:
				fail(f"parity gate unknown-then-{suffix_label}-then-{help_flag_label} stderr mismatch with unknown-arg baseline")

	gate_duplicate_threshold_then_help = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--threshold=blue",
			"--help",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_then_help.returncode != 1:
		fail("parity gate duplicate-threshold-then-help exit code must be 1")
	if gate_duplicate_threshold_then_help.stdout.strip():
		fail("parity gate duplicate-threshold-then-help stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-then-help stderr",
		gate_duplicate_threshold_then_help.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_then_help.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-then-help stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_threshold_then_help_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--threshold",
			"blue",
			"--help",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_then_help_spaced.returncode != 1:
		fail("parity gate duplicate-threshold-then-help-spaced exit code must be 1")
	if gate_duplicate_threshold_then_help_spaced.stdout.strip():
		fail("parity gate duplicate-threshold-then-help-spaced stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-then-help-spaced stderr",
		gate_duplicate_threshold_then_help_spaced.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_then_help_spaced.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-then-help-spaced stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_threshold_then_short_help = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--threshold=blue",
			"-h",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_then_short_help.returncode != 1:
		fail("parity gate duplicate-threshold-then-short-help exit code must be 1")
	if gate_duplicate_threshold_then_short_help.stdout.strip():
		fail("parity gate duplicate-threshold-then-short-help stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-then-short-help stderr",
		gate_duplicate_threshold_then_short_help.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_then_short_help.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-then-short-help stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_threshold_then_short_help_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--threshold",
			"blue",
			"-h",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_then_short_help_spaced.returncode != 1:
		fail("parity gate duplicate-threshold-then-short-help-spaced exit code must be 1")
	if gate_duplicate_threshold_then_short_help_spaced.stdout.strip():
		fail("parity gate duplicate-threshold-then-short-help-spaced stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-then-short-help-spaced stderr",
		gate_duplicate_threshold_then_short_help_spaced.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_then_short_help_spaced.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-then-short-help-spaced stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_threshold_then_malformed_then_help_cases = [
		(
			"parity gate duplicate-threshold-then-missing-threshold-then-help",
			["--threshold=red", "--threshold", "--help"],
		),
		(
			"parity gate duplicate-threshold-then-empty-threshold-then-help",
			["--threshold=red", "--threshold=", "--help"],
		),
		(
			"parity gate duplicate-threshold-then-missing-threshold-then-short-help",
			["--threshold=red", "--threshold", "-h"],
		),
		(
			"parity gate duplicate-threshold-then-empty-threshold-then-short-help",
			["--threshold=red", "--threshold=", "-h"],
		),
	]
	for label, extra_args in gate_duplicate_threshold_then_malformed_then_help_cases:
		proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), *extra_args],
			check=False,
			capture_output=True,
			text=True,
		)
		if proc.returncode != 1:
			fail(f"{label} exit code must be 1")
		if proc.stdout.strip():
			fail(f"{label} stdout must be empty")
		assert_exact_error_plus_usage(
			f"{label} stderr",
			proc.stderr,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		if extract_nonempty_lines(proc.stderr) != gate_duplicate_threshold_lines:
			fail(f"{label} stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_threshold_then_malformed_then_unknown_cases = [
		(
			"parity gate duplicate-threshold-then-missing-threshold-then-unknown",
			["--threshold=red", "--threshold", "--not-a-real-flag"],
		),
		(
			"parity gate duplicate-threshold-then-empty-threshold-then-unknown",
			["--threshold=red", "--threshold=", "--not-a-real-flag"],
		),
		(
			"parity gate duplicate-threshold-then-invalid-threshold-inline-then-unknown",
			["--threshold=red", "--threshold=blue", "--not-a-real-flag"],
		),
		(
			"parity gate duplicate-threshold-then-invalid-threshold-spaced-then-unknown",
			["--threshold=red", "--threshold", "blue", "--not-a-real-flag"],
		),
	]
	for label, extra_args in gate_duplicate_threshold_then_malformed_then_unknown_cases:
		proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), *extra_args],
			check=False,
			capture_output=True,
			text=True,
		)
		if proc.returncode != 1:
			fail(f"{label} exit code must be 1")
		if proc.stdout.strip():
			fail(f"{label} stdout must be empty")
		assert_exact_error_plus_usage(
			f"{label} stderr",
			proc.stderr,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		if extract_nonempty_lines(proc.stderr) != gate_duplicate_threshold_lines:
			fail(f"{label} stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_skip_checks_then_help = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--skip-checks",
			"--skip-checks",
			"--help",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_skip_checks_then_help.returncode != 1:
		fail("parity gate duplicate-skip-checks-then-help exit code must be 1")
	if gate_duplicate_skip_checks_then_help.stdout.strip():
		fail("parity gate duplicate-skip-checks-then-help stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-skip-checks-then-help stderr",
		gate_duplicate_skip_checks_then_help.stderr,
		expected_gate_duplicate_skip_checks_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_skip_checks_then_help.stderr) != gate_duplicate_skip_checks_lines:
		fail("parity gate duplicate-skip-checks-then-help stderr mismatch with duplicate-skip-checks baseline")
	gate_duplicate_skip_checks_then_short_help = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--skip-checks",
			"--skip-checks",
			"-h",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_skip_checks_then_short_help.returncode != 1:
		fail("parity gate duplicate-skip-checks-then-short-help exit code must be 1")
	if gate_duplicate_skip_checks_then_short_help.stdout.strip():
		fail("parity gate duplicate-skip-checks-then-short-help stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-skip-checks-then-short-help stderr",
		gate_duplicate_skip_checks_then_short_help.stderr,
		expected_gate_duplicate_skip_checks_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_skip_checks_then_short_help.stderr) != gate_duplicate_skip_checks_lines:
		fail("parity gate duplicate-skip-checks-then-short-help stderr mismatch with duplicate-skip-checks baseline")
	gate_duplicate_skip_then_malformed_threshold_cases = [
		(
			"parity gate duplicate-skip-checks-then-missing-threshold",
			["--skip-checks", "--skip-checks", "--threshold"],
		),
		(
			"parity gate duplicate-skip-checks-then-empty-threshold",
			["--skip-checks", "--skip-checks", "--threshold="],
		),
		(
			"parity gate duplicate-skip-checks-then-invalid-threshold-inline",
			["--skip-checks", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate duplicate-skip-checks-then-invalid-threshold-spaced",
			["--skip-checks", "--skip-checks", "--threshold", "blue"],
		),
	]
	for label, extra_args in gate_duplicate_skip_then_malformed_threshold_cases:
		proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), *extra_args],
			check=False,
			capture_output=True,
			text=True,
		)
		if proc.returncode != 1:
			fail(f"{label} exit code must be 1")
		if proc.stdout.strip():
			fail(f"{label} stdout must be empty")
		assert_exact_error_plus_usage(
			f"{label} stderr",
			proc.stderr,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		if extract_nonempty_lines(proc.stderr) != gate_duplicate_skip_checks_lines:
			fail(f"{label} stderr mismatch with duplicate-skip-checks baseline")
		for help_flag, help_label in [("--help", "help"), ("-h", "short-help")]:
			proc_with_help = subprocess.run(
				["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), *extra_args, help_flag],
				check=False,
				capture_output=True,
				text=True,
			)
			if proc_with_help.returncode != 1:
				fail(f"{label} then {help_label} exit code must be 1")
			if proc_with_help.stdout.strip():
				fail(f"{label} then {help_label} stdout must be empty")
			assert_exact_error_plus_usage(
				f"{label} then {help_label} stderr",
				proc_with_help.stderr,
				expected_gate_duplicate_skip_checks_line,
				expected_gate_usage_line,
			)
			if extract_nonempty_lines(proc_with_help.stderr) != gate_duplicate_skip_checks_lines:
				fail(f"{label} then {help_label} stderr mismatch with duplicate-skip-checks baseline")
		proc_with_unknown = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), *extra_args, "--not-a-real-flag"],
			check=False,
			capture_output=True,
			text=True,
		)
		if proc_with_unknown.returncode != 1:
			fail(f"{label} then unknown exit code must be 1")
		if proc_with_unknown.stdout.strip():
			fail(f"{label} then unknown stdout must be empty")
		assert_exact_error_plus_usage(
			f"{label} then unknown stderr",
			proc_with_unknown.stderr,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		if extract_nonempty_lines(proc_with_unknown.stderr) != gate_duplicate_skip_checks_lines:
			fail(f"{label} then unknown stderr mismatch with duplicate-skip-checks baseline")

	gate_unknown_precedence_cases = [
		(
			"parity gate unknown-arg precedence leading-unknown",
			["--not-a-real-flag", "--threshold=red", "--skip-checks"],
		),
		(
			"parity gate unknown-arg precedence leading-unknown spaced-threshold",
			["--not-a-real-flag", "--threshold", "red", "--skip-checks"],
		),
		(
			"parity gate unknown-arg precedence after-valid-threshold",
			["--threshold=red", "--not-a-real-flag", "--skip-checks"],
		),
		(
			"parity gate unknown-arg precedence after-valid-threshold spaced",
			["--threshold", "red", "--not-a-real-flag", "--skip-checks"],
		),
		(
			"parity gate unknown-arg precedence after-valid-skip",
			["--skip-checks", "--not-a-real-flag", "--threshold=red"],
		),
		(
			"parity gate unknown-arg precedence after-valid-skip spaced-threshold",
			["--skip-checks", "--not-a-real-flag", "--threshold", "red"],
		),
	]
	for label, extra_args in gate_unknown_precedence_cases:
		proc = subprocess.run(
			["bash", str(root / "scripts/run_ts_eslint_parity_gate.sh"), *extra_args],
			check=False,
			capture_output=True,
			text=True,
		)
		if proc.returncode != 1:
			fail(f"{label} exit code must be 1")
		if proc.stdout.strip():
			fail(f"{label} stdout must be empty")
		assert_exact_error_plus_usage(
			f"{label} stderr",
			proc.stderr,
			expected_gate_unknown_arg_line,
			expected_gate_usage_line,
		)
		if extract_nonempty_lines(proc.stderr) != gate_unknown_arg_lines:
			fail(f"{label} stderr mismatch with unknown-arg baseline")

	gate_duplicate_threshold_then_unknown = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--threshold=blue",
			"--not-a-real-flag",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_then_unknown.returncode != 1:
		fail("parity gate duplicate-threshold-then-unknown exit code must be 1")
	if gate_duplicate_threshold_then_unknown.stdout.strip():
		fail("parity gate duplicate-threshold-then-unknown stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-then-unknown stderr",
		gate_duplicate_threshold_then_unknown.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_then_unknown.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-then-unknown stderr mismatch with duplicate-threshold baseline")
	gate_duplicate_threshold_then_unknown_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--threshold",
			"blue",
			"--not-a-real-flag",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_threshold_then_unknown_spaced.returncode != gate_duplicate_threshold_then_unknown.returncode:
		fail("parity gate duplicate-threshold-then-unknown spaced exit code mismatch with inline form")
	if gate_duplicate_threshold_then_unknown_spaced.stdout.strip():
		fail("parity gate duplicate-threshold-then-unknown spaced stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-threshold-then-unknown spaced stderr",
		gate_duplicate_threshold_then_unknown_spaced.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_threshold_then_unknown_spaced.stderr) != gate_duplicate_threshold_lines:
		fail("parity gate duplicate-threshold-then-unknown spaced stderr mismatch with duplicate-threshold baseline")

	gate_duplicate_skip_then_unknown = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--skip-checks",
			"--skip-checks",
			"--not-a-real-flag",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_duplicate_skip_then_unknown.returncode != 1:
		fail("parity gate duplicate-skip-checks-then-unknown exit code must be 1")
	if gate_duplicate_skip_then_unknown.stdout.strip():
		fail("parity gate duplicate-skip-checks-then-unknown stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate duplicate-skip-checks-then-unknown stderr",
		gate_duplicate_skip_then_unknown.stderr,
		expected_gate_duplicate_skip_checks_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_duplicate_skip_then_unknown.stderr) != gate_duplicate_skip_checks_lines:
		fail("parity gate duplicate-skip-checks-then-unknown stderr mismatch with duplicate-skip-checks baseline")

	# Direct gate conflict-order precedence checks
	gate_conflict_threshold_first = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold=red",
			"--skip-checks",
			"--threshold=blue",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_conflict_threshold_first.returncode != 1:
		fail("parity gate conflict threshold-first exit code must be 1")
	if gate_conflict_threshold_first.stdout.strip():
		fail("parity gate conflict threshold-first stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate conflict threshold-first stderr",
		gate_conflict_threshold_first.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	gate_conflict_threshold_first_lines = extract_nonempty_lines(gate_conflict_threshold_first.stderr)
	if gate_conflict_threshold_first_lines != gate_duplicate_threshold_lines:
		fail("parity gate conflict threshold-first stderr mismatch with duplicate-threshold baseline")
	gate_conflict_threshold_first_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--threshold",
			"red",
			"--skip-checks",
			"--threshold",
			"blue",
			"--skip-checks",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_conflict_threshold_first_spaced.returncode != gate_conflict_threshold_first.returncode:
		fail("parity gate conflict threshold-first spaced exit code mismatch with inline form")
	if gate_conflict_threshold_first_spaced.stdout.strip():
		fail("parity gate conflict threshold-first spaced stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate conflict threshold-first spaced stderr",
		gate_conflict_threshold_first_spaced.stderr,
		expected_gate_duplicate_threshold_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_conflict_threshold_first_spaced.stderr) != gate_conflict_threshold_first_lines:
		fail("parity gate conflict threshold-first spaced stderr mismatch with inline form")

	gate_conflict_skip_first = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--skip-checks",
			"--threshold=red",
			"--skip-checks",
			"--threshold=blue",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_conflict_skip_first.returncode != 1:
		fail("parity gate conflict skip-first exit code must be 1")
	if gate_conflict_skip_first.stdout.strip():
		fail("parity gate conflict skip-first stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate conflict skip-first stderr",
		gate_conflict_skip_first.stderr,
		expected_gate_duplicate_skip_checks_line,
		expected_gate_usage_line,
	)
	gate_conflict_skip_first_lines = extract_nonempty_lines(gate_conflict_skip_first.stderr)
	if gate_conflict_skip_first_lines != gate_duplicate_skip_checks_lines:
		fail("parity gate conflict skip-first stderr mismatch with duplicate-skip-checks baseline")
	gate_conflict_skip_first_spaced = subprocess.run(
		[
			"bash",
			str(root / "scripts/run_ts_eslint_parity_gate.sh"),
			"--skip-checks",
			"--threshold",
			"red",
			"--skip-checks",
			"--threshold",
			"blue",
		],
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_conflict_skip_first_spaced.returncode != gate_conflict_skip_first.returncode:
		fail("parity gate conflict skip-first spaced exit code mismatch with inline form")
	if gate_conflict_skip_first_spaced.stdout.strip():
		fail("parity gate conflict skip-first spaced stdout must be empty")
	assert_exact_error_plus_usage(
		"parity gate conflict skip-first spaced stderr",
		gate_conflict_skip_first_spaced.stderr,
		expected_gate_duplicate_skip_checks_line,
		expected_gate_usage_line,
	)
	if extract_nonempty_lines(gate_conflict_skip_first_spaced.stderr) != gate_conflict_skip_first_lines:
		fail("parity gate conflict skip-first spaced stderr mismatch with inline form")

	# Gate npm wrapper help/unknown-arg forwarding checks
	gate_wrapper_help_cases = [
		("parity gate command --help", ["pnpm", "--silent", "parity:ts-eslint:gate", "--help"]),
		("parity gate command red --help", ["pnpm", "--silent", "parity:ts-eslint:gate:red", "--help"]),
		("parity gate command yellow --help", ["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--help"]),
		("parity gate quick command --help", ["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--help"]),
		(
			"parity gate quick command red --help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--help"],
		),
		(
			"parity gate quick command yellow --help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--help"],
		),
	]
	gate_wrapper_help_lines: dict[str, list[str]] = {}
	gate_wrapper_help_codes: dict[str, int] = {}
	for label, command in gate_wrapper_help_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		gate_wrapper_help_lines[label] = assert_gate_wrapper_help_contract(label, proc, expected_gate_usage_line)
		gate_wrapper_help_codes[label] = proc.returncode
	if gate_wrapper_help_codes["parity gate command --help"] != gate_wrapper_help_codes["parity gate command red --help"]:
		fail("parity gate command help alias return code mismatch with gate:red")
	if gate_wrapper_help_lines["parity gate command --help"] != gate_wrapper_help_lines["parity gate command red --help"]:
		fail("parity gate command help alias stderr mismatch with gate:red")
	if (
		gate_wrapper_help_codes["parity gate quick command --help"]
		!= gate_wrapper_help_codes["parity gate quick command red --help"]
	):
		fail("parity gate quick help alias return code mismatch with quick:red")
	if gate_wrapper_help_lines["parity gate quick command --help"] != gate_wrapper_help_lines[
		"parity gate quick command red --help"
	]:
		fail("parity gate quick help alias stderr mismatch with quick:red")
	gate_wrapper_help_baseline = gate_wrapper_help_lines["parity gate command --help"]
	if gate_wrapper_help_baseline != gate_help_lines:
		fail("parity gate wrapper help baseline mismatch with direct --help stderr")
	for label, lines in gate_wrapper_help_lines.items():
		if lines != gate_wrapper_help_baseline:
			fail(f"{label} stderr output mismatch with gate wrapper help baseline")
	gate_wrapper_short_help_cases = [
		("parity gate command -h", ["pnpm", "--silent", "parity:ts-eslint:gate", "-h"], "parity gate command --help"),
		(
			"parity gate command red -h",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "-h"],
			"parity gate command red --help",
		),
		(
			"parity gate command yellow -h",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "-h"],
			"parity gate command yellow --help",
		),
		(
			"parity gate quick command -h",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "-h"],
			"parity gate quick command --help",
		),
		(
			"parity gate quick command red -h",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "-h"],
			"parity gate quick command red --help",
		),
		(
			"parity gate quick command yellow -h",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "-h"],
			"parity gate quick command yellow --help",
		),
	]
	for label, command, help_label in gate_wrapper_short_help_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		short_help_lines = assert_gate_wrapper_help_contract(label, proc, expected_gate_usage_line)
		if proc.returncode != gate_wrapper_help_codes[help_label]:
			fail(f"{label} return code mismatch with {help_label}")
		if short_help_lines != gate_wrapper_help_lines[help_label]:
			fail(f"{label} stderr output mismatch with {help_label}")

	gate_wrapper_unknown_arg_cases = [
		(
			"parity gate command unknown-arg",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--not-a-real-flag"],
		),
		(
			"parity gate command red unknown-arg",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--not-a-real-flag"],
		),
		(
			"parity gate command yellow unknown-arg",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--not-a-real-flag"],
		),
		(
			"parity gate quick command unknown-arg",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--not-a-real-flag"],
		),
		(
			"parity gate quick command red unknown-arg",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--not-a-real-flag"],
		),
		(
			"parity gate quick command yellow unknown-arg",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--not-a-real-flag"],
		),
	]
	gate_wrapper_unknown_arg_lines: dict[str, list[str]] = {}
	gate_wrapper_unknown_arg_codes: dict[str, int] = {}
	for label, command in gate_wrapper_unknown_arg_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		gate_wrapper_unknown_arg_lines[label] = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_unknown_arg_line,
			expected_gate_usage_line,
		)
		gate_wrapper_unknown_arg_codes[label] = proc.returncode
	if gate_wrapper_unknown_arg_codes["parity gate command unknown-arg"] != gate_wrapper_unknown_arg_codes[
		"parity gate command red unknown-arg"
	]:
		fail("parity gate command unknown-arg alias return code mismatch with gate:red")
	if gate_wrapper_unknown_arg_lines["parity gate command unknown-arg"] != gate_wrapper_unknown_arg_lines[
		"parity gate command red unknown-arg"
	]:
		fail("parity gate command unknown-arg alias stderr mismatch with gate:red")
	if gate_wrapper_unknown_arg_codes["parity gate quick command unknown-arg"] != gate_wrapper_unknown_arg_codes[
		"parity gate quick command red unknown-arg"
	]:
		fail("parity gate quick unknown-arg alias return code mismatch with quick:red")
	if gate_wrapper_unknown_arg_lines["parity gate quick command unknown-arg"] != gate_wrapper_unknown_arg_lines[
		"parity gate quick command red unknown-arg"
	]:
		fail("parity gate quick unknown-arg alias stderr mismatch with quick:red")
	gate_wrapper_unknown_arg_baseline = gate_wrapper_unknown_arg_lines["parity gate command unknown-arg"]
	if gate_wrapper_unknown_arg_baseline != gate_unknown_arg_lines:
		fail("parity gate wrapper unknown-arg baseline mismatch with direct unknown-arg stderr")
	for label, lines in gate_wrapper_unknown_arg_lines.items():
		if lines != gate_wrapper_unknown_arg_baseline:
			fail(f"{label} stderr output mismatch with gate wrapper unknown-arg baseline")
	gate_wrapper_unknown_arg_precedence_cases = [
		(
			"parity gate command unknown-arg precedence trailing-duplicates",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--not-a-real-flag", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate command red unknown-arg precedence trailing-duplicates",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--not-a-real-flag", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate command yellow unknown-arg precedence trailing-duplicates",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--not-a-real-flag", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate quick command unknown-arg precedence trailing-duplicates",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--not-a-real-flag", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick command red unknown-arg precedence trailing-duplicates",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--not-a-real-flag", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick command yellow unknown-arg precedence trailing-duplicates",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--not-a-real-flag", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick command unknown-arg precedence trailing-duplicates spaced-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--not-a-real-flag", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate quick command red unknown-arg precedence trailing-duplicates spaced-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--not-a-real-flag", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate quick command yellow unknown-arg precedence trailing-duplicates spaced-threshold",
			[
				"pnpm",
				"--silent",
				"parity:ts-eslint:gate:quick:yellow",
				"--not-a-real-flag",
				"--threshold",
				"blue",
				"--skip-checks",
			],
		),
	]
	for label, command in gate_wrapper_unknown_arg_precedence_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		precedence_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_unknown_arg_line,
			expected_gate_usage_line,
		)
		if precedence_lines != gate_wrapper_unknown_arg_baseline:
			fail(f"{label} stderr output mismatch with unknown-arg precedence baseline")
	gate_wrapper_help_vs_unknown_precedence_cases = [
		(
			"parity gate command help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--help", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate command red help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--help", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate command yellow help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--help", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate quick command help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--help", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate quick command red help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--help", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate quick command yellow help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--help", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate command short-help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate", "-h", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate command red short-help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "-h", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate command yellow short-help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "-h", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate quick command short-help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "-h", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate quick command red short-help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "-h", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate quick command yellow short-help-then-unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "-h", "--not-a-real-flag"],
			"help",
		),
		(
			"parity gate command help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--help", "--threshold=blue"],
			"help",
		),
		(
			"parity gate command red help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--help", "--threshold=blue"],
			"help",
		),
		(
			"parity gate command yellow help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--help", "--threshold=blue"],
			"help",
		),
		(
			"parity gate quick command help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--help", "--threshold=blue"],
			"help",
		),
		(
			"parity gate quick command red help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--help", "--threshold=blue"],
			"help",
		),
		(
			"parity gate quick command yellow help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--help", "--threshold=blue"],
			"help",
		),
		(
			"parity gate command help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--help", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate command red help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--help", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate command yellow help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--help", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate quick command help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--help", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate quick command red help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--help", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate quick command yellow help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--help", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate command short-help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate", "-h", "--threshold=blue"],
			"help",
		),
		(
			"parity gate command red short-help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "-h", "--threshold=blue"],
			"help",
		),
		(
			"parity gate command yellow short-help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "-h", "--threshold=blue"],
			"help",
		),
		(
			"parity gate quick command short-help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "-h", "--threshold=blue"],
			"help",
		),
		(
			"parity gate quick command red short-help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "-h", "--threshold=blue"],
			"help",
		),
		(
			"parity gate quick command yellow short-help-then-duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "-h", "--threshold=blue"],
			"help",
		),
		(
			"parity gate command short-help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "-h", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate command red short-help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "-h", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate command yellow short-help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "-h", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate quick command short-help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "-h", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate quick command red short-help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "-h", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate quick command yellow short-help-then-duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "-h", "--threshold", "blue"],
			"help",
		),
		(
			"parity gate command help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--help", "--skip-checks", "--skip-checks"],
			"help",
		),
		(
			"parity gate command red help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--help", "--skip-checks", "--skip-checks"],
			"help",
		),
		(
			"parity gate command yellow help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--help", "--skip-checks", "--skip-checks"],
			"help",
		),
		(
			"parity gate quick command help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--help", "--skip-checks"],
			"help",
		),
		(
			"parity gate quick command red help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--help", "--skip-checks"],
			"help",
		),
		(
			"parity gate quick command yellow help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--help", "--skip-checks"],
			"help",
		),
		(
			"parity gate command short-help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "-h", "--skip-checks", "--skip-checks"],
			"help",
		),
		(
			"parity gate command red short-help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "-h", "--skip-checks", "--skip-checks"],
			"help",
		),
		(
			"parity gate command yellow short-help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "-h", "--skip-checks", "--skip-checks"],
			"help",
		),
		(
			"parity gate quick command short-help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "-h", "--skip-checks"],
			"help",
		),
		(
			"parity gate quick command red short-help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "-h", "--skip-checks"],
			"help",
		),
		(
			"parity gate quick command yellow short-help-then-duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "-h", "--skip-checks"],
			"help",
		),
		(
			"parity gate command unknown-then-help",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--not-a-real-flag", "--help"],
			"unknown",
		),
		(
			"parity gate command red unknown-then-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--not-a-real-flag", "--help"],
			"unknown",
		),
		(
			"parity gate command yellow unknown-then-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--not-a-real-flag", "--help"],
			"unknown",
		),
		(
			"parity gate quick command unknown-then-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--not-a-real-flag", "--help"],
			"unknown",
		),
		(
			"parity gate quick command red unknown-then-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--not-a-real-flag", "--help"],
			"unknown",
		),
		(
			"parity gate quick command yellow unknown-then-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--not-a-real-flag", "--help"],
			"unknown",
		),
		(
			"parity gate command unknown-then-short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--not-a-real-flag", "-h"],
			"unknown",
		),
		(
			"parity gate command red unknown-then-short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--not-a-real-flag", "-h"],
			"unknown",
		),
		(
			"parity gate command yellow unknown-then-short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--not-a-real-flag", "-h"],
			"unknown",
		),
		(
			"parity gate quick command unknown-then-short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--not-a-real-flag", "-h"],
			"unknown",
		),
		(
			"parity gate quick command red unknown-then-short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--not-a-real-flag", "-h"],
			"unknown",
		),
		(
			"parity gate quick command yellow unknown-then-short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--not-a-real-flag", "-h"],
			"unknown",
		),
	]
	for label, command, mode in gate_wrapper_help_vs_unknown_precedence_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		if mode == "help":
			lines = assert_gate_wrapper_help_contract(label, proc, expected_gate_usage_line)
			if lines != gate_wrapper_help_baseline:
				fail(f"{label} stderr output mismatch with help precedence baseline")
		else:
			lines = assert_gate_wrapper_unknown_arg_contract(
				label,
				proc,
				expected_gate_unknown_arg_line,
				expected_gate_usage_line,
			)
			if lines != gate_wrapper_unknown_arg_baseline:
				fail(f"{label} stderr output mismatch with unknown precedence baseline")
	gate_wrapper_help_then_malformed_suffixes = [
		("missing-threshold", ["--threshold"]),
		("empty-threshold", ["--threshold="]),
		("missing-threshold with trailing skip-checks", ["--threshold", "--skip-checks"]),
		("invalid-threshold-inline", ["--threshold=blue"]),
		("invalid-threshold-spaced", ["--threshold", "blue"]),
		("invalid-threshold-inline with trailing skip-checks", ["--threshold=blue", "--skip-checks"]),
		("invalid-threshold-spaced with trailing skip-checks", ["--threshold", "blue", "--skip-checks"]),
	]
	gate_wrapper_help_base_commands = [
		("parity gate command", ["pnpm", "--silent", "parity:ts-eslint:gate"]),
		("parity gate command red", ["pnpm", "--silent", "parity:ts-eslint:gate:red"]),
		("parity gate command yellow", ["pnpm", "--silent", "parity:ts-eslint:gate:yellow"]),
		("parity gate quick command", ["pnpm", "--silent", "parity:ts-eslint:gate:quick"]),
		("parity gate quick command red", ["pnpm", "--silent", "parity:ts-eslint:gate:quick:red"]),
		("parity gate quick command yellow", ["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow"]),
	]
	for base_label, base_command in gate_wrapper_help_base_commands:
		for suffix_label, suffix_tokens in gate_wrapper_help_then_malformed_suffixes:
			help_proc = subprocess.run(
				[*base_command, "--help", *suffix_tokens],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			help_lines = assert_gate_wrapper_help_contract(
				f"{base_label} help-then-{suffix_label}", help_proc, expected_gate_usage_line
			)
			if help_lines != gate_wrapper_help_baseline:
				fail(f"{base_label} help-then-{suffix_label} stderr output mismatch with help baseline")

			short_help_proc = subprocess.run(
				[*base_command, "-h", *suffix_tokens],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			short_help_lines = assert_gate_wrapper_help_contract(
				f"{base_label} short-help-then-{suffix_label}", short_help_proc, expected_gate_usage_line
			)
			if short_help_lines != gate_wrapper_help_baseline:
				fail(f"{base_label} short-help-then-{suffix_label} stderr output mismatch with help baseline")
			unknown_proc = subprocess.run(
				[*base_command, "--not-a-real-flag", *suffix_tokens],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			unknown_lines = assert_gate_wrapper_unknown_arg_contract(
				f"{base_label} unknown-then-{suffix_label}",
				unknown_proc,
				expected_gate_unknown_arg_line,
				expected_gate_usage_line,
			)
			if unknown_lines != gate_wrapper_unknown_arg_baseline:
				fail(f"{base_label} unknown-then-{suffix_label} stderr output mismatch with unknown baseline")
			for help_flag, help_flag_label in [("--help", "help"), ("-h", "short-help")]:
				unknown_then_help_proc = subprocess.run(
					[*base_command, "--not-a-real-flag", *suffix_tokens, help_flag],
					cwd=str(root),
					check=False,
					capture_output=True,
					text=True,
				)
				unknown_then_help_lines = assert_gate_wrapper_unknown_arg_contract(
					f"{base_label} unknown-then-{suffix_label}-then-{help_flag_label}",
					unknown_then_help_proc,
					expected_gate_unknown_arg_line,
					expected_gate_usage_line,
				)
				if unknown_then_help_lines != gate_wrapper_unknown_arg_baseline:
					fail(
						f"{base_label} unknown-then-{suffix_label}-then-{help_flag_label} "
						"stderr output mismatch with unknown baseline"
					)

	gate_wrapper_duplicate_threshold_cases = [
		(
			"parity gate command duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=red"],
		),
		(
			"parity gate command red duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=red"],
		),
		(
			"parity gate command yellow duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=yellow"],
		),
		(
			"parity gate quick command duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=red"],
		),
		(
			"parity gate quick command red duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=red"],
		),
		(
			"parity gate quick command yellow duplicate-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=yellow"],
		),
	]
	gate_wrapper_duplicate_threshold_lines: dict[str, list[str]] = {}
	gate_wrapper_duplicate_threshold_codes: dict[str, int] = {}
	for label, command in gate_wrapper_duplicate_threshold_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		gate_wrapper_duplicate_threshold_lines[label] = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		gate_wrapper_duplicate_threshold_codes[label] = proc.returncode
	if gate_wrapper_duplicate_threshold_codes["parity gate command duplicate-threshold"] != gate_wrapper_duplicate_threshold_codes[
		"parity gate command red duplicate-threshold"
	]:
		fail("parity gate duplicate-threshold alias return code mismatch with gate:red")
	if gate_wrapper_duplicate_threshold_lines["parity gate command duplicate-threshold"] != gate_wrapper_duplicate_threshold_lines[
		"parity gate command red duplicate-threshold"
	]:
		fail("parity gate duplicate-threshold alias stderr mismatch with gate:red")
	if gate_wrapper_duplicate_threshold_codes["parity gate quick command duplicate-threshold"] != gate_wrapper_duplicate_threshold_codes[
		"parity gate quick command red duplicate-threshold"
	]:
		fail("parity gate quick duplicate-threshold alias return code mismatch with quick:red")
	if gate_wrapper_duplicate_threshold_lines["parity gate quick command duplicate-threshold"] != gate_wrapper_duplicate_threshold_lines[
		"parity gate quick command red duplicate-threshold"
	]:
		fail("parity gate quick duplicate-threshold alias stderr mismatch with quick:red")
	gate_wrapper_duplicate_threshold_baseline = gate_wrapper_duplicate_threshold_lines[
		"parity gate command duplicate-threshold"
	]
	if gate_wrapper_duplicate_threshold_baseline != gate_duplicate_threshold_lines:
		fail("parity gate wrapper duplicate-threshold baseline mismatch with direct duplicate-threshold stderr")
	for label, lines in gate_wrapper_duplicate_threshold_lines.items():
		if lines != gate_wrapper_duplicate_threshold_baseline:
			fail(f"{label} stderr output mismatch with gate wrapper duplicate-threshold baseline")
	gate_wrapper_duplicate_threshold_spaced_cases = [
		(
			"parity gate command duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "red"],
			"parity gate command duplicate-threshold",
		),
		(
			"parity gate command red duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "red"],
			"parity gate command red duplicate-threshold",
		),
		(
			"parity gate command yellow duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "yellow"],
			"parity gate command yellow duplicate-threshold",
		),
		(
			"parity gate quick command duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "red"],
			"parity gate quick command duplicate-threshold",
		),
		(
			"parity gate quick command red duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "red"],
			"parity gate quick command red duplicate-threshold",
		),
		(
			"parity gate quick command yellow duplicate-threshold spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "yellow"],
			"parity gate quick command yellow duplicate-threshold",
		),
	]
	for label, command, inline_label in gate_wrapper_duplicate_threshold_spaced_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		spaced_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		if proc.returncode != gate_wrapper_duplicate_threshold_codes[inline_label]:
			fail(f"{label} return code mismatch with {inline_label}")
		if spaced_lines != gate_wrapper_duplicate_threshold_lines[inline_label]:
			fail(f"{label} stderr output mismatch with {inline_label}")
	gate_wrapper_duplicate_threshold_precedence_cases = [
		(
			"parity gate command duplicate-threshold precedence missing-value",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold"],
		),
		(
			"parity gate command red duplicate-threshold precedence invalid-value",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=blue"],
		),
		(
			"parity gate command yellow duplicate-threshold precedence empty-value",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold="],
		),
		(
			"parity gate quick command duplicate-threshold precedence missing-value",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold"],
		),
		(
			"parity gate quick command red duplicate-threshold precedence invalid-value",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=blue"],
		),
		(
			"parity gate quick command yellow duplicate-threshold precedence empty-value",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold="],
		),
		(
			"parity gate command duplicate-threshold precedence invalid-value-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "blue"],
		),
		(
			"parity gate command red duplicate-threshold precedence invalid-value-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "blue"],
		),
		(
			"parity gate command yellow duplicate-threshold precedence invalid-value-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "blue"],
		),
		(
			"parity gate quick command duplicate-threshold precedence invalid-value-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "blue"],
		),
		(
			"parity gate quick command red duplicate-threshold precedence invalid-value-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "blue"],
		),
		(
			"parity gate quick command yellow duplicate-threshold precedence invalid-value-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "blue"],
		),
		(
			"parity gate command duplicate-threshold precedence missing-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "--skip-checks"],
		),
		(
			"parity gate command red duplicate-threshold precedence missing-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "--skip-checks"],
		),
		(
			"parity gate command yellow duplicate-threshold precedence missing-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "--skip-checks"],
		),
		(
			"parity gate quick command duplicate-threshold precedence missing-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "--skip-checks"],
		),
		(
			"parity gate quick command red duplicate-threshold precedence missing-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "--skip-checks"],
		),
		(
			"parity gate quick command yellow duplicate-threshold precedence missing-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "--skip-checks"],
		),
		(
			"parity gate command duplicate-threshold precedence empty-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=", "--skip-checks"],
		),
		(
			"parity gate command red duplicate-threshold precedence empty-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=", "--skip-checks"],
		),
		(
			"parity gate command yellow duplicate-threshold precedence empty-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=", "--skip-checks"],
		),
		(
			"parity gate quick command duplicate-threshold precedence empty-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=", "--skip-checks"],
		),
		(
			"parity gate quick command red duplicate-threshold precedence empty-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=", "--skip-checks"],
		),
		(
			"parity gate quick command yellow duplicate-threshold precedence empty-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=", "--skip-checks"],
		),
		(
			"parity gate command duplicate-threshold precedence invalid-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate command red duplicate-threshold precedence invalid-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate command yellow duplicate-threshold precedence invalid-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick command duplicate-threshold precedence invalid-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick command red duplicate-threshold precedence invalid-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick command yellow duplicate-threshold precedence invalid-value with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate command duplicate-threshold precedence invalid-value-spaced with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate command red duplicate-threshold precedence invalid-value-spaced with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate command yellow duplicate-threshold precedence invalid-value-spaced with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate quick command duplicate-threshold precedence invalid-value-spaced with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate quick command red duplicate-threshold precedence invalid-value-spaced with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "blue", "--skip-checks"],
		),
		(
			"parity gate quick command yellow duplicate-threshold precedence invalid-value-spaced with trailing skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "blue", "--skip-checks"],
		),
	]
	for label, command in gate_wrapper_duplicate_threshold_precedence_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		precedence_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		if precedence_lines != gate_wrapper_duplicate_threshold_baseline:
			fail(f"{label} stderr output mismatch with duplicate-threshold precedence baseline")

	gate_wrapper_duplicate_skip_checks_cases = [
		(
			"parity gate command duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate command red duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate command yellow duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate quick command duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks"],
		),
		(
			"parity gate quick command red duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks"],
		),
		(
			"parity gate quick command yellow duplicate-skip-checks",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks"],
		),
	]
	gate_wrapper_duplicate_skip_checks_lines: dict[str, list[str]] = {}
	gate_wrapper_duplicate_skip_checks_codes: dict[str, int] = {}
	for label, command in gate_wrapper_duplicate_skip_checks_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		gate_wrapper_duplicate_skip_checks_lines[label] = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		gate_wrapper_duplicate_skip_checks_codes[label] = proc.returncode
	if gate_wrapper_duplicate_skip_checks_codes["parity gate command duplicate-skip-checks"] != gate_wrapper_duplicate_skip_checks_codes[
		"parity gate command red duplicate-skip-checks"
	]:
		fail("parity gate duplicate-skip-checks alias return code mismatch with gate:red")
	if gate_wrapper_duplicate_skip_checks_lines["parity gate command duplicate-skip-checks"] != gate_wrapper_duplicate_skip_checks_lines[
		"parity gate command red duplicate-skip-checks"
	]:
		fail("parity gate duplicate-skip-checks alias stderr mismatch with gate:red")
	if gate_wrapper_duplicate_skip_checks_codes["parity gate quick command duplicate-skip-checks"] != gate_wrapper_duplicate_skip_checks_codes[
		"parity gate quick command red duplicate-skip-checks"
	]:
		fail("parity gate quick duplicate-skip-checks alias return code mismatch with quick:red")
	if gate_wrapper_duplicate_skip_checks_lines["parity gate quick command duplicate-skip-checks"] != gate_wrapper_duplicate_skip_checks_lines[
		"parity gate quick command red duplicate-skip-checks"
	]:
		fail("parity gate quick duplicate-skip-checks alias stderr mismatch with quick:red")
	gate_wrapper_duplicate_skip_checks_baseline = gate_wrapper_duplicate_skip_checks_lines[
		"parity gate command duplicate-skip-checks"
	]
	if gate_wrapper_duplicate_skip_checks_baseline != gate_duplicate_skip_checks_lines:
		fail("parity gate wrapper duplicate-skip-checks baseline mismatch with direct duplicate-skip-checks stderr")
	for label, lines in gate_wrapper_duplicate_skip_checks_lines.items():
		if lines != gate_wrapper_duplicate_skip_checks_baseline:
			fail(f"{label} stderr output mismatch with gate wrapper duplicate-skip-checks baseline")
	gate_wrapper_duplicate_then_help_cases = [
		(
			"parity gate command duplicate-threshold then help",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command red duplicate-threshold then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command yellow duplicate-threshold then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command duplicate-threshold then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command red duplicate-threshold then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command yellow duplicate-threshold then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command duplicate-threshold then help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command red duplicate-threshold then help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command yellow duplicate-threshold then help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command duplicate-threshold then help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command red duplicate-threshold then help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command yellow duplicate-threshold then help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "blue", "--help"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command duplicate-threshold then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command red duplicate-threshold then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command yellow duplicate-threshold then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command duplicate-threshold then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command red duplicate-threshold then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command yellow duplicate-threshold then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command duplicate-threshold then short-help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command red duplicate-threshold then short-help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command yellow duplicate-threshold then short-help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command duplicate-threshold then short-help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command red duplicate-threshold then short-help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command yellow duplicate-threshold then short-help spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "blue", "-h"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command duplicate-skip-checks then help",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--help"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command red duplicate-skip-checks then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--help"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command yellow duplicate-skip-checks then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--help"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command duplicate-skip-checks then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--help"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command red duplicate-skip-checks then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--help"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--help"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command duplicate-skip-checks then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "-h"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command red duplicate-skip-checks then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "-h"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command yellow duplicate-skip-checks then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "-h"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command duplicate-skip-checks then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "-h"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command red duplicate-skip-checks then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "-h"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then short-help",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "-h"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
	]
	for label, command, expected_error_line, baseline_lines in gate_wrapper_duplicate_then_help_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		precedence_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_error_line,
			expected_gate_usage_line,
		)
		if precedence_lines != baseline_lines:
			fail(f"{label} stderr output mismatch with duplicate-vs-help precedence baseline")
	gate_wrapper_duplicate_threshold_tail_tokens = [
		("missing-threshold", ["--threshold"]),
		("empty-threshold", ["--threshold="]),
		("invalid-threshold-inline", ["--threshold=blue"]),
		("invalid-threshold-spaced", ["--threshold", "blue"]),
	]
	for base_label, base_command in gate_wrapper_help_base_commands:
		for tail_label, tail_tokens in gate_wrapper_duplicate_threshold_tail_tokens:
			for help_flag, help_label in [("--help", "help"), ("-h", "short-help")]:
				proc = subprocess.run(
					[*base_command, *tail_tokens, help_flag],
					cwd=str(root),
					check=False,
					capture_output=True,
					text=True,
				)
				lines = assert_gate_wrapper_unknown_arg_contract(
					f"{base_label} duplicate-threshold-then-{tail_label}-then-{help_label}",
					proc,
					expected_gate_duplicate_threshold_line,
					expected_gate_usage_line,
				)
				if lines != gate_wrapper_duplicate_threshold_baseline:
					fail(
						f"{base_label} duplicate-threshold-then-{tail_label}-then-{help_label} "
						"stderr output mismatch with duplicate-threshold baseline"
					)
			proc_with_unknown = subprocess.run(
				[*base_command, *tail_tokens, "--not-a-real-flag"],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			lines_with_unknown = assert_gate_wrapper_unknown_arg_contract(
				f"{base_label} duplicate-threshold-then-{tail_label}-then-unknown",
				proc_with_unknown,
				expected_gate_duplicate_threshold_line,
				expected_gate_usage_line,
			)
			if lines_with_unknown != gate_wrapper_duplicate_threshold_baseline:
				fail(
					f"{base_label} duplicate-threshold-then-{tail_label}-then-unknown "
					"stderr output mismatch with duplicate-threshold baseline"
				)
	gate_wrapper_duplicate_skip_then_malformed_threshold_cases = [
		(
			"parity gate command duplicate-skip-checks then missing-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--threshold"],
		),
		(
			"parity gate command red duplicate-skip-checks then missing-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--threshold"],
		),
		(
			"parity gate command yellow duplicate-skip-checks then missing-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--threshold"],
		),
		(
			"parity gate quick command duplicate-skip-checks then missing-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--threshold"],
		),
		(
			"parity gate quick command red duplicate-skip-checks then missing-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--threshold"],
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then missing-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--threshold"],
		),
		(
			"parity gate command duplicate-skip-checks then empty-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--threshold="],
		),
		(
			"parity gate command red duplicate-skip-checks then empty-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--threshold="],
		),
		(
			"parity gate command yellow duplicate-skip-checks then empty-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--threshold="],
		),
		(
			"parity gate quick command duplicate-skip-checks then empty-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--threshold="],
		),
		(
			"parity gate quick command red duplicate-skip-checks then empty-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--threshold="],
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then empty-threshold",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--threshold="],
		),
		(
			"parity gate command duplicate-skip-checks then invalid-threshold-inline",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate command red duplicate-skip-checks then invalid-threshold-inline",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate command yellow duplicate-skip-checks then invalid-threshold-inline",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate quick command duplicate-skip-checks then invalid-threshold-inline",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate quick command red duplicate-skip-checks then invalid-threshold-inline",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then invalid-threshold-inline",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate command duplicate-skip-checks then invalid-threshold-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--threshold", "blue"],
		),
		(
			"parity gate command red duplicate-skip-checks then invalid-threshold-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--threshold", "blue"],
		),
		(
			"parity gate command yellow duplicate-skip-checks then invalid-threshold-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--threshold", "blue"],
		),
		(
			"parity gate quick command duplicate-skip-checks then invalid-threshold-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--threshold", "blue"],
		),
		(
			"parity gate quick command red duplicate-skip-checks then invalid-threshold-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--threshold", "blue"],
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then invalid-threshold-spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--threshold", "blue"],
		),
	]
	for label, command in gate_wrapper_duplicate_skip_then_malformed_threshold_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		precedence_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		if precedence_lines != gate_wrapper_duplicate_skip_checks_baseline:
			fail(f"{label} stderr output mismatch with duplicate-skip-checks malformed-tail baseline")
		for help_flag, help_label in [("--help", "help"), ("-h", "short-help")]:
			proc_with_help = subprocess.run(
				[*command, help_flag],
				cwd=str(root),
				check=False,
				capture_output=True,
				text=True,
			)
			precedence_with_help_lines = assert_gate_wrapper_unknown_arg_contract(
				f"{label} then {help_label}",
				proc_with_help,
				expected_gate_duplicate_skip_checks_line,
				expected_gate_usage_line,
			)
			if precedence_with_help_lines != gate_wrapper_duplicate_skip_checks_baseline:
				fail(f"{label} then {help_label} stderr output mismatch with duplicate-skip-checks malformed-tail baseline")
	gate_wrapper_duplicate_then_unknown_cases = [
		(
			"parity gate command duplicate-threshold then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command red duplicate-threshold then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command yellow duplicate-threshold then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command duplicate-threshold then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command red duplicate-threshold then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command yellow duplicate-threshold then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command duplicate-threshold then unknown spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command red duplicate-threshold then unknown spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command yellow duplicate-threshold then unknown spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command duplicate-threshold then unknown spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command red duplicate-threshold then unknown spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate quick command yellow duplicate-threshold then unknown spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "blue", "--not-a-real-flag"],
			expected_gate_duplicate_threshold_line,
			gate_wrapper_duplicate_threshold_baseline,
		),
		(
			"parity gate command duplicate-skip-checks then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--not-a-real-flag"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command red duplicate-skip-checks then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--not-a-real-flag"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate command yellow duplicate-skip-checks then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--not-a-real-flag"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command duplicate-skip-checks then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--not-a-real-flag"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command red duplicate-skip-checks then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--not-a-real-flag"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
		(
			"parity gate quick command yellow duplicate-skip-checks then unknown",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--not-a-real-flag"],
			expected_gate_duplicate_skip_checks_line,
			gate_wrapper_duplicate_skip_checks_baseline,
		),
	]
	for label, command, expected_error_line, baseline_lines in gate_wrapper_duplicate_then_unknown_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		precedence_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_error_line,
			expected_gate_usage_line,
		)
		if precedence_lines != baseline_lines:
			fail(f"{label} stderr output mismatch with duplicate precedence baseline")
	gate_wrapper_conflict_threshold_first_cases = [
		(
			"parity gate quick conflict threshold-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick:red conflict threshold-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold=blue", "--skip-checks"],
		),
		(
			"parity gate quick:yellow conflict threshold-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold=blue", "--skip-checks"],
		),
	]
	gate_wrapper_conflict_threshold_first_lines: dict[str, list[str]] = {}
	gate_wrapper_conflict_threshold_first_codes: dict[str, int] = {}
	for label, command in gate_wrapper_conflict_threshold_first_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		conflict_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		gate_wrapper_conflict_threshold_first_lines[label] = conflict_lines
		gate_wrapper_conflict_threshold_first_codes[label] = proc.returncode
		if conflict_lines != gate_wrapper_duplicate_threshold_baseline:
			fail(f"{label} stderr output mismatch with duplicate-threshold precedence baseline")
		if conflict_lines != gate_conflict_threshold_first_lines:
			fail(f"{label} stderr output mismatch with direct conflict threshold-first baseline")
	if gate_wrapper_conflict_threshold_first_codes["parity gate quick conflict threshold-first"] != gate_wrapper_conflict_threshold_first_codes[
		"parity gate quick:red conflict threshold-first"
	]:
		fail("parity gate quick threshold-first conflict alias return code mismatch with quick:red")
	if gate_wrapper_conflict_threshold_first_lines["parity gate quick conflict threshold-first"] != gate_wrapper_conflict_threshold_first_lines[
		"parity gate quick:red conflict threshold-first"
	]:
		fail("parity gate quick threshold-first conflict alias stderr mismatch with quick:red")
	gate_wrapper_conflict_threshold_first_spaced_cases = [
		(
			"parity gate quick conflict threshold-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--threshold", "blue", "--skip-checks"],
			"parity gate quick conflict threshold-first",
		),
		(
			"parity gate quick:red conflict threshold-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--threshold", "blue", "--skip-checks"],
			"parity gate quick:red conflict threshold-first",
		),
		(
			"parity gate quick:yellow conflict threshold-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--threshold", "blue", "--skip-checks"],
			"parity gate quick:yellow conflict threshold-first",
		),
	]
	for label, command, inline_label in gate_wrapper_conflict_threshold_first_spaced_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		spaced_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		if proc.returncode != gate_wrapper_conflict_threshold_first_codes[inline_label]:
			fail(f"{label} return code mismatch with {inline_label}")
		if spaced_lines != gate_wrapper_conflict_threshold_first_lines[inline_label]:
			fail(f"{label} stderr output mismatch with {inline_label}")

	gate_wrapper_conflict_skip_first_cases = [
		(
			"parity gate quick conflict skip-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate quick:red conflict skip-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate quick:yellow conflict skip-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--threshold=blue"],
		),
	]
	gate_wrapper_conflict_skip_first_lines: dict[str, list[str]] = {}
	gate_wrapper_conflict_skip_first_codes: dict[str, int] = {}
	for label, command in gate_wrapper_conflict_skip_first_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		conflict_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		gate_wrapper_conflict_skip_first_lines[label] = conflict_lines
		gate_wrapper_conflict_skip_first_codes[label] = proc.returncode
		if conflict_lines != gate_wrapper_duplicate_skip_checks_baseline:
			fail(f"{label} stderr output mismatch with duplicate-skip-checks precedence baseline")
		if conflict_lines != gate_conflict_skip_first_lines:
			fail(f"{label} stderr output mismatch with direct conflict skip-first baseline")
	if gate_wrapper_conflict_skip_first_codes["parity gate quick conflict skip-first"] != gate_wrapper_conflict_skip_first_codes[
		"parity gate quick:red conflict skip-first"
	]:
		fail("parity gate quick skip-first conflict alias return code mismatch with quick:red")
	if gate_wrapper_conflict_skip_first_lines["parity gate quick conflict skip-first"] != gate_wrapper_conflict_skip_first_lines[
		"parity gate quick:red conflict skip-first"
	]:
		fail("parity gate quick skip-first conflict alias stderr mismatch with quick:red")
	gate_wrapper_conflict_skip_first_spaced_cases = [
		(
			"parity gate quick conflict skip-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick", "--skip-checks", "--threshold", "blue"],
			"parity gate quick conflict skip-first",
		),
		(
			"parity gate quick:red conflict skip-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:red", "--skip-checks", "--threshold", "blue"],
			"parity gate quick:red conflict skip-first",
		),
		(
			"parity gate quick:yellow conflict skip-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:quick:yellow", "--skip-checks", "--threshold", "blue"],
			"parity gate quick:yellow conflict skip-first",
		),
	]
	for label, command, inline_label in gate_wrapper_conflict_skip_first_spaced_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		spaced_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		if proc.returncode != gate_wrapper_conflict_skip_first_codes[inline_label]:
			fail(f"{label} return code mismatch with {inline_label}")
		if spaced_lines != gate_wrapper_conflict_skip_first_lines[inline_label]:
			fail(f"{label} stderr output mismatch with {inline_label}")
	gate_wrapper_conflict_default_threshold_first_cases = [
		(
			"parity gate command conflict threshold-first",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold=blue", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate command red conflict threshold-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold=blue", "--skip-checks", "--skip-checks"],
		),
		(
			"parity gate command yellow conflict threshold-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold=blue", "--skip-checks", "--skip-checks"],
		),
	]
	gate_wrapper_conflict_default_threshold_first_lines: dict[str, list[str]] = {}
	gate_wrapper_conflict_default_threshold_first_codes: dict[str, int] = {}
	for label, command in gate_wrapper_conflict_default_threshold_first_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		conflict_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		gate_wrapper_conflict_default_threshold_first_lines[label] = conflict_lines
		gate_wrapper_conflict_default_threshold_first_codes[label] = proc.returncode
		if conflict_lines != gate_wrapper_duplicate_threshold_baseline:
			fail(f"{label} stderr output mismatch with duplicate-threshold precedence baseline")
		if conflict_lines != gate_conflict_threshold_first_lines:
			fail(f"{label} stderr output mismatch with direct conflict threshold-first baseline")
	if gate_wrapper_conflict_default_threshold_first_codes["parity gate command conflict threshold-first"] != gate_wrapper_conflict_default_threshold_first_codes[
		"parity gate command red conflict threshold-first"
	]:
		fail("parity gate command threshold-first conflict alias return code mismatch with gate:red")
	if gate_wrapper_conflict_default_threshold_first_lines["parity gate command conflict threshold-first"] != gate_wrapper_conflict_default_threshold_first_lines[
		"parity gate command red conflict threshold-first"
	]:
		fail("parity gate command threshold-first conflict alias stderr mismatch with gate:red")
	gate_wrapper_conflict_default_threshold_first_spaced_cases = [
		(
			"parity gate command conflict threshold-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--threshold", "blue", "--skip-checks", "--skip-checks"],
			"parity gate command conflict threshold-first",
		),
		(
			"parity gate command red conflict threshold-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--threshold", "blue", "--skip-checks", "--skip-checks"],
			"parity gate command red conflict threshold-first",
		),
		(
			"parity gate command yellow conflict threshold-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--threshold", "blue", "--skip-checks", "--skip-checks"],
			"parity gate command yellow conflict threshold-first",
		),
	]
	for label, command, inline_label in gate_wrapper_conflict_default_threshold_first_spaced_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		spaced_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_threshold_line,
			expected_gate_usage_line,
		)
		if proc.returncode != gate_wrapper_conflict_default_threshold_first_codes[inline_label]:
			fail(f"{label} return code mismatch with {inline_label}")
		if spaced_lines != gate_wrapper_conflict_default_threshold_first_lines[inline_label]:
			fail(f"{label} stderr output mismatch with {inline_label}")

	gate_wrapper_conflict_default_skip_first_cases = [
		(
			"parity gate command conflict skip-first",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate command red conflict skip-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--threshold=blue"],
		),
		(
			"parity gate command yellow conflict skip-first",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--threshold=blue"],
		),
	]
	gate_wrapper_conflict_default_skip_first_lines: dict[str, list[str]] = {}
	gate_wrapper_conflict_default_skip_first_codes: dict[str, int] = {}
	for label, command in gate_wrapper_conflict_default_skip_first_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		conflict_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		gate_wrapper_conflict_default_skip_first_lines[label] = conflict_lines
		gate_wrapper_conflict_default_skip_first_codes[label] = proc.returncode
		if conflict_lines != gate_wrapper_duplicate_skip_checks_baseline:
			fail(f"{label} stderr output mismatch with duplicate-skip-checks precedence baseline")
		if conflict_lines != gate_conflict_skip_first_lines:
			fail(f"{label} stderr output mismatch with direct conflict skip-first baseline")
	if gate_wrapper_conflict_default_skip_first_codes["parity gate command conflict skip-first"] != gate_wrapper_conflict_default_skip_first_codes[
		"parity gate command red conflict skip-first"
	]:
		fail("parity gate command skip-first conflict alias return code mismatch with gate:red")
	if gate_wrapper_conflict_default_skip_first_lines["parity gate command conflict skip-first"] != gate_wrapper_conflict_default_skip_first_lines[
		"parity gate command red conflict skip-first"
	]:
		fail("parity gate command skip-first conflict alias stderr mismatch with gate:red")
	gate_wrapper_conflict_default_skip_first_spaced_cases = [
		(
			"parity gate command conflict skip-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks", "--skip-checks", "--threshold", "blue"],
			"parity gate command conflict skip-first",
		),
		(
			"parity gate command red conflict skip-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks", "--skip-checks", "--threshold", "blue"],
			"parity gate command red conflict skip-first",
		),
		(
			"parity gate command yellow conflict skip-first spaced",
			["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks", "--skip-checks", "--threshold", "blue"],
			"parity gate command yellow conflict skip-first",
		),
	]
	for label, command, inline_label in gate_wrapper_conflict_default_skip_first_spaced_cases:
		proc = subprocess.run(
			command,
			cwd=str(root),
			check=False,
			capture_output=True,
			text=True,
		)
		spaced_lines = assert_gate_wrapper_unknown_arg_contract(
			label,
			proc,
			expected_gate_duplicate_skip_checks_line,
			expected_gate_usage_line,
		)
		if proc.returncode != gate_wrapper_conflict_default_skip_first_codes[inline_label]:
			fail(f"{label} return code mismatch with {inline_label}")
		if spaced_lines != gate_wrapper_conflict_default_skip_first_lines[inline_label]:
			fail(f"{label} stderr output mismatch with {inline_label}")

	# Gate npm command wrappers in skip-check mode
	gate_cmd = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:gate", "--skip-checks"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_cmd.returncode != expected_gate_red_exit:
		fail(
			"parity gate command exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_cmd.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity gate command stdout", gate_cmd.stdout)
	assert_no_pnpm_lifecycle_noise("parity gate command stderr", gate_cmd.stderr)
	if "[parity-gate] Skipping strict clean parity checks (--skip-checks)." not in (gate_cmd.stdout + gate_cmd.stderr):
		fail("parity gate command output missing skip-checks message")
	if "[parity-gate] Applying red threshold gates" not in (gate_cmd.stdout + gate_cmd.stderr):
		fail("parity gate command output missing red-threshold marker")
	if "[parity-gate] Running strict clean parity checks" in (gate_cmd.stdout + gate_cmd.stderr):
		fail("parity gate command should not run strict clean checks")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_cmd.stderr:
		fail("parity gate command stderr missing health+reason message")
	assert_gate_success_contract("parity gate command", gate_cmd, "red", expected_gate_red_exit)
	assert_exact_nonempty_lines("parity gate command combined output", gate_cmd.stdout + gate_cmd.stderr, gate_red_lines)
	assert_exact_nonempty_lines("parity gate command stdout", gate_cmd.stdout, gate_red_stdout_lines)
	assert_exact_nonempty_lines("parity gate command stderr", gate_cmd.stderr, gate_red_stderr_lines)
	gate_cmd_prefixed_lines = extract_prefixed_lines(
		gate_cmd.stdout + gate_cmd.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_cmd_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate command prefixed output mismatch with direct red skip-check run")

	gate_cmd_red = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:gate:red", "--skip-checks"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_cmd_red.returncode != expected_gate_red_exit:
		fail(
			"parity gate command red exit-code mismatch: "
			f"expected={expected_gate_red_exit} actual={gate_cmd_red.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity gate command red stdout", gate_cmd_red.stdout)
	assert_no_pnpm_lifecycle_noise("parity gate command red stderr", gate_cmd_red.stderr)
	if "[parity-gate] Skipping strict clean parity checks (--skip-checks)." not in (gate_cmd_red.stdout + gate_cmd_red.stderr):
		fail("parity gate command red output missing skip-checks message")
	if "[parity-gate] Applying red threshold gates" not in (gate_cmd_red.stdout + gate_cmd_red.stderr):
		fail("parity gate command red output missing red-threshold marker")
	if "[parity-gate] Running strict clean parity checks" in (gate_cmd_red.stdout + gate_cmd_red.stderr):
		fail("parity gate command red should not run strict clean checks")
	if expected_gate_red_exit == 2 and expected_health_reason_marker not in gate_cmd_red.stderr:
		fail("parity gate command red stderr missing health+reason message")
	assert_gate_success_contract("parity gate command red", gate_cmd_red, "red", expected_gate_red_exit)
	assert_exact_nonempty_lines(
		"parity gate command red combined output", gate_cmd_red.stdout + gate_cmd_red.stderr, gate_red_lines
	)
	assert_exact_nonempty_lines("parity gate command red stdout", gate_cmd_red.stdout, gate_red_stdout_lines)
	assert_exact_nonempty_lines("parity gate command red stderr", gate_cmd_red.stderr, gate_red_stderr_lines)
	gate_cmd_red_prefixed_lines = extract_prefixed_lines(
		gate_cmd_red.stdout + gate_cmd_red.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_cmd_red_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate command red prefixed output mismatch with direct red skip-check run")
	if gate_cmd.returncode != gate_cmd_red.returncode:
		fail("parity gate command alias return code mismatch with gate:red")
	assert_exact_nonempty_lines(
		"parity gate command alias stdout",
		gate_cmd.stdout,
		extract_nonempty_lines(gate_cmd_red.stdout),
	)
	assert_exact_nonempty_lines(
		"parity gate command alias stderr",
		gate_cmd.stderr,
		extract_nonempty_lines(gate_cmd_red.stderr),
	)
	if gate_cmd_prefixed_lines != gate_cmd_red_prefixed_lines:
		fail("parity gate command alias prefixed output mismatch with gate:red")

	gate_cmd_yellow = subprocess.run(
		["pnpm", "--silent", "parity:ts-eslint:gate:yellow", "--skip-checks"],
		cwd=str(root),
		check=False,
		capture_output=True,
		text=True,
	)
	if gate_cmd_yellow.returncode != expected_gate_yellow_exit:
		fail(
			"parity gate command yellow exit-code mismatch: "
			f"expected={expected_gate_yellow_exit} actual={gate_cmd_yellow.returncode}"
		)
	assert_no_pnpm_lifecycle_noise("parity gate command yellow stdout", gate_cmd_yellow.stdout)
	assert_no_pnpm_lifecycle_noise("parity gate command yellow stderr", gate_cmd_yellow.stderr)
	if "[parity-gate] Skipping strict clean parity checks (--skip-checks)." not in (
		gate_cmd_yellow.stdout + gate_cmd_yellow.stderr
	):
		fail("parity gate command yellow output missing skip-checks message")
	if "[parity-gate] Applying yellow threshold gates" not in (gate_cmd_yellow.stdout + gate_cmd_yellow.stderr):
		fail("parity gate command yellow output missing yellow-threshold marker")
	if "[parity-gate] Running strict clean parity checks" in (gate_cmd_yellow.stdout + gate_cmd_yellow.stderr):
		fail("parity gate command yellow should not run strict clean checks")
	if expected_gate_yellow_exit == 3 and expected_health_reason_marker not in gate_cmd_yellow.stderr:
		fail("parity gate command yellow stderr missing health+reason message")
	assert_gate_success_contract("parity gate command yellow", gate_cmd_yellow, "yellow", expected_gate_yellow_exit)
	assert_exact_nonempty_lines(
		"parity gate command yellow combined output",
		gate_cmd_yellow.stdout + gate_cmd_yellow.stderr,
		gate_yellow_lines,
	)
	assert_exact_nonempty_lines("parity gate command yellow stdout", gate_cmd_yellow.stdout, gate_yellow_stdout_lines)
	assert_exact_nonempty_lines("parity gate command yellow stderr", gate_cmd_yellow.stderr, gate_yellow_stderr_lines)
	gate_cmd_yellow_prefixed_lines = extract_prefixed_lines(
		gate_cmd_yellow.stdout + gate_cmd_yellow.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_cmd_yellow_prefixed_lines != gate_yellow_prefixed_lines:
		fail("parity gate command yellow prefixed output mismatch with direct yellow skip-check run")

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
	assert_gate_success_contract("parity gate quick", gate_quick, "red", expected_gate_red_exit)
	assert_exact_nonempty_lines("parity gate quick combined output", gate_quick.stdout + gate_quick.stderr, gate_red_lines)
	assert_exact_nonempty_lines("parity gate quick stdout", gate_quick.stdout, gate_red_stdout_lines)
	assert_exact_nonempty_lines("parity gate quick stderr", gate_quick.stderr, gate_red_stderr_lines)
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
	assert_gate_success_contract("parity gate quick:red", gate_quick_red, "red", expected_gate_red_exit)
	assert_exact_nonempty_lines("parity gate quick:red combined output", gate_quick_red.stdout + gate_quick_red.stderr, gate_red_lines)
	assert_exact_nonempty_lines("parity gate quick:red stdout", gate_quick_red.stdout, gate_red_stdout_lines)
	assert_exact_nonempty_lines("parity gate quick:red stderr", gate_quick_red.stderr, gate_red_stderr_lines)
	gate_quick_red_prefixed_lines = extract_prefixed_lines(
		gate_quick_red.stdout + gate_quick_red.stderr,
		("[parity-gate]", "[parity-status]", "[parity-doctor]"),
	)
	if gate_quick_red_prefixed_lines != gate_red_prefixed_lines:
		fail("parity gate quick:red prefixed output mismatch with direct red skip-check run")
	if gate_quick.returncode != gate_quick_red.returncode:
		fail("parity gate quick alias return code mismatch with quick:red")
	assert_exact_nonempty_lines(
		"parity gate quick alias stdout",
		gate_quick.stdout,
		extract_nonempty_lines(gate_quick_red.stdout),
	)
	assert_exact_nonempty_lines(
		"parity gate quick alias stderr",
		gate_quick.stderr,
		extract_nonempty_lines(gate_quick_red.stderr),
	)
	if gate_quick_prefixed_lines != gate_quick_red_prefixed_lines:
		fail("parity gate quick alias prefixed output mismatch with quick:red")

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
	assert_gate_success_contract("parity gate quick:yellow", gate_quick_yellow, "yellow", expected_gate_yellow_exit)
	assert_exact_nonempty_lines(
		"parity gate quick:yellow combined output",
		gate_quick_yellow.stdout + gate_quick_yellow.stderr,
		gate_yellow_lines,
	)
	assert_exact_nonempty_lines("parity gate quick:yellow stdout", gate_quick_yellow.stdout, gate_yellow_stdout_lines)
	assert_exact_nonempty_lines("parity gate quick:yellow stderr", gate_quick_yellow.stderr, gate_yellow_stderr_lines)
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
	ci_summary_script = root / "scripts/generate_ts_eslint_parity_ci_summary.py"
	try:
		ci_summary_proc = subprocess.run(
			["python3", str(ci_summary_script)],
			check=True,
			capture_output=True,
			text=True,
		)
		ci_summary_json_proc = subprocess.run(
			["python3", str(ci_summary_script), "--json"],
			check=True,
			capture_output=True,
			text=True,
		)
	except subprocess.CalledProcessError as err:
		fail(f"ci summary script failed: {err}")
	if ci_summary_proc.stderr.strip():
		fail("ci summary direct script stderr must be empty in non-strict mode")
	if ci_summary_json_proc.stderr.strip():
		fail("ci summary json direct script stderr must be empty in non-strict mode")
	ci_summary_output = ci_summary_proc.stdout
	ci_summary_json_output = ci_summary_json_proc.stdout

	ci_summary = parse_ci_summary_markdown(ci_summary_output)
	ci_summary_json = parse_ci_summary_json(ci_summary_json_output)
	ci_summary_lines = [line.strip() for line in ci_summary_output.splitlines() if line.strip()]
	ci_summary_json_lines = [line.strip() for line in ci_summary_json_output.splitlines() if line.strip()]
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
	if ci_summary_cmd.stderr.strip():
		fail("ci summary command stderr must be empty in non-strict mode")
	assert_exact_nonempty_lines("ci summary command stdout", ci_summary_cmd.stdout, ci_summary_lines)
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
	if ci_summary_json_cmd.stderr.strip():
		fail("ci summary json command stderr must be empty in non-strict mode")
	assert_exact_nonempty_lines("ci summary json command stdout", ci_summary_json_cmd.stdout, ci_summary_json_lines)
	ci_summary_json_cmd_parsed = parse_ci_summary_json(ci_summary_json_cmd.stdout)
	if ci_summary_json_cmd_parsed != ci_summary_json:
		fail("ci summary json command output mismatch with direct script output")
	ci_summary_cli_contracts = [
		(
			"ci summary command",
			[],
			["pnpm", "--silent", "parity:ts-eslint:ci-summary"],
		),
		(
			"ci summary json command",
			["--json"],
			["pnpm", "--silent", "parity:ts-eslint:ci-summary:json"],
		),
		(
			"ci summary command strict",
			["--fail-on-red"],
			["pnpm", "--silent", "parity:ts-eslint:ci-summary:strict"],
		),
		(
			"ci summary command strict-yellow",
			["--fail-on-yellow"],
			["pnpm", "--silent", "parity:ts-eslint:ci-summary:strict:yellow"],
		),
	]
	assert_wrapper_argparse_forwarding_contracts(root, ci_summary_script, ci_summary_cli_contracts)

	# CI summary strict-mode exit-code checks
	ci_summary_strict = subprocess.run(
		["python3", str(ci_summary_script), "--fail-on-red"],
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
	if expected_ci_summary_strict_exit == 0 and ci_summary_strict.stderr.strip():
		fail("ci summary strict stderr must be empty on success")
	assert_exact_nonempty_lines("ci summary strict stdout", ci_summary_strict.stdout, ci_summary_lines)
	ci_summary_strict_parsed = parse_ci_summary_markdown(ci_summary_strict.stdout)
	if ci_summary_strict_parsed != ci_summary:
		fail("ci summary strict stdout mismatch with non-strict summary output")

	ci_summary_strict_yellow = subprocess.run(
		["python3", str(ci_summary_script), "--fail-on-yellow"],
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
	if expected_ci_summary_strict_yellow_exit == 0 and ci_summary_strict_yellow.stderr.strip():
		fail("ci summary strict-yellow stderr must be empty on success")
	assert_exact_nonempty_lines("ci summary strict-yellow stdout", ci_summary_strict_yellow.stdout, ci_summary_lines)
	ci_summary_strict_yellow_parsed = parse_ci_summary_markdown(ci_summary_strict_yellow.stdout)
	if ci_summary_strict_yellow_parsed != ci_summary:
		fail("ci summary strict-yellow stdout mismatch with non-strict summary output")
	ci_summary_strict_stdout_lines = extract_nonempty_lines(ci_summary_strict.stdout)
	ci_summary_strict_yellow_stdout_lines = extract_nonempty_lines(ci_summary_strict_yellow.stdout)
	ci_summary_strict_stderr_lines = extract_nonempty_lines(ci_summary_strict.stderr)
	ci_summary_strict_yellow_stderr_lines = extract_nonempty_lines(ci_summary_strict_yellow.stderr)

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
	if expected_ci_summary_strict_exit == 0 and ci_summary_cmd_strict.stderr.strip():
		fail("ci summary command strict stderr must be empty on success")
	assert_exact_nonempty_lines("ci summary command strict stdout", ci_summary_cmd_strict.stdout, ci_summary_strict_stdout_lines)
	ci_summary_cmd_strict_parsed = parse_ci_summary_markdown(ci_summary_cmd_strict.stdout)
	if ci_summary_cmd_strict_parsed != ci_summary_strict_parsed:
		fail("ci summary command strict stdout mismatch with direct strict summary output")
	if expected_ci_summary_strict_exit == 2 and "[parity-ci-summary] ERROR:" not in ci_summary_cmd_strict.stderr:
		fail("ci summary command strict stderr missing parity-ci-summary error prefix")
	if expected_ci_summary_strict_exit == 2 and expected_health_reason_marker not in ci_summary_cmd_strict.stderr:
		fail("ci summary command strict stderr missing health+reason message")
	assert_exact_nonempty_lines("ci summary command strict stderr", ci_summary_cmd_strict.stderr, ci_summary_strict_stderr_lines)
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
	if expected_ci_summary_strict_yellow_exit == 0 and ci_summary_cmd_strict_yellow.stderr.strip():
		fail("ci summary command strict-yellow stderr must be empty on success")
	assert_exact_nonempty_lines(
		"ci summary command strict-yellow stdout",
		ci_summary_cmd_strict_yellow.stdout,
		ci_summary_strict_yellow_stdout_lines,
	)
	ci_summary_cmd_strict_yellow_parsed = parse_ci_summary_markdown(ci_summary_cmd_strict_yellow.stdout)
	if ci_summary_cmd_strict_yellow_parsed != ci_summary_strict_yellow_parsed:
		fail("ci summary command strict-yellow stdout mismatch with direct strict-yellow summary output")
	if expected_ci_summary_strict_yellow_exit == 3 and "[parity-ci-summary] ERROR:" not in ci_summary_cmd_strict_yellow.stderr:
		fail("ci summary command strict-yellow stderr missing parity-ci-summary error prefix")
	if expected_ci_summary_strict_yellow_exit == 3 and expected_health_reason_marker not in ci_summary_cmd_strict_yellow.stderr:
		fail("ci summary command strict-yellow stderr missing health+reason message")
	assert_exact_nonempty_lines(
		"ci summary command strict-yellow stderr",
		ci_summary_cmd_strict_yellow.stderr,
		ci_summary_strict_yellow_stderr_lines,
	)
	ci_summary_strict_yellow_prefixed_lines = extract_prefixed_lines(
		ci_summary_strict_yellow.stdout + ci_summary_strict_yellow.stderr, ("[parity-ci-summary]",)
	)
	ci_summary_cmd_strict_yellow_prefixed_lines = extract_prefixed_lines(
		ci_summary_cmd_strict_yellow.stdout + ci_summary_cmd_strict_yellow.stderr, ("[parity-ci-summary]",)
	)
	if ci_summary_cmd_strict_yellow_prefixed_lines != ci_summary_strict_yellow_prefixed_lines:
		fail("ci summary command strict-yellow prefixed stderr output mismatch with direct strict-yellow mode")

	# Parity doctor output checks
	doctor_script = root / "scripts/generate_ts_eslint_parity_doctor.py"
	try:
		doctor_plain_proc = subprocess.run(
			["python3", str(doctor_script)],
			check=True,
			capture_output=True,
			text=True,
		)
		doctor_md_proc = subprocess.run(
			["python3", str(doctor_script), "--markdown"],
			check=True,
			capture_output=True,
			text=True,
		)
		doctor_json_proc = subprocess.run(
			["python3", str(doctor_script), "--json"],
			check=True,
			capture_output=True,
			text=True,
		)
	except subprocess.CalledProcessError as err:
		fail(f"parity doctor script failed: {err}")
	if doctor_plain_proc.stderr.strip():
		fail("parity doctor direct plain script stderr must be empty in non-strict mode")
	if doctor_md_proc.stderr.strip():
		fail("parity doctor direct markdown script stderr must be empty in non-strict mode")
	if doctor_json_proc.stderr.strip():
		fail("parity doctor direct json script stderr must be empty in non-strict mode")
	doctor_plain = doctor_plain_proc.stdout
	doctor_md = doctor_md_proc.stdout
	doctor_json = doctor_json_proc.stdout

	if "Parity Doctor" not in doctor_plain:
		fail("parity doctor plain output missing title")
	if "### Parity Doctor" not in doctor_md:
		fail("parity doctor markdown output missing heading")

	doctor_plain_data = parse_doctor_plain_output(doctor_plain)
	doctor_md_data = parse_doctor_markdown_output(doctor_md)
	doctor_json_data = parse_doctor_json_output(doctor_json)
	doctor_plain_lines = [line.strip() for line in doctor_plain.splitlines() if line.strip()]
	doctor_markdown_lines = [line.strip() for line in doctor_md.splitlines() if line.strip()]
	doctor_json_lines = [line.strip() for line in doctor_json.splitlines() if line.strip()]

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
	if doctor_cmd.stderr.strip():
		fail("parity doctor command stderr must be empty in non-strict mode")
	assert_exact_nonempty_lines("parity doctor command stdout", doctor_cmd.stdout, doctor_plain_lines)
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
	if doctor_markdown_cmd.stderr.strip():
		fail("parity doctor markdown command stderr must be empty in non-strict mode")
	assert_exact_nonempty_lines("parity doctor markdown command stdout", doctor_markdown_cmd.stdout, doctor_markdown_lines)
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
	if doctor_json_cmd.stderr.strip():
		fail("parity doctor json command stderr must be empty in non-strict mode")
	assert_exact_nonempty_lines("parity doctor json command stdout", doctor_json_cmd.stdout, doctor_json_lines)
	if parse_doctor_json_output(doctor_json_cmd.stdout) != doctor_json_data:
		fail("parity doctor json command output mismatch with direct script output")
	doctor_cli_contracts = [
		(
			"parity doctor command",
			[],
			["pnpm", "--silent", "parity:ts-eslint:doctor"],
		),
		(
			"parity doctor markdown command",
			["--markdown"],
			["pnpm", "--silent", "parity:ts-eslint:doctor:markdown"],
		),
		(
			"parity doctor json command",
			["--json"],
			["pnpm", "--silent", "parity:ts-eslint:doctor:json"],
		),
		(
			"parity doctor command strict",
			["--fail-on-critical"],
			["pnpm", "--silent", "parity:ts-eslint:doctor:strict"],
		),
		(
			"parity doctor command strict-yellow",
			["--fail-on-yellow"],
			["pnpm", "--silent", "parity:ts-eslint:doctor:strict:yellow"],
		),
		(
			"parity doctor json command strict",
			["--json", "--fail-on-critical"],
			["pnpm", "--silent", "parity:ts-eslint:doctor:json:strict"],
		),
		(
			"parity doctor json command strict-yellow",
			["--json", "--fail-on-yellow"],
			["pnpm", "--silent", "parity:ts-eslint:doctor:json:strict:yellow"],
		),
	]
	assert_wrapper_argparse_forwarding_contracts(root, doctor_script, doctor_cli_contracts)

	# Parity doctor strict-mode exit-code checks
	doctor_strict = subprocess.run(
		["python3", str(doctor_script), "--fail-on-critical"],
		check=False,
		capture_output=True,
		text=True,
	)
	doctor_json_strict = subprocess.run(
		["python3", str(doctor_script), "--json", "--fail-on-critical"],
		check=False,
		capture_output=True,
		text=True,
	)
	doctor_yellow_strict = subprocess.run(
		["python3", str(doctor_script), "--fail-on-yellow"],
		check=False,
		capture_output=True,
		text=True,
	)
	doctor_json_yellow_strict = subprocess.run(
		["python3", str(doctor_script), "--json", "--fail-on-yellow"],
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
	if expected_strict_exit == 0 and doctor_strict.stderr.strip():
		fail("parity doctor strict stderr must be empty on success")
	if expected_strict_exit == 0 and doctor_json_strict.stderr.strip():
		fail("parity doctor json strict stderr must be empty on success")
	assert_exact_nonempty_lines("parity doctor strict stdout", doctor_strict.stdout, doctor_plain_lines)
	doctor_strict_data = parse_doctor_plain_output(doctor_strict.stdout)
	if doctor_strict_data != doctor_plain_data:
		fail("parity doctor strict stdout mismatch with non-strict plain output")
	assert_exact_nonempty_lines("parity doctor json strict stdout", doctor_json_strict.stdout, doctor_json_lines)
	doctor_json_strict_data = parse_doctor_json_output(doctor_json_strict.stdout)
	if doctor_json_strict_data != doctor_json_data:
		fail("parity doctor json strict stdout mismatch with non-strict json output")
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
	if expected_yellow_strict_exit == 0 and doctor_yellow_strict.stderr.strip():
		fail("parity doctor strict-yellow stderr must be empty on success")
	if expected_yellow_strict_exit == 0 and doctor_json_yellow_strict.stderr.strip():
		fail("parity doctor json strict-yellow stderr must be empty on success")
	assert_exact_nonempty_lines("parity doctor strict-yellow stdout", doctor_yellow_strict.stdout, doctor_plain_lines)
	doctor_yellow_strict_data = parse_doctor_plain_output(doctor_yellow_strict.stdout)
	if doctor_yellow_strict_data != doctor_plain_data:
		fail("parity doctor strict-yellow stdout mismatch with non-strict plain output")
	assert_exact_nonempty_lines("parity doctor json strict-yellow stdout", doctor_json_yellow_strict.stdout, doctor_json_lines)
	doctor_json_yellow_strict_data = parse_doctor_json_output(doctor_json_yellow_strict.stdout)
	if doctor_json_yellow_strict_data != doctor_json_data:
		fail("parity doctor json strict-yellow stdout mismatch with non-strict json output")
	doctor_strict_stdout_lines = extract_nonempty_lines(doctor_strict.stdout)
	doctor_yellow_strict_stdout_lines = extract_nonempty_lines(doctor_yellow_strict.stdout)
	doctor_json_strict_stdout_lines = extract_nonempty_lines(doctor_json_strict.stdout)
	doctor_json_yellow_strict_stdout_lines = extract_nonempty_lines(doctor_json_yellow_strict.stdout)
	doctor_strict_stderr_lines = extract_nonempty_lines(doctor_strict.stderr)
	doctor_yellow_strict_stderr_lines = extract_nonempty_lines(doctor_yellow_strict.stderr)
	doctor_json_strict_stderr_lines = extract_nonempty_lines(doctor_json_strict.stderr)
	doctor_json_yellow_strict_stderr_lines = extract_nonempty_lines(doctor_json_yellow_strict.stderr)

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
	if expected_strict_exit == 0 and doctor_cmd_strict.stderr.strip():
		fail("parity doctor command strict stderr must be empty on success")
	assert_exact_nonempty_lines("parity doctor command strict stdout", doctor_cmd_strict.stdout, doctor_strict_stdout_lines)
	if parse_doctor_plain_output(doctor_cmd_strict.stdout) != doctor_strict_data:
		fail("parity doctor command strict stdout mismatch with direct strict plain output")
	if expected_strict_exit == 2 and "[parity-doctor] ERROR:" not in doctor_cmd_strict.stderr:
		fail("parity doctor command strict stderr missing parity-doctor error prefix")
	if expected_strict_exit == 2 and "A_critical backlog is non-zero" not in doctor_cmd_strict.stderr:
		fail("parity doctor command strict stderr missing critical backlog message")
	assert_exact_nonempty_lines("parity doctor command strict stderr", doctor_cmd_strict.stderr, doctor_strict_stderr_lines)
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
	if expected_yellow_strict_exit == 0 and doctor_cmd_strict_yellow.stderr.strip():
		fail("parity doctor command strict-yellow stderr must be empty on success")
	assert_exact_nonempty_lines(
		"parity doctor command strict-yellow stdout", doctor_cmd_strict_yellow.stdout, doctor_yellow_strict_stdout_lines
	)
	if parse_doctor_plain_output(doctor_cmd_strict_yellow.stdout) != doctor_yellow_strict_data:
		fail("parity doctor command strict-yellow stdout mismatch with direct strict-yellow plain output")
	if expected_yellow_strict_exit == 3 and "[parity-doctor] ERROR:" not in doctor_cmd_strict_yellow.stderr:
		fail("parity doctor command strict-yellow stderr missing parity-doctor error prefix")
	if expected_yellow_strict_exit == 3 and expected_health_reason_marker not in doctor_cmd_strict_yellow.stderr:
		fail("parity doctor command strict-yellow stderr missing health+reason message")
	assert_exact_nonempty_lines(
		"parity doctor command strict-yellow stderr",
		doctor_cmd_strict_yellow.stderr,
		doctor_yellow_strict_stderr_lines,
	)
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
	if expected_strict_exit == 0 and doctor_cmd_json_strict.stderr.strip():
		fail("parity doctor command json strict stderr must be empty on success")
	assert_exact_nonempty_lines(
		"parity doctor command json strict stdout", doctor_cmd_json_strict.stdout, doctor_json_strict_stdout_lines
	)
	if parse_doctor_json_output(doctor_cmd_json_strict.stdout) != doctor_json_strict_data:
		fail("parity doctor command json strict stdout mismatch with direct json strict output")
	if expected_strict_exit == 2 and "[parity-doctor] ERROR:" not in doctor_cmd_json_strict.stderr:
		fail("parity doctor command json strict stderr missing parity-doctor error prefix")
	if expected_strict_exit == 2 and "A_critical backlog is non-zero" not in doctor_cmd_json_strict.stderr:
		fail("parity doctor command json strict stderr missing critical backlog message")
	assert_exact_nonempty_lines(
		"parity doctor command json strict stderr",
		doctor_cmd_json_strict.stderr,
		doctor_json_strict_stderr_lines,
	)
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
	if expected_yellow_strict_exit == 0 and doctor_cmd_json_strict_yellow.stderr.strip():
		fail("parity doctor command json strict-yellow stderr must be empty on success")
	assert_exact_nonempty_lines(
		"parity doctor command json strict-yellow stdout",
		doctor_cmd_json_strict_yellow.stdout,
		doctor_json_yellow_strict_stdout_lines,
	)
	if parse_doctor_json_output(doctor_cmd_json_strict_yellow.stdout) != doctor_json_yellow_strict_data:
		fail("parity doctor command json strict-yellow stdout mismatch with direct json strict-yellow output")
	if expected_yellow_strict_exit == 3 and "[parity-doctor] ERROR:" not in doctor_cmd_json_strict_yellow.stderr:
		fail("parity doctor command json strict-yellow stderr missing parity-doctor error prefix")
	if expected_yellow_strict_exit == 3 and expected_health_reason_marker not in doctor_cmd_json_strict_yellow.stderr:
		fail("parity doctor command json strict-yellow stderr missing health+reason message")
	assert_exact_nonempty_lines(
		"parity doctor command json strict-yellow stderr",
		doctor_cmd_json_strict_yellow.stderr,
		doctor_json_yellow_strict_stderr_lines,
	)
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
