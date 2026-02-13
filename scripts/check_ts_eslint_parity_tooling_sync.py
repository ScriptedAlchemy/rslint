#!/usr/bin/env python3
"""
Validate parity toolkit command/docs synchronization.

Checks:
1. Required package.json parity scripts exist.
2. Core parity docs mention those commands.
3. Referenced helper scripts exist on disk.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys


def fail(msg: str) -> None:
	print(f"[parity-tooling-check] ERROR: {msg}")
	sys.exit(1)


def main() -> None:
	root = pathlib.Path("/workspace")
	package_json = root / "package.json"
	guide_md = root / "typescript-eslint-rule-parity-guide.md"
	report_md = root / "typescript-eslint-rule-parity-report.md"
	index_md = root / "typescript-eslint-rule-parity-index.md"
	commands_md = root / "typescript-eslint-rule-parity-commands.md"
	readme_md = root / "README.md"
	contributing_md = root / "CONTRIBUTING.md"
	workflow_yml = root / ".github/workflows/parity-artifacts-check.yml"

	pkg = json.loads(package_json.read_text())
	scripts = pkg.get("scripts", {})
	actual_parity_scripts = sorted(name for name in scripts if name.startswith("parity:ts-eslint"))

	expected_scripts = {
		"parity:ts-eslint": "refresh-ts-eslint-parity-artifacts.sh",
		"parity:ts-eslint:check": "check_ts_eslint_parity_artifacts.py",
		"parity:ts-eslint:check:all": "check_ts_eslint_parity_all.sh",
		"parity:ts-eslint:check:strict": "check_ts_eslint_parity_all.sh && python3 scripts/generate_ts_eslint_parity_doctor.py --fail-on-critical",
		"parity:ts-eslint:check:tooling": "check_ts_eslint_parity_tooling_sync.py",
		"parity:ts-eslint:commands": "generate_ts_eslint_parity_commands.py",
		"parity:ts-eslint:diff": "compare_ts_eslint_parity_trackers.py",
		"parity:ts-eslint:diff:json": "compare_ts_eslint_parity_trackers.py --output-json /workspace/typescript-eslint-rule-parity-diff.json",
		"parity:ts-eslint:tasklist": "generate_ts_eslint_parity_issue_tasklist.py",
		"parity:ts-eslint:tasklist:all": "generate_ts_eslint_parity_tasklists_all.sh",
		"parity:ts-eslint:issue-body": "generate_ts_eslint_parity_issue_body.py",
		"parity:ts-eslint:issue-body:all": "generate_ts_eslint_parity_issue_bodies_all.sh",
		"parity:ts-eslint:badges": "generate_ts_eslint_parity_badges.py",
		"parity:ts-eslint:status": "generate_ts_eslint_parity_status.py",
		"parity:ts-eslint:ci-summary": "generate_ts_eslint_parity_ci_summary.py",
		"parity:ts-eslint:ci-summary:json": "generate_ts_eslint_parity_ci_summary.py --json",
		"parity:ts-eslint:doctor": "generate_ts_eslint_parity_doctor.py",
		"parity:ts-eslint:doctor:markdown": "generate_ts_eslint_parity_doctor.py --markdown",
		"parity:ts-eslint:doctor:json": "generate_ts_eslint_parity_doctor.py --json",
		"parity:ts-eslint:doctor:json:strict": "generate_ts_eslint_parity_doctor.py --json --fail-on-critical",
		"parity:ts-eslint:doctor:strict": "generate_ts_eslint_parity_doctor.py --fail-on-critical",
		"parity:ts-eslint:top": "generate_ts_eslint_parity_top.py",
		"parity:ts-eslint:manifest": "generate_ts_eslint_parity_manifest.py",
		"parity:ts-eslint:rebuild-metadata": "rebuild_ts_eslint_parity_from_metadata.sh",
		"parity:ts-eslint:verify-clean": "verify_ts_eslint_parity_clean.sh",
	}
	expected_parity_scripts = sorted(expected_scripts.keys())
	if actual_parity_scripts != expected_parity_scripts:
		fail(
			"parity script inventory mismatch: "
			f"expected={expected_parity_scripts} actual={actual_parity_scripts}"
		)

	for script_name, expected_token in expected_scripts.items():
		value = scripts.get(script_name)
		if not value:
			fail(f"missing package script: {script_name}")
		if expected_token not in value:
			fail(f"package script `{script_name}` does not reference `{expected_token}`")

	command_tokens = [f"pnpm {name}" for name in expected_scripts]
	documents = {
		"guide": guide_md.read_text(),
		"report": report_md.read_text(),
		"index": index_md.read_text(),
	}
	for token in command_tokens:
		for doc_name, text in documents.items():
			if token not in text:
				fail(f"`{token}` missing in parity {doc_name} documentation")

	required_artifacts = [
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
		"typescript-eslint-rule-parity-manifest.json",
		"typescript-eslint-rule-parity-index.md",
		"typescript-eslint-rule-parity-issue-plan.md",
	]
	for artifact in required_artifacts:
		for doc_name in ("guide", "index"):
			text = documents[doc_name]
			if artifact not in text:
				fail(f"`{artifact}` missing in parity {doc_name} documentation")

	invalid_command_examples = [
		"pnpm parity:ts-eslint:diff -- --base-ref",
		"pnpm parity:ts-eslint:diff:json -- --base-ref",
	]
	for invalid in invalid_command_examples:
		for doc_name, text in documents.items():
			if invalid in text:
				fail(f"invalid parity command example `{invalid}` found in {doc_name} documentation")

	# Ensure contributor-facing docs mention essential parity commands
	readme_text = readme_md.read_text() if readme_md.exists() else ""
	contributing_text = contributing_md.read_text() if contributing_md.exists() else ""
	if not readme_text:
		fail("missing or empty README.md")
	if not contributing_text:
		fail("missing or empty CONTRIBUTING.md")

	required_readme_tokens = [
		"TypeScript-ESLint parity toolkit",
		"typescript-eslint-rule-parity-guide.md",
		"pnpm parity:ts-eslint",
		"pnpm parity:ts-eslint:check:all",
		"pnpm parity:ts-eslint:check:strict",
	]
	for token in required_readme_tokens:
		if token not in readme_text:
			fail(f"`{token}` missing in README parity section")

	required_contributing_tokens = [
		"Maintain TypeScript-ESLint parity artifacts",
		"typescript-eslint-rule-parity-guide.md",
		"pnpm parity:ts-eslint",
		"pnpm parity:ts-eslint:check:all",
		"pnpm parity:ts-eslint:check:strict",
	]
	for token in required_contributing_tokens:
		if token not in contributing_text:
			fail(f"`{token}` missing in CONTRIBUTING parity section")

	commands_text = commands_md.read_text() if commands_md.exists() else ""
	if not commands_text:
		fail("missing or empty parity commands reference markdown")

	command_rows = {}
	for line in commands_text.splitlines():
		match = re.match(r"^\| `pnpm ([^`]+)` \| (.*) \| `([^`]*)` \|$", line)
		if not match:
			continue
		command_rows[match.group(1)] = {
			"description": match.group(2),
			"backing_script": match.group(3),
		}

	if sorted(command_rows.keys()) != expected_parity_scripts:
		fail(
			"parity commands reference inventory mismatch: "
			f"expected={expected_parity_scripts} actual={sorted(command_rows.keys())}"
		)

	for script_name, expected_token in expected_scripts.items():
		cmd_token = f"pnpm {script_name}"
		if cmd_token not in commands_text:
			fail(f"`{cmd_token}` missing in parity commands reference")
		if expected_token not in commands_text:
			fail(f"backing token `{expected_token}` missing in parity commands reference")
		if f"| `pnpm {script_name}` | No description provided." in commands_text:
			fail(f"`pnpm {script_name}` is missing command description in parity commands reference")
		row = command_rows.get(script_name)
		if not row:
			fail(f"`pnpm {script_name}` missing command row in parity commands reference")
		if row["backing_script"] != scripts.get(script_name, ""):
			fail(
				f"`pnpm {script_name}` backing script mismatch in parity commands reference: "
				f"expected=`{scripts.get(script_name, '')}` actual=`{row['backing_script']}`"
			)

	# Ensure all referenced helper scripts exist
	required_scripts = {
		"scripts/refresh-ts-eslint-parity-artifacts.sh",
		"scripts/check_ts_eslint_parity_artifacts.py",
		"scripts/check_ts_eslint_parity_all.sh",
		"scripts/check_ts_eslint_parity_tooling_sync.py",
		"scripts/generate_ts_eslint_parity_commands.py",
		"scripts/compare_ts_eslint_parity_trackers.py",
		"scripts/generate_ts_eslint_parity_issue_tasklist.py",
		"scripts/generate_ts_eslint_parity_tasklists_all.sh",
		"scripts/generate_ts_eslint_parity_issue_body.py",
		"scripts/generate_ts_eslint_parity_issue_bodies_all.sh",
		"scripts/generate_ts_eslint_parity_badges.py",
		"scripts/generate_ts_eslint_parity_status.py",
		"scripts/generate_ts_eslint_parity_ci_summary.py",
		"scripts/generate_ts_eslint_parity_doctor.py",
		"scripts/generate_ts_eslint_parity_top.py",
		"scripts/generate_ts_eslint_parity_manifest.py",
		"scripts/rebuild_ts_eslint_parity_from_metadata.sh",
		"scripts/verify_ts_eslint_parity_clean.sh",
	}
	for rel in required_scripts:
		if not (root / rel).exists():
			fail(f"missing required parity helper script: {rel}")

	# Ensure CI workflow remains wired to parity checks/artifacts
	if not workflow_yml.exists():
		fail("missing parity CI workflow: .github/workflows/parity-artifacts-check.yml")

	workflow_text = workflow_yml.read_text()
	required_workflow_tokens = [
		"python3 scripts/check_ts_eslint_parity_artifacts.py",
		"python3 scripts/check_ts_eslint_parity_tooling_sync.py",
		"bash scripts/verify_ts_eslint_parity_clean.sh",
		"--output-json \"typescript-eslint-rule-parity-diff.json\"",
		"python3 scripts/generate_ts_eslint_parity_ci_summary.py >> \"$GITHUB_STEP_SUMMARY\"",
		"python3 scripts/generate_ts_eslint_parity_doctor.py --markdown >> \"$GITHUB_STEP_SUMMARY\"",
		"name: typescript-eslint-parity-diff",
		"name: typescript-eslint-parity-artifacts",
	]
	for token in required_workflow_tokens:
		if token not in workflow_text:
			fail(f"missing workflow wiring token: {token}")

	required_bundle_artifacts = [
		"typescript-eslint-rule-parity-report.md",
		"typescript-eslint-rule-parity-guide.md",
		"typescript-eslint-rule-parity-index.md",
		"typescript-eslint-rule-parity-summary.md",
		"typescript-eslint-rule-parity-top.md",
		"typescript-eslint-rule-parity-worklist.md",
		"typescript-eslint-rule-parity-issue-plan.md",
		"typescript-eslint-rule-parity-tracker.csv",
		"typescript-eslint-rule-parity-tracker.json",
		"typescript-eslint-rule-parity-metadata.json",
		"typescript-eslint-rule-parity-badges.json",
		"typescript-eslint-rule-parity-status.json",
		"typescript-eslint-rule-parity-commands.md",
		"typescript-eslint-rule-parity-diff.md",
		"typescript-eslint-rule-parity-diff.json",
		"typescript-eslint-rule-parity-manifest.json",
		"typescript-eslint-rule-parity-tasklist-A_critical.md",
		"typescript-eslint-rule-parity-tasklist-B_high.md",
		"typescript-eslint-rule-parity-tasklist-C_medium.md",
		"typescript-eslint-rule-parity-tasklist-D_low.md",
		"typescript-eslint-rule-parity-issue-body-A_critical.md",
		"typescript-eslint-rule-parity-issue-body-B_high.md",
		"typescript-eslint-rule-parity-issue-body-C_medium.md",
		"typescript-eslint-rule-parity-issue-body-D_low.md",
	]
	for artifact in required_bundle_artifacts:
		if artifact not in workflow_text:
			fail(f"missing workflow uploaded artifact path: {artifact}")

	print("[parity-tooling-check] OK: parity commands/docs/scripts are synchronized.")


if __name__ == "__main__":
	main()
