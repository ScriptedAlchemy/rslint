#!/usr/bin/env python3
"""
Generate a GitHub tasklist snippet for a parity phase.

Example:
  python3 scripts/generate_ts_eslint_parity_issue_tasklist.py --phase A_critical
"""

from __future__ import annotations

import argparse
import json
import pathlib


PHASES = {"A_critical", "B_high", "C_medium", "D_low"}


def parse_flags(raw: str) -> list[str]:
	if not raw:
		return []
	return [f for f in raw.split("|") if f]


def summarize_reason(row: dict) -> str:
	flags = set(parse_flags(row.get("flags", "")))
	parts: list[str] = []
	if "missing_go_test" in flags:
		parts.append("missing Go tests")
	if "missing_js_file" in flags:
		parts.append("missing JS test files")
	if "severe_invalid_gap" in flags or "moderate_invalid_gap" in flags:
		parts.append(f"errors {row.get('js_errs_local', 0)}/{row.get('js_errs_upstream', 0)}")
	if "severe_js_size_gap" in flags or "moderate_js_size_gap" in flags:
		parts.append(f"size {row.get('js_lines_local', 0)}/{row.get('js_lines_upstream', 0)}")
	if "fix_gap_suspected" in flags:
		parts.append(f"fix {row.get('js_outputs_local', 0)}/{row.get('js_outputs_upstream', 0)}")
	if "suggestion_gap_suspected" in flags:
		parts.append(f"suggestions {row.get('js_suggestions_local', 0)}/{row.get('js_suggestions_upstream', 0)}")
	if "go_skips" in flags:
		parts.append(f"go-skip {row.get('go_skip_count', 0)}")
	if "todo_markers" in flags:
		parts.append(f"todo {row.get('todo_fixme_count', 0)}")
	if "extra_js_skips" in flags:
		parts.append(f"js-skip-delta {row.get('js_skip_delta', 0)}")
	return ", ".join(parts) if parts else "review parity"


def main() -> None:
	parser = argparse.ArgumentParser(description="Generate parity issue tasklist snippet.")
	parser.add_argument("--phase", required=True, choices=sorted(PHASES))
	parser.add_argument(
		"--tracker",
		default="/workspace/typescript-eslint-rule-parity-tracker.json",
		help="Path to tracker JSON",
	)
	parser.add_argument(
		"--output",
		default="",
		help="Output path. Defaults to /workspace/typescript-eslint-rule-parity-tasklist-<phase>.md",
	)
	args = parser.parse_args()

	tracker_path = pathlib.Path(args.tracker)
	rows = json.loads(tracker_path.read_text())
	phase_rows = [row for row in rows if row.get("recommended_phase") == args.phase]
	phase_rows = sorted(phase_rows, key=lambda r: (-int(r.get("priority_score", 0)), r.get("rule", "")))

	lines: list[str] = []
	lines.append("```[tasklist]")
	lines.append(f"### {args.phase} parity tasks")
	for row in phase_rows:
		rule = row.get("rule", "")
		score = row.get("priority_score", 0)
		reason = summarize_reason(row)
		lines.append(f"- [ ] {rule} (score {score}) — {reason}")
	lines.append("```")
	lines.append("")

	output_path = (
		pathlib.Path(args.output)
		if args.output
		else pathlib.Path(f"/workspace/typescript-eslint-rule-parity-tasklist-{args.phase}.md")
	)
	output_path.write_text("\n".join(lines))
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
