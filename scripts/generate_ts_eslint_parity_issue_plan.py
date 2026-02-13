#!/usr/bin/env python3
"""
Generate a GitHub-issue-friendly parity execution plan from tracker JSON.

Input:
  - /workspace/typescript-eslint-rule-parity-tracker.json

Output:
  - /workspace/typescript-eslint-rule-parity-issue-plan.md
"""

from __future__ import annotations

import json
import pathlib
from collections import defaultdict


PHASE_ORDER = ["A_critical", "B_high", "C_medium", "D_low"]


def parse_flags(raw: str) -> list[str]:
	if not raw:
		return []
	return [flag for flag in raw.split("|") if flag]


def summarize_rule(row: dict) -> str:
	flags = set(parse_flags(row.get("flags", "")))
	parts: list[str] = []

	if "missing_go_test" in flags:
		parts.append("add missing Go tests")
	if "missing_js_file" in flags:
		parts.append("add missing JS parity test files")
	if "severe_invalid_gap" in flags or "moderate_invalid_gap" in flags:
		parts.append(f"restore invalid-case coverage ({row.get('js_errs_local', 0)}/{row.get('js_errs_upstream', 0)})")
	if "severe_js_size_gap" in flags or "moderate_js_size_gap" in flags:
		parts.append(f"backfill upstream test scenarios ({row.get('js_lines_local', 0)}/{row.get('js_lines_upstream', 0)})")
	if "fix_gap_suspected" in flags:
		parts.append(f"verify/restore autofix parity ({row.get('js_outputs_local', 0)}/{row.get('js_outputs_upstream', 0)})")
	if "suggestion_gap_suspected" in flags:
		parts.append(
			f"verify/restore suggestion parity ({row.get('js_suggestions_local', 0)}/{row.get('js_suggestions_upstream', 0)})"
		)
	if "go_skips" in flags:
		parts.append(f"remove/resolve Go Skip:true cases ({row.get('go_skip_count', 0)})")
	if "todo_markers" in flags:
		parts.append(f"close TODO/FIXME parity debt ({row.get('todo_fixme_count', 0)})")
	if "extra_js_skips" in flags:
		parts.append(f"remove/justify extra JS skip markers (delta {row.get('js_skip_delta', 0)})")
	if "local_only_rule" in flags:
		parts.append("decide local-only rule policy")

	if not parts:
		return "review parity status"
	return "; ".join(parts)


def main() -> None:
	root = pathlib.Path("/workspace")
	tracker_path = root / "typescript-eslint-rule-parity-tracker.json"
	output_path = root / "typescript-eslint-rule-parity-issue-plan.md"

	rows = json.loads(tracker_path.read_text())
	grouped = defaultdict(list)
	for row in rows:
		phase = row.get("recommended_phase", "")
		if phase in PHASE_ORDER:
			grouped[phase].append(row)

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Parity Issue Plan")
	lines.append("")
	lines.append("This plan is generated from `typescript-eslint-rule-parity-tracker.json`.")
	lines.append("Use it to create and track GitHub issues by execution phase.")
	lines.append("")
	lines.append("## Suggested labels")
	lines.append("")
	lines.append("- `area:typescript-eslint-parity`")
	lines.append("- `kind:parity`")
	lines.append("- `kind:test` (when coverage/test parity is the main gap)")
	lines.append("- `kind:fixer` (for autofix/suggestion parity)")
	lines.append("- `priority:critical|high|medium|low`")
	lines.append("")

	for phase in PHASE_ORDER:
		phase_rows = sorted(grouped.get(phase, []), key=lambda r: (-int(r.get("priority_score", 0)), r.get("rule", "")))
		priority = phase.split("_", 1)[1]
		lines.append(f"## {phase} ({len(phase_rows)} rules)")
		lines.append("")
		if not phase_rows:
			lines.append("_No rules in this phase._")
			lines.append("")
			continue

		lines.append(f"Suggested issue title: `Parity: complete {phase} rule backlog`")
		lines.append("")
		lines.append("Checklist:")
		lines.append("")
		for row in phase_rows:
			rule = row.get("rule", "")
			score = row.get("priority_score", 0)
			detail = summarize_rule(row)
			lines.append(f"- [ ] `{rule}` (score {score}) — {detail}")
		lines.append("")
		lines.append("Issue notes template:")
		lines.append("")
		lines.append("```md")
		lines.append(f"Labels: area:typescript-eslint-parity, kind:parity, priority:{priority}")
		lines.append("")
		lines.append("Acceptance criteria:")
		lines.append("- Go tests pass for touched rules.")
		lines.append("- JS parity tests pass for touched rules.")
		lines.append("- Parity artifacts are regenerated.")
		lines.append("- `pnpm parity:ts-eslint:check` passes.")
		lines.append("```")
		lines.append("")

	lines.append("## Post-phase housekeeping")
	lines.append("")
	lines.append("After closing a phase:")
	lines.append("1. Run `pnpm parity:ts-eslint` to refresh all artifacts.")
	lines.append("2. Run `pnpm parity:ts-eslint:check`.")
	lines.append("3. Confirm phase counts and top-priority ordering changed as expected.")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
