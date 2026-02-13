#!/usr/bin/env python3
"""
Generate top-priority parity rule list markdown from tracker JSON.

Outputs:
  - /workspace/typescript-eslint-rule-parity-top.md
"""

from __future__ import annotations

import json
import pathlib


def parse_flags(raw: str) -> list[str]:
	if not raw:
		return []
	return [flag for flag in raw.split("|") if flag]


def summarize(row: dict) -> str:
	flags = set(parse_flags(row.get("flags", "")))
	parts: list[str] = []
	if "missing_go_test" in flags:
		parts.append("missing Go tests")
	if "missing_js_file" in flags:
		parts.append("missing JS parity test file")
	if "severe_invalid_gap" in flags or "moderate_invalid_gap" in flags:
		parts.append(f"errors {row.get('js_errs_local', 0)}/{row.get('js_errs_upstream', 0)}")
	if "severe_js_size_gap" in flags or "moderate_js_size_gap" in flags:
		parts.append(f"size {row.get('js_lines_local', 0)}/{row.get('js_lines_upstream', 0)}")
	if "fix_gap_suspected" in flags:
		parts.append(f"fix {row.get('js_outputs_local', 0)}/{row.get('js_outputs_upstream', 0)}")
	if "suggestion_gap_suspected" in flags:
		parts.append(f"suggestions {row.get('js_suggestions_local', 0)}/{row.get('js_suggestions_upstream', 0)}")
	if "go_skips" in flags:
		parts.append(f"go-skips {row.get('go_skip_count', 0)}")
	if "todo_markers" in flags:
		parts.append(f"todo {row.get('todo_fixme_count', 0)}")
	return "; ".join(parts) if parts else "review parity state"


def main() -> None:
	root = pathlib.Path("/workspace")
	tracker_path = root / "typescript-eslint-rule-parity-tracker.json"
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	output_path = root / "typescript-eslint-rule-parity-top.md"

	rows = json.loads(tracker_path.read_text())
	metadata = json.loads(metadata_path.read_text())
	top_rows = sorted(
		[row for row in rows if int(row.get("priority_score", 0)) > 0],
		key=lambda row: (-int(row.get("priority_score", 0)), row.get("rule", "")),
	)[:25]

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Parity Top Priorities")
	lines.append("")
	lines.append(f"_Generated: {metadata.get('generated_at_utc', 'unknown')}_")
	lines.append("")
	lines.append(f"- Upstream ref: `{metadata.get('upstream_ref_requested', 'unknown')}`")
	lines.append(f"- Upstream commit: `{metadata.get('upstream_commit', 'unknown')}`")
	lines.append("")
	lines.append("| Rank | Rule | Score | Phase | Why |")
	lines.append("|---:|---|---:|---|---|")
	for idx, row in enumerate(top_rows, 1):
		lines.append(
			f"| {idx} | `{row.get('rule','')}` | {row.get('priority_score', 0)} | `{row.get('recommended_phase','')}` | {summarize(row)} |"
		)
	lines.append("")
	lines.append("Use this list for immediate implementation focus; consult the full tracker for complete details.")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
