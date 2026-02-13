#!/usr/bin/env python3
"""
Generate a concise parity dashboard markdown from tracker JSON.

Input:
  - /workspace/typescript-eslint-rule-parity-tracker.json

Output:
  - /workspace/typescript-eslint-rule-parity-summary.md
"""

from __future__ import annotations

import collections
import json
import pathlib


def parse_flags(raw: str) -> list[str]:
	if not raw:
		return []
	return [f for f in raw.split("|") if f]


def main() -> None:
	root = pathlib.Path("/workspace")
	input_path = root / "typescript-eslint-rule-parity-tracker.json"
	output_path = root / "typescript-eslint-rule-parity-summary.md"

	rows: list[dict] = json.loads(input_path.read_text())
	total = len(rows)
	flagged = [r for r in rows if r.get("priority_score", 0) > 0]
	aligned = [r for r in rows if r.get("priority_score", 0) == 0]

	phase_counts = collections.Counter(r.get("recommended_phase", "unknown") for r in rows)
	flag_counts = collections.Counter()
	for row in flagged:
		flag_counts.update(parse_flags(row.get("flags", "")))

	top_priority = sorted(flagged, key=lambda r: (-r.get("priority_score", 0), r.get("rule", "")))[:15]

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Rule Parity Summary Dashboard")
	lines.append("")
	lines.append("Generated from `typescript-eslint-rule-parity-tracker.json`.")
	lines.append("")
	lines.append("## Headline metrics")
	lines.append(f"- Total tracked rules: **{total}**")
	lines.append(f"- Rules needing correction (`priority_score > 0`): **{len(flagged)}**")
	lines.append(f"- Rules currently aligned (`priority_score = 0`): **{len(aligned)}**")
	lines.append("")

	lines.append("## Phase distribution")
	lines.append("| Phase | Rules |")
	lines.append("|---|---:|")
	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		lines.append(f"| `{phase}` | {phase_counts.get(phase, 0)} |")
	lines.append("")

	lines.append("## Most common parity flags")
	lines.append("| Flag | Rules |")
	lines.append("|---|---:|")
	for flag, count in flag_counts.most_common(15):
		lines.append(f"| `{flag}` | {count} |")
	lines.append("")

	lines.append("## Top 15 highest priority rules")
	lines.append("| Rank | Rule | Score | Flags |")
	lines.append("|---:|---|---:|---|")
	for idx, row in enumerate(top_priority, 1):
		lines.append(
			f"| {idx} | `{row.get('rule','')}` | {row.get('priority_score', 0)} | `{row.get('flags', '')}` |"
		)
	lines.append("")

	lines.append("## Suggested execution order")
	lines.append("1. Complete all `A_critical` rules.")
	lines.append("2. Burn down `B_high` rules with largest test-coverage deficits.")
	lines.append("3. Resolve `C_medium` skip/TODO debt and fix/suggestion parity gaps.")
	lines.append("4. Close `D_low` tail items and reassess score distribution.")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
