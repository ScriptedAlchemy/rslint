#!/usr/bin/env python3
"""
Generate a markdown implementation worklist from parity tracker JSON.

Input:
  - /workspace/typescript-eslint-rule-parity-tracker.json

Output:
  - /workspace/typescript-eslint-rule-parity-worklist.md
"""

from __future__ import annotations

import json
import pathlib
from collections import defaultdict


PHASE_ORDER = ["A_critical", "B_high", "C_medium", "D_low", "aligned"]


def parse_flags(raw: str) -> list[str]:
	if not raw:
		return []
	return [f for f in raw.split("|") if f]


def summarize_reason(row: dict) -> str:
	flags = set(parse_flags(row.get("flags", "")))
	reasons: list[str] = []

	if "missing_go_test" in flags:
		reasons.append("missing Go tests")
	if "missing_js_file" in flags:
		reasons.append("missing JS parity file")
	if "missing_go_implementation" in flags:
		reasons.append("missing Go implementation")
	if "severe_invalid_gap" in flags or "moderate_invalid_gap" in flags:
		reasons.append(f"invalid coverage {row.get('js_errs_local', 0)}/{row.get('js_errs_upstream', 0)}")
	if "severe_js_size_gap" in flags or "moderate_js_size_gap" in flags:
		reasons.append(f"JS test size {row.get('js_lines_local', 0)}/{row.get('js_lines_upstream', 0)}")
	if "fix_gap_suspected" in flags:
		reasons.append(f"fix output parity {row.get('js_outputs_local', 0)}/{row.get('js_outputs_upstream', 0)}")
	if "suggestion_gap_suspected" in flags:
		reasons.append(f"suggestion parity {row.get('js_suggestions_local', 0)}/{row.get('js_suggestions_upstream', 0)}")
	if "go_skips" in flags:
		reasons.append(f"Go Skip:true x{row.get('go_skip_count', 0)}")
	if "todo_markers" in flags:
		reasons.append(f"TODO/FIXME x{row.get('todo_fixme_count', 0)}")
	if "extra_js_skips" in flags:
		reasons.append(f"extra JS skips Δ{row.get('js_skip_delta', 0)}")
	if "local_only_rule" in flags:
		reasons.append("local-only rule divergence")

	return "; ".join(reasons) if reasons else "no action needed"


def main() -> None:
	root = pathlib.Path("/workspace")
	input_path = root / "typescript-eslint-rule-parity-tracker.json"
	output_path = root / "typescript-eslint-rule-parity-worklist.md"

	rows = json.loads(input_path.read_text())
	by_phase = defaultdict(list)
	for row in rows:
		by_phase[row.get("recommended_phase", "D_low")].append(row)

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Rule Parity Worklist")
	lines.append("")
	lines.append("Generated from `typescript-eslint-rule-parity-tracker.json`.")
	lines.append("")
	lines.append("Usage:")
	lines.append("1. Work top-down by phase.")
	lines.append("2. Inside a phase, work by descending `priority_score`.")
	lines.append("3. Mark checklist items complete as parity lands.")
	lines.append("")

	for phase in PHASE_ORDER:
		phase_rows = sorted(by_phase.get(phase, []), key=lambda r: (-r.get("priority_score", 0), r.get("rule", "")))
		if not phase_rows:
			continue

		lines.append(f"## {phase} ({len(phase_rows)} rules)")
		lines.append("")

		if phase == "aligned":
			lines.append("_No known action required based on current parity signals._")
			lines.append("")
			continue

		for row in phase_rows:
			rule = row["rule"]
			score = row.get("priority_score", 0)
			reason = summarize_reason(row)
			flags = row.get("flags", "")
			lines.append(f"- [ ] `{rule}` (score: {score})")
			lines.append(f"  - Why: {reason}")
			lines.append(f"  - Flags: `{flags}`")

			up_rule = row.get("upstream_rule_file", "")
			if up_rule:
				lines.append(f"  - Upstream: `{up_rule}`")

			go_impl = row.get("local_go_impl_files", "")
			go_test = row.get("local_go_test_files", "")
			js_test = row.get("local_js_test_files", "")
			missing_js = row.get("missing_js_files", "")
			if go_impl:
				lines.append(f"  - Go impl: `{go_impl}`")
			if go_test:
				lines.append(f"  - Go tests: `{go_test}`")
			if js_test:
				lines.append(f"  - JS tests: `{js_test}`")
			if missing_js:
				lines.append(f"  - Missing JS test file(s): `{missing_js}`")

		lines.append("")

	lines.append("## Per-rule verification checklist")
	lines.append("")
	lines.append("For each rule completed:")
	lines.append("- `go test -count=1 ./internal/plugins/typescript/rules/<rule_dir>`")
	lines.append("- `cd packages/rslint && pnpm run build:bin`")
	lines.append("- `cd packages/rslint-test-tools && npx rstest run --testTimeout=10000 <rule-name>`")
	lines.append("- Confirm no unintended new `skip` markers were introduced.")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
