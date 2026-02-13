#!/usr/bin/env python3
"""
Generate a GitHub issue body markdown for a parity phase.

Example:
  python3 scripts/generate_ts_eslint_parity_issue_body.py --phase A_critical
"""

from __future__ import annotations

import argparse
import pathlib


VALID_PHASES = {"A_critical", "B_high", "C_medium", "D_low"}


def main() -> None:
	parser = argparse.ArgumentParser(description="Generate parity tracking issue body markdown.")
	parser.add_argument("--phase", required=True, choices=sorted(VALID_PHASES))
	parser.add_argument(
		"--tasklist",
		default="",
		help="Path to tasklist markdown. Defaults to /workspace/typescript-eslint-rule-parity-tasklist-<phase>.md",
	)
	parser.add_argument(
		"--output",
		default="",
		help="Output issue body path. Defaults to /workspace/typescript-eslint-rule-parity-issue-body-<phase>.md",
	)
	args = parser.parse_args()

	tasklist_path = (
		pathlib.Path(args.tasklist)
		if args.tasklist
		else pathlib.Path(f"/workspace/typescript-eslint-rule-parity-tasklist-{args.phase}.md")
	)
	if not tasklist_path.exists():
		raise FileNotFoundError(f"tasklist not found: {tasklist_path}")
	tasklist_text = tasklist_path.read_text().strip()

	priority = args.phase.split("_", 1)[1]
	output_path = (
		pathlib.Path(args.output)
		if args.output
		else pathlib.Path(f"/workspace/typescript-eslint-rule-parity-issue-body-{args.phase}.md")
	)

	lines: list[str] = []
	lines.append(f"## TypeScript-ESLint Parity — {args.phase}")
	lines.append("")
	lines.append("### Context")
	lines.append("- Source artifacts: parity tracker/worklist/issue-plan generated from toolkit.")
	lines.append("- Goal: reduce parity gaps for this phase and refresh artifacts.")
	lines.append("")
	lines.append("### Labels")
	lines.append(f"- `area:typescript-eslint-parity`")
	lines.append("- `kind:parity`")
	lines.append(f"- `priority:{priority}`")
	lines.append("")
	lines.append("### Tasklist")
	lines.append("")
	lines.append(tasklist_text)
	lines.append("")
	lines.append("### Acceptance criteria")
	lines.append("- [ ] Go tests pass for touched rules.")
	lines.append("- [ ] JS parity tests pass for touched rules.")
	lines.append("- [ ] Parity artifacts regenerated (`pnpm parity:ts-eslint`).")
	lines.append("- [ ] Consistency checks pass (`pnpm parity:ts-eslint:check`).")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
