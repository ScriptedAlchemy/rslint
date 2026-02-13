#!/usr/bin/env python3
"""
Generate a central index page for parity artifacts.

Inputs:
  - /workspace/typescript-eslint-rule-parity-metadata.json

Output:
  - /workspace/typescript-eslint-rule-parity-index.md
"""

from __future__ import annotations

import json
import pathlib


def main() -> None:
	root = pathlib.Path("/workspace")
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	output_path = root / "typescript-eslint-rule-parity-index.md"

	metadata = json.loads(metadata_path.read_text())
	summary = metadata.get("summary", {})
	phase_counts = metadata.get("phase_counts", {})
	upstream_ref = metadata.get("upstream_ref_requested", "main")
	upstream_commit = metadata.get("upstream_commit", "unknown")
	generated_at = metadata.get("generated_at_utc", "unknown")

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Parity Artifact Index")
	lines.append("")
	lines.append(f"_Generated: {generated_at}_")
	lines.append("")
	lines.append("## Snapshot")
	lines.append(f"- Upstream ref requested: `{upstream_ref}`")
	lines.append(f"- Upstream commit resolved: `{upstream_commit}`")
	lines.append(f"- Total rules: **{summary.get('total_rules', 0)}**")
	lines.append(f"- Flagged rules: **{summary.get('flagged_rules', 0)}**")
	lines.append(f"- Aligned rules: **{summary.get('aligned_rules', 0)}**")
	lines.append("")

	lines.append("## Phase distribution")
	lines.append("| Phase | Rules |")
	lines.append("|---|---:|")
	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		lines.append(f"| `{phase}` | {phase_counts.get(phase, 0)} |")
	lines.append("")

	lines.append("## Artifacts")
	lines.append("- `typescript-eslint-rule-parity-index.md` — this central navigation page.")
	lines.append("- `typescript-eslint-rule-parity-report.md` — detailed narrative audit.")
	lines.append("- `typescript-eslint-rule-parity-tracker.csv` — tabular machine-readable dataset.")
	lines.append("- `typescript-eslint-rule-parity-tracker.json` — JSON machine-readable dataset.")
	lines.append("- `typescript-eslint-rule-parity-worklist.md` — phase-based execution checklist.")
	lines.append("- `typescript-eslint-rule-parity-top.md` — ranked top-25 immediate priorities.")
	lines.append("- `typescript-eslint-rule-parity-commands.md` — generated parity command reference.")
	lines.append("- `typescript-eslint-rule-parity-summary.md` — concise dashboard.")
	lines.append("- `typescript-eslint-rule-parity-metadata.json` — run metadata and counters.")
	lines.append("- `typescript-eslint-rule-parity-badges.json` — badge-friendly metrics JSON (including health + badge color).")
	lines.append("- `typescript-eslint-rule-parity-status.json` — compact health/status summary JSON.")
	lines.append("- `typescript-eslint-rule-parity-manifest.json` — deterministic checksums for parity artifacts.")
	lines.append("- `typescript-eslint-rule-parity-issue-plan.md` — issue-friendly phase plans.")
	lines.append("- `typescript-eslint-rule-parity-diff.md` — optional snapshot comparison output.")
	lines.append("- `typescript-eslint-rule-parity-diff.json` — optional machine-readable diff output.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-A_critical.md` — tasklist snippet for A_critical.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-B_high.md` — tasklist snippet for B_high.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-C_medium.md` — tasklist snippet for C_medium.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-D_low.md` — tasklist snippet for D_low.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-<phase>.md` — generic tasklist naming convention.")
	lines.append("- `typescript-eslint-rule-parity-issue-body-A_critical.md` — issue body draft for A_critical.")
	lines.append("- `typescript-eslint-rule-parity-issue-body-B_high.md` — issue body draft for B_high.")
	lines.append("- `typescript-eslint-rule-parity-issue-body-C_medium.md` — issue body draft for C_medium.")
	lines.append("- `typescript-eslint-rule-parity-issue-body-D_low.md` — issue body draft for D_low.")
	lines.append("- `typescript-eslint-rule-parity-issue-body-<phase>.md` — optional full issue body draft.")
	lines.append("- `typescript-eslint-rule-parity-guide.md` — toolkit usage guide.")
	lines.append("")

	lines.append("## Commands")
	lines.append("```bash")
	lines.append("pnpm parity:ts-eslint")
	lines.append("PARITY_OFFLINE=1 TS_ESLINT_REF=main pnpm parity:ts-eslint")
	lines.append("pnpm parity:ts-eslint:check")
	lines.append("pnpm parity:ts-eslint:check:all")
	lines.append("pnpm parity:ts-eslint:check:strict")
	lines.append("pnpm parity:ts-eslint:check:tooling")
	lines.append("pnpm parity:ts-eslint:commands")
	lines.append("pnpm parity:ts-eslint:badges")
	lines.append("pnpm parity:ts-eslint:status")
	lines.append("pnpm parity:ts-eslint:ci-summary")
	lines.append("pnpm parity:ts-eslint:ci-summary:json")
	lines.append("pnpm parity:ts-eslint:doctor")
	lines.append("pnpm parity:ts-eslint:doctor:markdown")
	lines.append("pnpm parity:ts-eslint:doctor:json")
	lines.append("pnpm parity:ts-eslint:doctor:json:strict")
	lines.append("pnpm parity:ts-eslint:doctor:strict")
	lines.append("pnpm parity:ts-eslint:diff --base-ref HEAD~1")
	lines.append("pnpm parity:ts-eslint:diff:json --base-ref HEAD~1")
	lines.append("pnpm parity:ts-eslint:tasklist --phase A_critical")
	lines.append("pnpm parity:ts-eslint:tasklist:all")
	lines.append("pnpm parity:ts-eslint:issue-body --phase A_critical")
	lines.append("pnpm parity:ts-eslint:issue-body:all")
	lines.append("pnpm parity:ts-eslint:top")
	lines.append("pnpm parity:ts-eslint:manifest")
	lines.append("pnpm parity:ts-eslint:rebuild-metadata")
	lines.append("pnpm parity:ts-eslint:verify-clean")
	lines.append("```")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
