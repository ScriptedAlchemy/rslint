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
	lines.append("- `typescript-eslint-rule-parity-summary.md` — concise dashboard.")
	lines.append("- `typescript-eslint-rule-parity-metadata.json` — run metadata and counters.")
	lines.append("- `typescript-eslint-rule-parity-manifest.json` — deterministic checksums for parity artifacts.")
	lines.append("- `typescript-eslint-rule-parity-issue-plan.md` — issue-friendly phase plans.")
	lines.append("- `typescript-eslint-rule-parity-diff.md` — optional snapshot comparison output.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-A_critical.md` — tasklist snippet for A_critical.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-B_high.md` — tasklist snippet for B_high.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-C_medium.md` — tasklist snippet for C_medium.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-D_low.md` — tasklist snippet for D_low.")
	lines.append("- `typescript-eslint-rule-parity-tasklist-<phase>.md` — generic tasklist naming convention.")
	lines.append("- `typescript-eslint-rule-parity-guide.md` — toolkit usage guide.")
	lines.append("")

	lines.append("## Commands")
	lines.append("```bash")
	lines.append("pnpm parity:ts-eslint")
	lines.append("PARITY_OFFLINE=1 TS_ESLINT_REF=main pnpm parity:ts-eslint")
	lines.append("pnpm parity:ts-eslint:check")
	lines.append("pnpm parity:ts-eslint:diff -- --base-ref HEAD~1")
	lines.append("pnpm parity:ts-eslint:tasklist --phase A_critical")
	lines.append("pnpm parity:ts-eslint:tasklist:all")
	lines.append("pnpm parity:ts-eslint:manifest")
	lines.append("pnpm parity:ts-eslint:rebuild-metadata")
	lines.append("```")
	lines.append("")

	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
