#!/usr/bin/env python3
"""
Print parity health diagnosis from generated artifacts.

Reads:
  - /workspace/typescript-eslint-rule-parity-metadata.json
  - /workspace/typescript-eslint-rule-parity-top.md

Optional:
  --markdown   emit markdown (default plain text)
  --fail-on-critical  exit non-zero if A_critical > 0
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


def parse_top_rules(top_text: str, limit: int = 5) -> list[str]:
	rules: list[str] = []
	for match in re.finditer(r"\|\s*\d+\s*\|\s*`([^`]+)`\s*\|", top_text):
		rules.append(match.group(1))
		if len(rules) >= limit:
			break
	return rules


def main() -> None:
	parser = argparse.ArgumentParser(description="Print parity health diagnosis.")
	parser.add_argument("--markdown", action="store_true", help="Emit markdown output.")
	parser.add_argument("--fail-on-critical", action="store_true", help="Exit non-zero if A_critical > 0.")
	args = parser.parse_args()

	root = pathlib.Path("/workspace")
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	top_path = root / "typescript-eslint-rule-parity-top.md"

	metadata = json.loads(metadata_path.read_text())
	top_text = top_path.read_text() if top_path.exists() else ""

	summary = metadata.get("summary", {})
	phases = metadata.get("phase_counts", {})
	total = int(summary.get("total_rules", 0))
	flagged = int(summary.get("flagged_rules", 0))
	aligned = int(summary.get("aligned_rules", 0))
	critical = int(phases.get("A_critical", 0))
	high = int(phases.get("B_high", 0))
	medium = int(phases.get("C_medium", 0))
	low = int(phases.get("D_low", 0))
	ratio = (aligned / total * 100.0) if total else 0.0

	top_rules = parse_top_rules(top_text, limit=5)

	if args.markdown:
		lines: list[str] = []
		lines.append("### Parity Doctor")
		lines.append(f"- Total rules: **{total}**")
		lines.append(f"- Aligned rules: **{aligned}** ({ratio:.1f}%)")
		lines.append(f"- Flagged rules: **{flagged}**")
		lines.append(f"- Phase load: A={critical}, B={high}, C={medium}, D={low}")
		if top_rules:
			lines.append(f"- Top immediate rules: {', '.join(f'`{rule}`' for rule in top_rules)}")
		print("\n".join(lines))
	else:
		print("Parity Doctor")
		print(f"  Total rules   : {total}")
		print(f"  Aligned rules : {aligned} ({ratio:.1f}%)")
		print(f"  Flagged rules : {flagged}")
		print(f"  Phase load    : A={critical} B={high} C={medium} D={low}")
		if top_rules:
			print(f"  Top rules     : {', '.join(top_rules)}")

	if args.fail_on_critical and critical > 0:
		print(f"[parity-doctor] ERROR: A_critical backlog is non-zero ({critical}).", file=sys.stderr)
		sys.exit(2)


if __name__ == "__main__":
	main()
