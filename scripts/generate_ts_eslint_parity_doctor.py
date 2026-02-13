#!/usr/bin/env python3
"""
Print parity health diagnosis from generated artifacts.

Reads:
  - /workspace/typescript-eslint-rule-parity-metadata.json
  - /workspace/typescript-eslint-rule-parity-top.md
  - /workspace/typescript-eslint-rule-parity-status.json (optional)

Optional:
  --markdown   emit markdown (default plain text)
  --json       emit JSON output for automation
  --fail-on-critical  exit non-zero if A_critical > 0
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

from parity_health import compute_health_reason


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
	parser.add_argument("--json", action="store_true", help="Emit JSON output.")
	parser.add_argument("--fail-on-critical", action="store_true", help="Exit non-zero if A_critical > 0.")
	args = parser.parse_args()
	if args.markdown and args.json:
		print("[parity-doctor] ERROR: choose one output mode: --markdown or --json", file=sys.stderr)
		sys.exit(1)

	root = pathlib.Path("/workspace")
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	top_path = root / "typescript-eslint-rule-parity-top.md"
	status_path = root / "typescript-eslint-rule-parity-status.json"

	metadata = json.loads(metadata_path.read_text())
	top_text = top_path.read_text() if top_path.exists() else ""
	status = json.loads(status_path.read_text()) if status_path.exists() else {}

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
	health_default, reason_default = compute_health_reason(critical=critical, high=high, flagged=flagged)
	health = status.get("health", health_default)
	reason = status.get("reason", reason_default)

	if args.json:
		payload = {
			"schema_version": 1,
			"generated_at_utc": metadata.get("generated_at_utc"),
			"upstream_ref_requested": metadata.get("upstream_ref_requested"),
			"upstream_commit": metadata.get("upstream_commit"),
			"health": health,
			"reason": reason,
			"summary": {
				"total_rules": total,
				"aligned_rules": aligned,
				"flagged_rules": flagged,
				"aligned_percent": round(ratio, 1),
			},
			"phase_counts": {
				"A_critical": critical,
				"B_high": high,
				"C_medium": medium,
				"D_low": low,
			},
			"top_rules": top_rules,
		}
		print(json.dumps(payload, indent=2))
	elif args.markdown:
		lines: list[str] = []
		lines.append("### Parity Doctor")
		lines.append(f"- Total rules: **{total}**")
		lines.append(f"- Aligned rules: **{aligned}** ({ratio:.1f}%)")
		lines.append(f"- Flagged rules: **{flagged}**")
		lines.append(f"- Health: **{health}** — {reason}")
		lines.append(f"- Phase load: A={critical}, B={high}, C={medium}, D={low}")
		if top_rules:
			lines.append(f"- Top immediate rules: {', '.join(f'`{rule}`' for rule in top_rules)}")
		print("\n".join(lines))
	else:
		print("Parity Doctor")
		print(f"  Total rules   : {total}")
		print(f"  Aligned rules : {aligned} ({ratio:.1f}%)")
		print(f"  Flagged rules : {flagged}")
		print(f"  Health        : {health} ({reason})")
		print(f"  Phase load    : A={critical} B={high} C={medium} D={low}")
		if top_rules:
			print(f"  Top rules     : {', '.join(top_rules)}")

	if args.fail_on_critical and critical > 0:
		print(f"[parity-doctor] ERROR: A_critical backlog is non-zero ({critical}).", file=sys.stderr)
		sys.exit(2)


if __name__ == "__main__":
	main()
