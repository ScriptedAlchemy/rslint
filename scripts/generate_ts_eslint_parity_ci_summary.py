#!/usr/bin/env python3
"""
Emit a concise markdown summary for CI job output.

Reads:
  - typescript-eslint-rule-parity-metadata.json (required)
  - typescript-eslint-rule-parity-diff.md (optional)

Prints markdown to stdout (intended for $GITHUB_STEP_SUMMARY),
or JSON with --json.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re


def read_optional_diff_metrics(diff_path: pathlib.Path) -> dict:
	if not diff_path.exists():
		return {}

	text = diff_path.read_text()
	metrics = {}
	patterns = {
		"net_flagged_change": r"Net flagged change:\s+\*\*([+-]?\d+)\*\*",
		"improved_rules": r"Improved rules .*:\s+\*\*(\d+)\*\*",
		"regressed_rules": r"Regressed rules .*:\s+\*\*(\d+)\*\*",
		"resolved_rules": r"Resolved rules .*:\s+\*\*(\d+)\*\*",
		"newly_flagged_rules": r"Newly flagged rules .*:\s+\*\*(\d+)\*\*",
	}
	for key, pattern in patterns.items():
		matched = re.search(pattern, text)
		if matched:
			metrics[key] = matched.group(1)
	return metrics


def main() -> None:
	parser = argparse.ArgumentParser(description="Emit parity CI summary.")
	parser.add_argument("--json", action="store_true", help="Emit JSON output instead of markdown.")
	args = parser.parse_args()

	root = pathlib.Path("/workspace")
	metadata_path = root / "typescript-eslint-rule-parity-metadata.json"
	status_path = root / "typescript-eslint-rule-parity-status.json"
	diff_path = root / "typescript-eslint-rule-parity-diff.md"

	metadata = json.loads(metadata_path.read_text())
	status = json.loads(status_path.read_text()) if status_path.exists() else {}
	summary = metadata.get("summary", {})
	phase_counts = metadata.get("phase_counts", {})
	upstream_ref = metadata.get("upstream_ref_requested", "unknown")
	upstream_commit = metadata.get("upstream_commit", "unknown")
	health = status.get("health")
	reason = status.get("reason")

	diff_metrics = read_optional_diff_metrics(diff_path)

	if args.json:
		payload = {
			"schema_version": 1,
			"generated_at_utc": metadata.get("generated_at_utc"),
			"upstream_ref_requested": upstream_ref,
			"upstream_commit": upstream_commit,
			"summary": {
				"total_rules": int(summary.get("total_rules", 0)),
				"flagged_rules": int(summary.get("flagged_rules", 0)),
				"aligned_rules": int(summary.get("aligned_rules", 0)),
			},
			"health": health,
			"health_reason": reason,
			"phase_counts": {
				"A_critical": int(phase_counts.get("A_critical", 0)),
				"B_high": int(phase_counts.get("B_high", 0)),
				"C_medium": int(phase_counts.get("C_medium", 0)),
				"D_low": int(phase_counts.get("D_low", 0)),
				"aligned": int(phase_counts.get("aligned", 0)),
			},
		}
		if diff_metrics:
			payload["diff_metrics"] = {key: int(value) for key, value in diff_metrics.items()}
		print(json.dumps(payload, indent=2))
		return

	lines: list[str] = []
	lines.append("## TypeScript-ESLint Parity Summary")
	lines.append("")
	lines.append(f"- Upstream ref: `{upstream_ref}`")
	lines.append(f"- Upstream commit: `{upstream_commit}`")
	lines.append(f"- Total rules: **{summary.get('total_rules', 0)}**")
	lines.append(f"- Flagged rules: **{summary.get('flagged_rules', 0)}**")
	lines.append(f"- Aligned rules: **{summary.get('aligned_rules', 0)}**")
	if health:
		health_line = f"- Health: **{health}**"
		if reason:
			health_line += f" — {reason}"
		lines.append(health_line)
	lines.append("")
	lines.append("| Phase | Rules |")
	lines.append("|---|---:|")
	for phase in ["A_critical", "B_high", "C_medium", "D_low", "aligned"]:
		lines.append(f"| `{phase}` | {phase_counts.get(phase, 0)} |")

	if diff_metrics:
		lines.append("")
		lines.append("### Diff vs baseline")
		lines.append(f"- Net flagged change: **{diff_metrics.get('net_flagged_change', 'n/a')}**")
		lines.append(f"- Improved rules: **{diff_metrics.get('improved_rules', 'n/a')}**")
		lines.append(f"- Regressed rules: **{diff_metrics.get('regressed_rules', 'n/a')}**")
		lines.append(f"- Resolved rules: **{diff_metrics.get('resolved_rules', 'n/a')}**")
		lines.append(f"- Newly flagged rules: **{diff_metrics.get('newly_flagged_rules', 'n/a')}**")

	print("\n".join(lines))


if __name__ == "__main__":
	main()
