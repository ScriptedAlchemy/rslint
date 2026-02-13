#!/usr/bin/env python3
"""
Compare two TypeScript-ESLint parity tracker snapshots.

Examples:
  python3 scripts/compare_ts_eslint_parity_trackers.py
  python3 scripts/compare_ts_eslint_parity_trackers.py --base-ref HEAD~1
  python3 scripts/compare_ts_eslint_parity_trackers.py \
    --base-json /path/to/old-tracker.json \
    --head-json /workspace/typescript-eslint-rule-parity-tracker.json \
    --output /workspace/typescript-eslint-rule-parity-diff.md \
    --output-json /workspace/typescript-eslint-rule-parity-diff.json
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import pathlib
import subprocess
from typing import Any


def load_rows_from_json(path: pathlib.Path) -> list[dict[str, Any]]:
	return json.loads(path.read_text())


def load_rows_from_ref(repo_root: pathlib.Path, ref: str) -> list[dict[str, Any]]:
	result = subprocess.run(
		["git", "-C", str(repo_root), "show", f"{ref}:typescript-eslint-rule-parity-tracker.json"],
		check=True,
		capture_output=True,
		text=True,
	)
	return json.loads(result.stdout)


def row_map(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
	return {row.get("rule", ""): row for row in rows}


def score(row: dict[str, Any] | None) -> int:
	if not row:
		return 0
	return int(row.get("priority_score", 0))


def phase(row: dict[str, Any] | None) -> str:
	if not row:
		return "missing"
	return str(row.get("recommended_phase", "unknown"))


def parse_flags(raw: str) -> set[str]:
	if not raw:
		return set()
	return {f for f in raw.split("|") if f}


def main() -> None:
	parser = argparse.ArgumentParser(description="Compare two parity tracker snapshots.")
	base_group = parser.add_mutually_exclusive_group(required=False)
	base_group.add_argument(
		"--base-ref",
		help="Git ref containing typescript-eslint-rule-parity-tracker.json (default: HEAD~1 when no base is provided)",
	)
	base_group.add_argument("--base-json", help="Path to baseline tracker JSON")
	parser.add_argument(
		"--head-json",
		default="/workspace/typescript-eslint-rule-parity-tracker.json",
		help="Path to head tracker JSON (default: /workspace/typescript-eslint-rule-parity-tracker.json)",
	)
	parser.add_argument(
		"--output",
		default="/workspace/typescript-eslint-rule-parity-diff.md",
		help="Output markdown path",
	)
	parser.add_argument(
		"--output-json",
		help="Optional output JSON path",
	)
	args = parser.parse_args()

	repo_root = pathlib.Path("/workspace")
	head_rows = load_rows_from_json(pathlib.Path(args.head_json))
	base_ref = args.base_ref or "HEAD~1"
	if args.base_ref or not args.base_json:
		base_rows = load_rows_from_ref(repo_root, base_ref)
		base_label = f"git:{base_ref}"
	else:
		base_rows = load_rows_from_json(pathlib.Path(args.base_json))
		base_label = str(pathlib.Path(args.base_json))

	head_label = str(pathlib.Path(args.head_json))
	base_map = row_map(base_rows)
	head_map = row_map(head_rows)
	all_rules = sorted(set(base_map) | set(head_map))

	improved: list[tuple[int, str]] = []
	regressed: list[tuple[int, str]] = []
	resolved: list[str] = []
	newly_flagged: list[str] = []
	phase_transitions: collections.Counter[str] = collections.Counter()

	base_flag_counts: collections.Counter[str] = collections.Counter()
	head_flag_counts: collections.Counter[str] = collections.Counter()

	for rule in all_rules:
		b = base_map.get(rule)
		h = head_map.get(rule)
		bs = score(b)
		hs = score(h)
		delta = hs - bs
		if delta < 0:
			improved.append((delta, rule))
		elif delta > 0:
			regressed.append((delta, rule))

		if bs > 0 and hs == 0:
			resolved.append(rule)
		if bs == 0 and hs > 0:
			newly_flagged.append(rule)

		bp = phase(b)
		hp = phase(h)
		if bp != hp:
			phase_transitions[f"{bp} -> {hp}"] += 1

		base_flag_counts.update(parse_flags((b or {}).get("flags", "")))
		head_flag_counts.update(parse_flags((h or {}).get("flags", "")))

	base_flagged = sum(1 for row in base_rows if score(row) > 0)
	head_flagged = sum(1 for row in head_rows if score(row) > 0)

	improved_sorted = sorted(improved, key=lambda x: (x[0], x[1]))  # most negative first
	regressed_sorted = sorted(regressed, key=lambda x: (-x[0], x[1]))  # largest positive first

	flag_delta_rows = []
	all_flags = sorted(set(base_flag_counts) | set(head_flag_counts))
	for flag in all_flags:
		before = base_flag_counts.get(flag, 0)
		after = head_flag_counts.get(flag, 0)
		diff = after - before
		flag_delta_rows.append((abs(diff), diff, flag, before, after))
	flag_delta_rows.sort(reverse=True)

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Parity Tracker Diff")
	lines.append("")
	lines.append(f"_Generated: {datetime.datetime.now(datetime.UTC).isoformat()}_")
	lines.append("")
	lines.append(f"- Base: `{base_label}`")
	lines.append(f"- Head: `{head_label}`")
	lines.append("")
	lines.append("## Summary")
	lines.append("")
	lines.append(f"- Rules compared: **{len(all_rules)}**")
	lines.append(f"- Flagged rules (base): **{base_flagged}**")
	lines.append(f"- Flagged rules (head): **{head_flagged}**")
	lines.append(f"- Net flagged change: **{head_flagged - base_flagged:+d}**")
	lines.append(f"- Improved rules (score decreased): **{len(improved)}**")
	lines.append(f"- Regressed rules (score increased): **{len(regressed)}**")
	lines.append(f"- Resolved rules (`>0 -> 0`): **{len(resolved)}**")
	lines.append(f"- Newly flagged rules (`0 -> >0`): **{len(newly_flagged)}**")
	lines.append("")

	lines.append("## Phase transitions")
	lines.append("")
	if phase_transitions:
		lines.append("| Transition | Rules |")
		lines.append("|---|---:|")
		for transition, count in phase_transitions.most_common():
			lines.append(f"| `{transition}` | {count} |")
	else:
		lines.append("_No phase transitions detected._")
	lines.append("")

	lines.append("## Top improvements")
	lines.append("")
	if improved_sorted:
		lines.append("| Rule | Score delta |")
		lines.append("|---|---:|")
		for delta, rule in improved_sorted[:20]:
			lines.append(f"| `{rule}` | {delta} |")
	else:
		lines.append("_No improvements detected._")
	lines.append("")

	lines.append("## Top regressions")
	lines.append("")
	if regressed_sorted:
		lines.append("| Rule | Score delta |")
		lines.append("|---|---:|")
		for delta, rule in regressed_sorted[:20]:
			lines.append(f"| `{rule}` | +{delta} |")
	else:
		lines.append("_No regressions detected._")
	lines.append("")

	lines.append("## Flag frequency deltas")
	lines.append("")
	if flag_delta_rows:
		lines.append("| Flag | Base | Head | Delta |")
		lines.append("|---|---:|---:|---:|")
		for _, diff, flag, before, after in flag_delta_rows[:30]:
			sign = f"{diff:+d}"
			lines.append(f"| `{flag}` | {before} | {after} | {sign} |")
	else:
		lines.append("_No flag deltas detected._")
	lines.append("")

	lines.append("## Newly flagged rules")
	lines.append("")
	if newly_flagged:
		for rule in sorted(newly_flagged):
			lines.append(f"- `{rule}`")
	else:
		lines.append("_None._")
	lines.append("")

	lines.append("## Resolved rules")
	lines.append("")
	if resolved:
		for rule in sorted(resolved):
			lines.append(f"- `{rule}`")
	else:
		lines.append("_None._")
	lines.append("")

	output_path = pathlib.Path(args.output)
	output_path.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_path}")

	if args.output_json:
		json_path = pathlib.Path(args.output_json)
		payload = {
			"schema_version": 1,
			"generated_at_utc": datetime.datetime.now(datetime.UTC).isoformat(),
			"base_label": base_label,
			"head_label": head_label,
			"summary": {
				"rules_compared": len(all_rules),
				"flagged_rules_base": base_flagged,
				"flagged_rules_head": head_flagged,
				"net_flagged_change": head_flagged - base_flagged,
				"improved_rules": len(improved),
				"regressed_rules": len(regressed),
				"resolved_rules": len(resolved),
				"newly_flagged_rules": len(newly_flagged),
			},
			"phase_transitions": dict(phase_transitions),
			"top_improvements": [{"rule": rule, "score_delta": delta} for delta, rule in improved_sorted[:20]],
			"top_regressions": [{"rule": rule, "score_delta": delta} for delta, rule in regressed_sorted[:20]],
			"flag_frequency_deltas": [
				{"flag": flag, "base": before, "head": after, "delta": diff} for _, diff, flag, before, after in flag_delta_rows
			],
			"newly_flagged_rules": sorted(newly_flagged),
			"resolved_rules": sorted(resolved),
		}
		json_path.write_text(json.dumps(payload, indent=2) + "\n")
		print(f"wrote {json_path}")


if __name__ == "__main__":
	main()
