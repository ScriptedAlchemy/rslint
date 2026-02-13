#!/usr/bin/env python3
"""
Generate machine-readable TypeScript-ESLint parity tracker files.

Outputs (repo root):
  - typescript-eslint-rule-parity-tracker.csv
  - typescript-eslint-rule-parity-tracker.json

Assumes upstream typescript-eslint repo exists at:
  /tmp/typescript-eslint
"""

from __future__ import annotations

import collections
import csv
import json
import pathlib
import re


def collect_js_test_metrics(root: pathlib.Path):
	files = collections.defaultdict(list)
	lines = collections.defaultdict(int)
	errs = collections.defaultdict(int)
	outs = collections.defaultdict(int)
	sugs = collections.defaultdict(int)
	skips = collections.defaultdict(int)
	skip_pat = re.compile(r"\bskip\s*:\s*true|describe\.skip|it\.skip|test\.skip")

	for test_file in root.rglob("*.test.ts"):
		rel = test_file.relative_to(root)
		if "__snapshots__" in rel.parts or rel.name == "index.test.ts":
			continue

		if len(rel.parts) > 1:
			rule = rel.parts[0]
		else:
			rule = rel.stem[:-5] if rel.stem.endswith(".test") else rel.stem

		text = test_file.read_text()
		files[rule].append(str(rel))
		lines[rule] += sum(1 for line in text.splitlines() if line.strip())
		errs[rule] += len(re.findall(r"\berrors\s*:", text))
		outs[rule] += len(re.findall(r"\boutput\s*:", text))
		sugs[rule] += len(re.findall(r"\bsuggestions\s*:", text))
		skips[rule] += len(skip_pat.findall(text))

	for key in files:
		files[key] = sorted(files[key])

	return files, lines, errs, outs, sugs, skips


def main() -> None:
	workspace = pathlib.Path("/workspace")
	up_repo = pathlib.Path("/tmp/typescript-eslint")
	up_rule_root = up_repo / "packages/eslint-plugin/src/rules"
	up_test_root = up_repo / "packages/eslint-plugin/tests/rules"
	local_rule_root = workspace / "internal/plugins/typescript/rules"
	local_js_root = workspace / "packages/rslint-test-tools/tests/typescript-eslint/rules"
	config_text = (workspace / "internal/config/config.go").read_text()

	registered = set(re.findall(r'GlobalRuleRegistry\.Register\("@typescript-eslint/([^"]+)"', config_text))
	up_rules = set(p.stem for p in up_rule_root.glob("*.ts") if p.name != "index.ts")
	local_rules = set(d.name.replace("_", "-") for d in local_rule_root.iterdir() if d.is_dir() and d.name != "fixtures")

	up_files, up_lines, up_errs, up_outs, up_sugs, up_skips = collect_js_test_metrics(up_test_root)
	loc_files, loc_lines, loc_errs, loc_outs, loc_sugs, loc_skips = collect_js_test_metrics(local_js_root)

	go_skip_pat = re.compile(r"\bSkip\s*:\s*true")
	todo_pat = re.compile(r"TODO\(port\)|TODO:\s*Add invalid test cases|FIXME|not implemented", re.I)

	all_rules = sorted(up_rules | local_rules | registered)
	rows = []

	for rule in all_rules:
		in_up = rule in up_rules
		in_local = rule in local_rules
		in_reg = rule in registered

		local_rule_dir = local_rule_root / rule.replace("-", "_")
		go_test_files = list(local_rule_dir.glob("*_test.go")) if local_rule_dir.exists() else []
		go_impl_files = [f for f in local_rule_dir.glob("*.go") if not f.name.endswith("_test.go")] if local_rule_dir.exists() else []

		impl_text = "\n".join(f.read_text() for f in go_impl_files)
		test_text = "\n".join(f.read_text() for f in go_test_files)
		go_skip_count = len(go_skip_pat.findall(test_text)) if test_text else 0
		todo_count = len(todo_pat.findall(impl_text + "\n" + test_text)) if (impl_text or test_text) else 0

		up_fixable = False
		up_has_suggestions = False
		if in_up:
			up_text = (up_rule_root / f"{rule}.ts").read_text()
			up_fixable = bool(re.search(r'fixable\s*:\s*["\']code["\']', up_text))
			up_has_suggestions = bool(re.search(r"hasSuggestions\s*:\s*true", up_text))

		local_has_fixes = any(s in impl_text for s in ["ReportNodeWithFixes", "ReportRangeWithFixes", "ReportNodeWithFixesOrSuggestions"])
		local_has_suggestions = any(
			s in impl_text for s in ["ReportNodeWithSuggestions", "ReportRangeWithSuggestions", "ReportNodeWithFixesOrSuggestions"]
		)

		flags: list[str] = []
		if in_up and not in_reg:
			flags.append("missing_registration")
		if in_up and not in_local:
			flags.append("missing_go_implementation")
		if in_up and in_local and not go_test_files:
			flags.append("missing_go_test")

		missing_js = sorted(set(up_files.get(rule, [])) - set(loc_files.get(rule, []))) if in_up else []
		if missing_js:
			flags.append("missing_js_file")

		if in_up and up_lines.get(rule, 0) > 0:
			js_line_ratio = loc_lines.get(rule, 0) / up_lines[rule]
			if js_line_ratio < 0.5:
				flags.append("severe_js_size_gap")
			elif js_line_ratio < 0.8:
				flags.append("moderate_js_size_gap")

		if in_up and up_errs.get(rule, 0) > 0:
			js_err_ratio = loc_errs.get(rule, 0) / up_errs[rule]
			if js_err_ratio < 0.5:
				flags.append("severe_invalid_gap")
			elif js_err_ratio < 0.8:
				flags.append("moderate_invalid_gap")

		if in_up and loc_skips.get(rule, 0) > up_skips.get(rule, 0):
			flags.append("extra_js_skips")
		if go_skip_count > 0:
			flags.append("go_skips")
		if todo_count > 0:
			flags.append("todo_markers")

		if in_up and up_fixable and ((not local_has_fixes) or (loc_outs.get(rule, 0) < up_outs.get(rule, 0))):
			flags.append("fix_gap_suspected")
		if in_up and up_has_suggestions and ((not local_has_suggestions) or (loc_sugs.get(rule, 0) < up_sugs.get(rule, 0))):
			flags.append("suggestion_gap_suspected")
		if not in_up and (in_local or in_reg):
			flags.append("local_only_rule")

		score = (
			(20 if "missing_go_test" in flags else 0)
			+ (20 if "missing_js_file" in flags else 0)
			+ (20 if "missing_go_implementation" in flags else 0)
			+ (18 if "severe_invalid_gap" in flags else 0)
			+ (16 if "severe_js_size_gap" in flags else 0)
			+ (10 if "moderate_invalid_gap" in flags else 0)
			+ (8 if "moderate_js_size_gap" in flags else 0)
			+ (8 if "go_skips" in flags else 0)
			+ (6 if "extra_js_skips" in flags else 0)
			+ (5 if "todo_markers" in flags else 0)
			+ (6 if "fix_gap_suspected" in flags else 0)
			+ (6 if "suggestion_gap_suspected" in flags else 0)
			+ (4 if "local_only_rule" in flags else 0)
		)

		if score >= 32:
			phase = "A_critical"
		elif score >= 18:
			phase = "B_high"
		elif score >= 10:
			phase = "C_medium"
		elif score > 0:
			phase = "D_low"
		else:
			phase = "aligned"

		rows.append(
			{
				"rule": rule,
				"priority_score": score,
				"recommended_phase": phase,
				"in_upstream": in_up,
				"registered_locally": in_reg,
				"local_go_rule_dir_exists": in_local,
				"has_go_test": bool(go_test_files),
				"missing_js_files": "|".join(missing_js) if missing_js else "",
				"js_errs_local": loc_errs.get(rule, 0),
				"js_errs_upstream": up_errs.get(rule, 0),
				"js_lines_local": loc_lines.get(rule, 0),
				"js_lines_upstream": up_lines.get(rule, 0),
				"js_outputs_local": loc_outs.get(rule, 0),
				"js_outputs_upstream": up_outs.get(rule, 0),
				"js_suggestions_local": loc_sugs.get(rule, 0),
				"js_suggestions_upstream": up_sugs.get(rule, 0),
				"js_skip_delta": (loc_skips.get(rule, 0) - up_skips.get(rule, 0)) if in_up else 0,
				"go_skip_count": go_skip_count,
				"todo_fixme_count": todo_count,
				"flags": "|".join(flags),
				"upstream_rule_file": f"packages/eslint-plugin/src/rules/{rule}.ts" if in_up else "",
				"local_go_impl_files": "|".join(sorted(str(p.relative_to(workspace)) for p in go_impl_files)),
				"local_go_test_files": "|".join(sorted(str(p.relative_to(workspace)) for p in go_test_files)),
				"local_js_test_files": "|".join(loc_files.get(rule, [])),
			}
		)

	rows_sorted = sorted(rows, key=lambda r: (-r["priority_score"], r["rule"]))

	csv_path = workspace / "typescript-eslint-rule-parity-tracker.csv"
	json_path = workspace / "typescript-eslint-rule-parity-tracker.json"

	fieldnames = [
		"rule",
		"priority_score",
		"recommended_phase",
		"in_upstream",
		"registered_locally",
		"local_go_rule_dir_exists",
		"has_go_test",
		"missing_js_files",
		"js_errs_local",
		"js_errs_upstream",
		"js_lines_local",
		"js_lines_upstream",
		"js_outputs_local",
		"js_outputs_upstream",
		"js_suggestions_local",
		"js_suggestions_upstream",
		"js_skip_delta",
		"go_skip_count",
		"todo_fixme_count",
		"flags",
		"upstream_rule_file",
		"local_go_impl_files",
		"local_go_test_files",
		"local_js_test_files",
	]

	with csv_path.open("w", newline="") as f:
		writer = csv.DictWriter(f, fieldnames=fieldnames)
		writer.writeheader()
		writer.writerows(rows_sorted)

	json_path.write_text(json.dumps(rows_sorted, indent=2))

	flagged = sum(1 for row in rows_sorted if row["priority_score"] > 0)
	print(f"wrote {csv_path}")
	print(f"wrote {json_path}")
	print(f"rows={len(rows_sorted)} flagged={flagged}")


if __name__ == "__main__":
	main()
