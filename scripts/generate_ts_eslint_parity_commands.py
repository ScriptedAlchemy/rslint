#!/usr/bin/env python3
"""
Generate parity command reference markdown from package.json scripts.

Output:
  - /workspace/typescript-eslint-rule-parity-commands.md
"""

from __future__ import annotations

import json
import pathlib


def main() -> None:
	root = pathlib.Path("/workspace")
	package_json = root / "package.json"
	output_md = root / "typescript-eslint-rule-parity-commands.md"

	package = json.loads(package_json.read_text())
	scripts = package.get("scripts", {})

	parity_script_names = sorted(name for name in scripts if name.startswith("parity:ts-eslint"))

	descriptions = {
		"parity:ts-eslint": "Refresh all parity artifacts from upstream reference and run validations.",
		"parity:ts-eslint:check": "Validate generated parity artifact consistency and structure.",
		"parity:ts-eslint:check:tooling": "Validate parity commands/docs/script synchronization.",
		"parity:ts-eslint:diff": "Compare current tracker against baseline snapshot or git ref.",
		"parity:ts-eslint:tasklist": "Generate one phase tasklist snippet.",
		"parity:ts-eslint:tasklist:all": "Generate tasklist snippets for all parity phases.",
		"parity:ts-eslint:issue-body": "Generate one phase issue body draft from tasklist.",
		"parity:ts-eslint:issue-body:all": "Generate issue body drafts for all parity phases.",
		"parity:ts-eslint:badges": "Generate badge-friendly parity metrics JSON.",
		"parity:ts-eslint:status": "Generate concise parity health status JSON for automation.",
		"parity:ts-eslint:doctor": "Print parity health diagnosis from metadata and top-priority artifact.",
		"parity:ts-eslint:top": "Generate top-priority ranked parity list.",
		"parity:ts-eslint:manifest": "Generate checksum manifest for parity artifacts.",
		"parity:ts-eslint:rebuild-metadata": "Rebuild artifacts pinned to metadata upstream commit.",
		"parity:ts-eslint:verify-clean": "Rebuild from metadata and assert parity artifact diff is clean.",
	}

	lines: list[str] = []
	lines.append("# TypeScript-ESLint Parity Command Reference")
	lines.append("")
	lines.append("Generated from `package.json` parity scripts.")
	lines.append("")
	lines.append("| Command | Description | Backing script |")
	lines.append("|---|---|---|")
	for name in parity_script_names:
		desc = descriptions.get(name, "No description provided.")
		backing = scripts.get(name, "")
		lines.append(f"| `pnpm {name}` | {desc} | `{backing}` |")
	lines.append("")

	output_md.write_text("\n".join(lines) + "\n")
	print(f"wrote {output_md}")


if __name__ == "__main__":
	main()
