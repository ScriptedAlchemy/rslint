#!/usr/bin/env python3
"""
Generate deterministic checksum manifest for parity artifacts.

Output:
  - /workspace/typescript-eslint-rule-parity-manifest.json
"""

from __future__ import annotations

import hashlib
import json
import pathlib


def sha256_file(path: pathlib.Path) -> str:
	hasher = hashlib.sha256()
	with path.open("rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			hasher.update(chunk)
	return hasher.hexdigest()


def main() -> None:
	root = pathlib.Path("/workspace")
	output_path = root / "typescript-eslint-rule-parity-manifest.json"

	artifacts = [
		"typescript-eslint-rule-parity-report.md",
		"typescript-eslint-rule-parity-guide.md",
		"typescript-eslint-rule-parity-index.md",
		"typescript-eslint-rule-parity-summary.md",
		"typescript-eslint-rule-parity-worklist.md",
		"typescript-eslint-rule-parity-issue-plan.md",
		"typescript-eslint-rule-parity-tracker.csv",
		"typescript-eslint-rule-parity-tracker.json",
		"typescript-eslint-rule-parity-metadata.json",
		"typescript-eslint-rule-parity-tasklist-A_critical.md",
		"typescript-eslint-rule-parity-tasklist-B_high.md",
		"typescript-eslint-rule-parity-tasklist-C_medium.md",
		"typescript-eslint-rule-parity-tasklist-D_low.md",
	]

	files = []
	for rel in artifacts:
		path = root / rel
		if not path.exists():
			raise FileNotFoundError(f"artifact not found: {rel}")
		files.append(
			{
				"path": rel,
				"sha256": sha256_file(path),
				"bytes": path.stat().st_size,
			}
		)

	manifest = {
		"schema_version": 1,
		"hash_algorithm": "sha256",
		"files": files,
	}

	output_path.write_text(json.dumps(manifest, indent=2) + "\n")
	print(f"wrote {output_path}")


if __name__ == "__main__":
	main()
