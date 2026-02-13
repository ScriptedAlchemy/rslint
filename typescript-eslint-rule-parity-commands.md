# TypeScript-ESLint Parity Command Reference

Generated from `package.json` parity scripts.

| Command | Description | Backing script |
|---|---|---|
| `pnpm parity:ts-eslint` | Refresh all parity artifacts from upstream reference and run validations. | `bash scripts/refresh-ts-eslint-parity-artifacts.sh` |
| `pnpm parity:ts-eslint:badges` | Generate badge-friendly parity metrics JSON. | `python3 scripts/generate_ts_eslint_parity_badges.py` |
| `pnpm parity:ts-eslint:check` | Validate generated parity artifact consistency and structure. | `python3 scripts/check_ts_eslint_parity_artifacts.py` |
| `pnpm parity:ts-eslint:check:all` | Run all parity checks; includes verify-clean when parity artifacts are clean. | `bash scripts/check_ts_eslint_parity_all.sh` |
| `pnpm parity:ts-eslint:check:clean` | Run check:all and require a clean parity-artifact tree for verify-clean. | `PARITY_CHECK_ALL_REQUIRE_CLEAN=1 bash scripts/check_ts_eslint_parity_all.sh` |
| `pnpm parity:ts-eslint:check:strict` | Run full parity checks and fail if critical backlog exists. | `bash scripts/check_ts_eslint_parity_all.sh && python3 scripts/generate_ts_eslint_parity_doctor.py --fail-on-critical` |
| `pnpm parity:ts-eslint:check:strict:clean` | Run strict gate and require clean parity artifacts for verify-clean. | `PARITY_CHECK_ALL_REQUIRE_CLEAN=1 bash scripts/check_ts_eslint_parity_all.sh && python3 scripts/generate_ts_eslint_parity_doctor.py --fail-on-critical` |
| `pnpm parity:ts-eslint:check:tooling` | Validate parity commands/docs/script synchronization. | `python3 scripts/check_ts_eslint_parity_tooling_sync.py` |
| `pnpm parity:ts-eslint:ci-summary` | Render CI-style markdown summary from parity artifacts. | `python3 scripts/generate_ts_eslint_parity_ci_summary.py` |
| `pnpm parity:ts-eslint:ci-summary:json` | Render CI summary as JSON for automation. | `python3 scripts/generate_ts_eslint_parity_ci_summary.py --json` |
| `pnpm parity:ts-eslint:ci-summary:strict` | Render CI summary and fail when health is red. | `python3 scripts/generate_ts_eslint_parity_ci_summary.py --fail-on-red` |
| `pnpm parity:ts-eslint:ci-summary:strict:yellow` | Render CI summary and fail when health is yellow or red. | `python3 scripts/generate_ts_eslint_parity_ci_summary.py --fail-on-yellow` |
| `pnpm parity:ts-eslint:commands` | Generate command reference markdown from package scripts. | `python3 scripts/generate_ts_eslint_parity_commands.py` |
| `pnpm parity:ts-eslint:diff` | Compare current tracker against baseline (defaults to HEAD~1; falls back to HEAD). | `python3 scripts/compare_ts_eslint_parity_trackers.py` |
| `pnpm parity:ts-eslint:diff:json` | Compare parity snapshots and emit JSON diff to default path (HEAD~1 baseline with HEAD fallback). | `python3 scripts/compare_ts_eslint_parity_trackers.py --with-default-output-json` |
| `pnpm parity:ts-eslint:diff:refresh` | Refresh standard markdown+JSON diff artifacts at repository root. | `python3 scripts/compare_ts_eslint_parity_trackers.py --output /workspace/typescript-eslint-rule-parity-diff.md --output-json /workspace/typescript-eslint-rule-parity-diff.json` |
| `pnpm parity:ts-eslint:doctor` | Print parity health diagnosis from metadata and top-priority artifact. | `python3 scripts/generate_ts_eslint_parity_doctor.py` |
| `pnpm parity:ts-eslint:doctor:json` | Print parity doctor output in JSON format for automation. | `python3 scripts/generate_ts_eslint_parity_doctor.py --json` |
| `pnpm parity:ts-eslint:doctor:json:strict` | Print parity doctor JSON and fail if critical backlog exists. | `python3 scripts/generate_ts_eslint_parity_doctor.py --json --fail-on-critical` |
| `pnpm parity:ts-eslint:doctor:json:strict:yellow` | Print parity doctor JSON and fail if health is yellow or red. | `python3 scripts/generate_ts_eslint_parity_doctor.py --json --fail-on-yellow` |
| `pnpm parity:ts-eslint:doctor:markdown` | Print parity doctor output in markdown format. | `python3 scripts/generate_ts_eslint_parity_doctor.py --markdown` |
| `pnpm parity:ts-eslint:doctor:strict` | Print parity health diagnosis and fail if critical backlog exists. | `python3 scripts/generate_ts_eslint_parity_doctor.py --fail-on-critical` |
| `pnpm parity:ts-eslint:doctor:strict:yellow` | Print parity doctor output and fail if health is yellow or red. | `python3 scripts/generate_ts_eslint_parity_doctor.py --fail-on-yellow` |
| `pnpm parity:ts-eslint:issue-body` | Generate one phase issue body draft from tasklist. | `python3 scripts/generate_ts_eslint_parity_issue_body.py` |
| `pnpm parity:ts-eslint:issue-body:all` | Generate issue body drafts for all parity phases. | `bash scripts/generate_ts_eslint_parity_issue_bodies_all.sh` |
| `pnpm parity:ts-eslint:manifest` | Generate checksum manifest for parity artifacts. | `python3 scripts/generate_ts_eslint_parity_manifest.py` |
| `pnpm parity:ts-eslint:rebuild-metadata` | Rebuild artifacts pinned to metadata upstream commit. | `bash scripts/rebuild_ts_eslint_parity_from_metadata.sh` |
| `pnpm parity:ts-eslint:status` | Generate concise parity health status JSON for automation. | `python3 scripts/generate_ts_eslint_parity_status.py` |
| `pnpm parity:ts-eslint:status:strict` | Generate status JSON and fail when health is red. | `python3 scripts/generate_ts_eslint_parity_status.py --fail-on-red` |
| `pnpm parity:ts-eslint:status:strict:yellow` | Generate status JSON and fail when health is yellow or red. | `python3 scripts/generate_ts_eslint_parity_status.py --fail-on-yellow` |
| `pnpm parity:ts-eslint:tasklist` | Generate one phase tasklist snippet. | `python3 scripts/generate_ts_eslint_parity_issue_tasklist.py` |
| `pnpm parity:ts-eslint:tasklist:all` | Generate tasklist snippets for all parity phases. | `bash scripts/generate_ts_eslint_parity_tasklists_all.sh` |
| `pnpm parity:ts-eslint:top` | Generate top-priority ranked parity list. | `python3 scripts/generate_ts_eslint_parity_top.py` |
| `pnpm parity:ts-eslint:verify-clean` | Rebuild from metadata and assert parity artifact status is clean. | `bash scripts/verify_ts_eslint_parity_clean.sh` |

