# TypeScript-ESLint Parity Command Reference

Generated from `package.json` parity scripts.

| Command | Description | Backing script |
|---|---|---|
| `pnpm parity:ts-eslint` | Refresh all parity artifacts from upstream reference and run validations. | `bash scripts/refresh-ts-eslint-parity-artifacts.sh` |
| `pnpm parity:ts-eslint:badges` | Generate badge-friendly parity metrics JSON. | `python3 scripts/generate_ts_eslint_parity_badges.py` |
| `pnpm parity:ts-eslint:check` | Validate generated parity artifact consistency and structure. | `python3 scripts/check_ts_eslint_parity_artifacts.py` |
| `pnpm parity:ts-eslint:check:all` | Run all parity checks; includes verify-clean when parity artifacts are clean. | `bash scripts/check_ts_eslint_parity_all.sh` |
| `pnpm parity:ts-eslint:check:tooling` | Validate parity commands/docs/script synchronization. | `python3 scripts/check_ts_eslint_parity_tooling_sync.py` |
| `pnpm parity:ts-eslint:commands` | Generate command reference markdown from package scripts. | `python3 scripts/generate_ts_eslint_parity_commands.py` |
| `pnpm parity:ts-eslint:diff` | Compare current tracker against baseline snapshot or git ref. | `python3 scripts/compare_ts_eslint_parity_trackers.py` |
| `pnpm parity:ts-eslint:doctor` | Print parity health diagnosis from metadata and top-priority artifact. | `python3 scripts/generate_ts_eslint_parity_doctor.py` |
| `pnpm parity:ts-eslint:issue-body` | Generate one phase issue body draft from tasklist. | `python3 scripts/generate_ts_eslint_parity_issue_body.py` |
| `pnpm parity:ts-eslint:issue-body:all` | Generate issue body drafts for all parity phases. | `bash scripts/generate_ts_eslint_parity_issue_bodies_all.sh` |
| `pnpm parity:ts-eslint:manifest` | Generate checksum manifest for parity artifacts. | `python3 scripts/generate_ts_eslint_parity_manifest.py` |
| `pnpm parity:ts-eslint:rebuild-metadata` | Rebuild artifacts pinned to metadata upstream commit. | `bash scripts/rebuild_ts_eslint_parity_from_metadata.sh` |
| `pnpm parity:ts-eslint:status` | Generate concise parity health status JSON for automation. | `python3 scripts/generate_ts_eslint_parity_status.py` |
| `pnpm parity:ts-eslint:tasklist` | Generate one phase tasklist snippet. | `python3 scripts/generate_ts_eslint_parity_issue_tasklist.py` |
| `pnpm parity:ts-eslint:tasklist:all` | Generate tasklist snippets for all parity phases. | `bash scripts/generate_ts_eslint_parity_tasklists_all.sh` |
| `pnpm parity:ts-eslint:top` | Generate top-priority ranked parity list. | `python3 scripts/generate_ts_eslint_parity_top.py` |
| `pnpm parity:ts-eslint:verify-clean` | Rebuild from metadata and assert parity artifact diff is clean. | `bash scripts/verify_ts_eslint_parity_clean.sh` |

