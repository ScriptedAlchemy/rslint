# TypeScript-ESLint Parity Toolkit Guide

This repository includes a parity toolkit to compare upstream
`typescript-eslint` rules against local Go ports and test suites.

## What this toolkit produces

After running the refresh command, the following artifacts are generated at repo root:

- `typescript-eslint-rule-parity-report.md` — narrative audit report.
- `typescript-eslint-rule-parity-tracker.csv` — machine-readable row dataset.
- `typescript-eslint-rule-parity-tracker.json` — JSON form of tracker data.
- `typescript-eslint-rule-parity-worklist.md` — execution checklist grouped by phase.
- `typescript-eslint-rule-parity-top.md` — ranked top priorities for immediate execution.
- `typescript-eslint-rule-parity-commands.md` — generated command reference.
- `typescript-eslint-rule-parity-summary.md` — dashboard with headline metrics and top priorities.
- `typescript-eslint-rule-parity-metadata.json` — run metadata (timestamp, upstream SHA, requested ref, counters).
- `typescript-eslint-rule-parity-badges.json` — badge-friendly metrics JSON (including health + badge color).
- `typescript-eslint-rule-parity-status.json` — compact health/status summary for automation.
- `typescript-eslint-rule-parity-manifest.json` — deterministic checksums for core parity artifacts.
- `typescript-eslint-rule-parity-index.md` — central index linking all parity artifacts.
- `typescript-eslint-rule-parity-issue-plan.md` — issue-friendly phase plan/checklist template.
- `typescript-eslint-rule-parity-tasklist-A_critical.md` — generated tasklist snippet for critical phase.
- `typescript-eslint-rule-parity-tasklist-B_high.md` — generated tasklist snippet for high phase.
- `typescript-eslint-rule-parity-tasklist-C_medium.md` — generated tasklist snippet for medium phase.
- `typescript-eslint-rule-parity-tasklist-D_low.md` — generated tasklist snippet for low phase.

## Commands

### One-command refresh (recommended)

```bash
pnpm parity:ts-eslint
```

This command:
1. Updates/clones upstream `typescript-eslint` under `/tmp/typescript-eslint`.
2. Regenerates all parity artifacts.
3. Runs artifact consistency checks.

To pin a specific upstream ref (branch/tag/SHA) for comparison:

```bash
TS_ESLINT_REF=main pnpm parity:ts-eslint
```

To run without network fetch (uses refs already available in `/tmp/typescript-eslint`):

```bash
PARITY_OFFLINE=1 TS_ESLINT_REF=main pnpm parity:ts-eslint
```

### Run consistency checks only

```bash
pnpm parity:ts-eslint:check
pnpm parity:ts-eslint:check:all
pnpm parity:ts-eslint:check:tooling
pnpm parity:ts-eslint:commands
pnpm parity:ts-eslint:badges
pnpm parity:ts-eslint:status
pnpm parity:ts-eslint:ci-summary
pnpm parity:ts-eslint:doctor
```

The checkers validate:
- tracker/worklist/summary/metadata/manifest/index/issue-plan coherence,
- issue-body structure/counts,
- CI summary rendering consistency,
- parity command/docs/script synchronization,
- exact parity command inventory in `package.json` vs checker expectations,
- CI workflow wiring (required parity checks and uploaded artifact bundle paths),
- status/badge schema, health reason, and summary arithmetic coherence.

`parity:ts-eslint:check:all` additionally runs metadata-pinned reproducibility verification when parity artifacts are clean.

### Compare parity progress between snapshots

```bash
# compare current tracker against tracker from previous commit
pnpm parity:ts-eslint:diff -- --base-ref HEAD~1
```

Outputs:

- `typescript-eslint-rule-parity-diff.md`

### Rebuild artifacts from pinned metadata commit

```bash
pnpm parity:ts-eslint:rebuild-metadata
pnpm parity:ts-eslint:verify-clean
```

This rebuilds artifacts using `upstream_commit` from
`typescript-eslint-rule-parity-metadata.json` and is useful for
reproducibility checks.

`parity:ts-eslint:verify-clean` additionally asserts there is no parity-artifact diff after rebuild.

By default it expects parity artifacts to be clean before running. To bypass precheck:

```bash
PARITY_VERIFY_ALLOW_DIRTY=1 pnpm parity:ts-eslint:verify-clean
```

### Generate GitHub issue tasklist snippets by phase

```bash
pnpm parity:ts-eslint:tasklist --phase A_critical
pnpm parity:ts-eslint:tasklist:all
pnpm parity:ts-eslint:top
pnpm parity:ts-eslint:manifest
```

Outputs:

- `typescript-eslint-rule-parity-tasklist-<phase>.md`

Note: `pnpm parity:ts-eslint` generates all four phase tasklist files automatically.

### Generate a complete issue body from phase tasklist

```bash
pnpm parity:ts-eslint:issue-body --phase A_critical
pnpm parity:ts-eslint:issue-body:all
```

Outputs:

- `typescript-eslint-rule-parity-issue-body-<phase>.md`

Note: `pnpm parity:ts-eslint` generates all four phase issue-body files automatically.

### Direct script usage

```bash
python3 scripts/generate_ts_eslint_parity_tracker.py
python3 scripts/generate_ts_eslint_parity_worklist.py
python3 scripts/generate_ts_eslint_parity_top.py
python3 scripts/generate_ts_eslint_parity_commands.py
python3 scripts/generate_ts_eslint_parity_badges.py
python3 scripts/generate_ts_eslint_parity_status.py
python3 scripts/generate_ts_eslint_parity_doctor.py
python3 scripts/generate_ts_eslint_parity_summary.py
python3 scripts/generate_ts_eslint_parity_metadata.py
python3 scripts/generate_ts_eslint_parity_manifest.py
python3 scripts/generate_ts_eslint_parity_index.py
python3 scripts/generate_ts_eslint_parity_issue_plan.py
python3 scripts/check_ts_eslint_parity_artifacts.py
python3 scripts/check_ts_eslint_parity_tooling_sync.py
bash scripts/check_ts_eslint_parity_all.sh
python3 scripts/compare_ts_eslint_parity_trackers.py --base-ref HEAD~1
python3 scripts/generate_ts_eslint_parity_issue_tasklist.py --phase A_critical
python3 scripts/generate_ts_eslint_parity_issue_body.py --phase A_critical
bash scripts/rebuild_ts_eslint_parity_from_metadata.sh
bash scripts/verify_ts_eslint_parity_clean.sh
python3 scripts/generate_ts_eslint_parity_ci_summary.py
```

## Typical workflow

1. Run `pnpm parity:ts-eslint`.
2. Review:
   - summary dashboard,
   - top-priority entries in worklist,
   - phase-based issue plan checklist,
   - detailed rows in tracker.
3. Implement parity fixes.
4. Re-run `pnpm parity:ts-eslint`.
5. Confirm checker passes (tracker/worklist/summary/metadata/manifest/index/issue-plan consistency).
6. Commit updated artifacts.

## CI behavior

Workflow: `.github/workflows/parity-artifacts-check.yml`

- Runs the parity artifact checker on parity-related changes.
- Ensures tracker/summary/worklist/metadata/manifest/index/issue-plan remain synchronized.
- On pull requests, also generates `typescript-eslint-rule-parity-diff.md`
  against the PR base branch and uploads it as a workflow artifact.
- On pull requests, uploads a full parity artifact bundle
  (`typescript-eslint-parity-artifacts`) for review.
- CI also rebuilds artifacts from metadata-pinned upstream commit and checks
  that parity artifacts remain unchanged.
- CI writes a concise parity status block into GitHub job summary.
- CI summary includes computed health (`red`/`yellow`/`green`) and reason from status artifact.
- CI appends parity doctor diagnosis into GitHub job summary.
- Issue template available:
  - `.github/ISSUE_TEMPLATE/4-ts-eslint-parity-tracking.en-US.yml`

## Notes

- This toolkit is designed for parity maintenance, not runtime correctness proof.
- Heuristic flags (for fixes/suggestions) should still be confirmed against source-level behavior when implementing changes.
