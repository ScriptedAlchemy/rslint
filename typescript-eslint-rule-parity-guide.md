# TypeScript-ESLint Parity Toolkit Guide

This repository includes a parity toolkit to compare upstream
`typescript-eslint` rules against local Go ports and test suites.

## What this toolkit produces

After running the refresh command, the following artifacts are generated at repo root:

- `typescript-eslint-rule-parity-report.md` — narrative audit report.
- `typescript-eslint-rule-parity-tracker.csv` — machine-readable row dataset.
- `typescript-eslint-rule-parity-tracker.json` — JSON form of tracker data.
- `typescript-eslint-rule-parity-worklist.md` — execution checklist grouped by phase.
- `typescript-eslint-rule-parity-summary.md` — dashboard with headline metrics and top priorities.
- `typescript-eslint-rule-parity-metadata.json` — run metadata (timestamp, upstream SHA, requested ref, counters).

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

### Run consistency checks only

```bash
pnpm parity:ts-eslint:check
```

### Direct script usage

```bash
python3 scripts/generate_ts_eslint_parity_tracker.py
python3 scripts/generate_ts_eslint_parity_worklist.py
python3 scripts/generate_ts_eslint_parity_summary.py
python3 scripts/generate_ts_eslint_parity_metadata.py
python3 scripts/check_ts_eslint_parity_artifacts.py
```

## Typical workflow

1. Run `pnpm parity:ts-eslint`.
2. Review:
   - summary dashboard,
   - top-priority entries in worklist,
   - detailed rows in tracker.
3. Implement parity fixes.
4. Re-run `pnpm parity:ts-eslint`.
5. Confirm checker passes and commit updated artifacts.

## CI behavior

Workflow: `.github/workflows/parity-artifacts-check.yml`

- Runs the parity artifact checker on parity-related changes.
- Ensures tracker/summary/worklist/metadata remain synchronized.

## Notes

- This toolkit is designed for parity maintenance, not runtime correctness proof.
- Heuristic flags (for fixes/suggestions) should still be confirmed against source-level behavior when implementing changes.
