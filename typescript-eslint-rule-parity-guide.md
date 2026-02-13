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
pnpm parity:ts-eslint:check:fast
pnpm parity:ts-eslint:check:all
pnpm parity:ts-eslint:check:clean
pnpm parity:ts-eslint:check:strict
pnpm parity:ts-eslint:check:strict:yellow
pnpm parity:ts-eslint:check:strict:clean
pnpm parity:ts-eslint:check:strict:yellow:clean
pnpm parity:ts-eslint:gate
pnpm parity:ts-eslint:gate:red
pnpm parity:ts-eslint:gate:yellow
pnpm parity:ts-eslint:gate:quick
pnpm parity:ts-eslint:gate:quick:red
pnpm parity:ts-eslint:gate:quick:yellow
pnpm parity:ts-eslint:check:tooling
pnpm parity:ts-eslint:commands
pnpm parity:ts-eslint:badges
pnpm parity:ts-eslint:status
pnpm parity:ts-eslint:status:strict
pnpm parity:ts-eslint:status:strict:yellow
pnpm parity:ts-eslint:ci-summary
pnpm parity:ts-eslint:ci-summary:json
pnpm parity:ts-eslint:ci-summary:strict
pnpm parity:ts-eslint:ci-summary:strict:yellow
pnpm parity:ts-eslint:doctor
pnpm parity:ts-eslint:doctor:markdown
pnpm parity:ts-eslint:doctor:json
pnpm parity:ts-eslint:doctor:json:strict
pnpm parity:ts-eslint:doctor:json:strict:yellow
pnpm parity:ts-eslint:doctor:strict
pnpm parity:ts-eslint:doctor:strict:yellow
```

The checkers validate:
- tracker/worklist/summary/metadata/manifest/index/issue-plan coherence,
- issue-body structure/counts,
- CI summary rendering consistency (markdown + JSON + npm wrapper parity, including direct+strict-wrapper exact non-empty-line stdout parity against direct strict baselines, strict exit behavior, component-prefixed health-reason stderr contracts with line-for-line strict stderr parity, shared argparse wrapper-contract checks for long+short+duplicate-help forwarding parity and help-vs-unknown precedence parity (including duplicate-help+unknown mixed tails) plus unknown-ordering/duplicate-unknown-token forwarding parity against direct-script baselines, silent-wrapper output-noise guards, and success-mode stderr silence across direct+wrapper commands, plus optional diff metrics when diff artifact exists),
- optional diff artifact summary consistency between markdown and JSON outputs,
- parity doctor output consistency (plain + markdown + JSON forms + npm wrapper parity, including direct+strict-wrapper exact non-empty-line stdout parity against direct strict baselines + line-for-line strict stderr parity + shared argparse wrapper-contract checks for long+short+duplicate-help forwarding parity and help-vs-unknown precedence parity (including duplicate-help+unknown mixed tails) plus unknown-ordering/duplicate-unknown-token forwarding parity against direct-script baselines + silent-wrapper output-noise guards + success-mode stderr silence across direct+wrapper commands),
- parity doctor strict-mode exit behavior (`--fail-on-critical` / `--fail-on-yellow`) with strict-wrapper stdout parity + component-prefixed health-reason stderr contracts (including npm wrapper strict commands),
- unified gate script exit and argument/help validation behavior (including missing/invalid/duplicate threshold handling, duplicate `--skip-checks` handling, default-red behavior, `--threshold=<value>` parsing, reordered flag parsing, short-help support, exact usage-line-once stderr contracts with threshold-form + skip-checks tokens + exact two-line error/usage block parity + equivalent-form stderr parity (inline/spaced), direct-script conflict-order precedence checks, direct unknown-vs-duplicate/help precedence checks (short+long help; missing/empty/invalid threshold tails after help/unknown, including trailing help/unknown tokens), and gate npm wrapper contracts (default `gate` alias + explicit `gate:red|yellow` + quick variants) for help (short+long)/unknown-arg/duplicate-threshold/duplicate-skip-checks forwarding parity + help-vs-duplicate precedence parity + spaced-vs-inline duplicate-threshold forwarding parity + duplicate-threshold and duplicate-skip-checks precedence parity for malformed forwarded threshold values (missing/empty/invalid; inline+spaced; with/without trailing skip-checks tokens and trailing help/unknown tokens) + wrapper conflict-order precedence parity (`--threshold=... --skip-checks` vs `--skip-checks --threshold=...`) + wrapper unknown-vs-duplicate/help precedence parity (inline+spaced threshold forms; short+long help forms; missing/empty/invalid threshold tails after help/unknown, including trailing help/unknown tokens) + spaced-vs-inline conflict-order parity + cross-wrapper and direct-script stderr parity baselines for those forwarding paths + exit+skip-checks+threshold-marker+health-reason/success-marker behavior + exact non-empty-line combined-output parity + stream-specific stdout/stderr parity + prefixed-output parity with direct and alternate skip-check runs + silent-wrapper output-noise guards + success-mode stderr silence + no success marker on failing exits, all of which must not run strict clean checks),
- parity command/docs/script synchronization,
- exact parity command inventory in `package.json` vs checker expectations,
- command alias invariants for gate shorthands (`gate == gate:red`, `gate:quick == gate:quick:red`) including runtime return-code/stdout/stderr/prefixed-output parity checks,
- command reference row/backing-script mapping parity with `package.json`,
- CI workflow wiring (required parity checks, trigger paths, diff generation/upload paths, and uploaded artifact bundle paths),
- status/badge schema, health reason, strict-exit behavior with component-prefixed stderr contracts (including npm wrapper strict commands), shared argparse wrapper-contract checks for long+short+duplicate-help forwarding parity and help-vs-unknown precedence parity (including duplicate-help+unknown mixed tails) plus unknown-ordering/duplicate-unknown-token forwarding parity against direct-script baselines across status wrappers, status artifact-write stability + exact single-line stdout/write-line format/parity across non-strict/strict/direct/wrapper status commands, and summary arithmetic coherence.

`parity:ts-eslint:check:all` additionally runs metadata-pinned reproducibility verification when parity artifacts are clean.
`parity:ts-eslint:check:fast` runs artifact+tooling checks only (no reproducibility rebuild).
`parity:ts-eslint:check:clean` enforces a clean parity-artifact tree before reproducibility verification.
`parity:ts-eslint:check:strict` additionally fails when critical backlog remains.
`parity:ts-eslint:check:strict:yellow` additionally fails when health is yellow or red.
`parity:ts-eslint:check:strict:clean` combines strict critical-backlog gating with clean-tree reproducibility enforcement.
`parity:ts-eslint:check:strict:yellow:clean` combines yellow-or-worse gating with clean-tree reproducibility enforcement.
`parity:ts-eslint:gate` is shorthand for `gate:red`.
`parity:ts-eslint:gate:red` runs strict clean checks then applies red-threshold status+doctor gates.
`parity:ts-eslint:gate:yellow` runs strict clean checks then applies yellow-threshold status+doctor gates.
`parity:ts-eslint:gate:quick` is shorthand for `gate:quick:red`.
`parity:ts-eslint:gate:quick:red` runs red-threshold status+doctor gates without strict clean checks.
`parity:ts-eslint:gate:quick:yellow` runs yellow-threshold status+doctor gates without strict clean checks.
`parity:ts-eslint:status:strict` additionally fails when computed parity health is red.
`parity:ts-eslint:status:strict:yellow` additionally fails when computed parity health is yellow or red.
`parity:ts-eslint:ci-summary:strict` additionally fails when computed parity health is red.
`parity:ts-eslint:ci-summary:strict:yellow` additionally fails when computed parity health is yellow or red.
`parity:ts-eslint:doctor:strict:yellow` and `doctor:json:strict:yellow` additionally fail when computed parity health is yellow or red.

### Compare parity progress between snapshots

```bash
# compare current tracker against tracker from previous commit
pnpm parity:ts-eslint:diff
pnpm parity:ts-eslint:diff --base-ref HEAD~1
pnpm parity:ts-eslint:diff:json
pnpm parity:ts-eslint:diff:json --base-ref HEAD~1

# refresh canonical diff artifacts at repository root
pnpm parity:ts-eslint:diff:refresh
```

Outputs:

- `typescript-eslint-rule-parity-diff.md`
- `typescript-eslint-rule-parity-diff.json` (when `--output-json` is supplied, including via `diff:json`)

If no baseline is provided, diff commands default to `HEAD~1` and automatically
fall back to `HEAD` when `HEAD~1` is unavailable.

### Rebuild artifacts from pinned metadata commit

```bash
pnpm parity:ts-eslint:rebuild-metadata
pnpm parity:ts-eslint:verify-clean
```

This rebuilds artifacts using `upstream_commit` from
`typescript-eslint-rule-parity-metadata.json` and is useful for
reproducibility checks.

`parity:ts-eslint:verify-clean` additionally asserts parity artifact status is clean after rebuild
(including modified and untracked parity artifact files).

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
- On pull requests, also generates:
  - `typescript-eslint-rule-parity-diff.md`
  - `typescript-eslint-rule-parity-diff.json`
  against the PR base branch and uploads them in the parity diff artifact.
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
