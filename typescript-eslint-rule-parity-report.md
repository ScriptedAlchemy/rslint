# TypeScript-ESLint Rule Parity Audit Report (Condensed)
_Last reviewed: 2026-02-13_

## Purpose
This is the retained, human-readable parity report after cleanup of parity automation artifacts.
It summarizes the most important parity findings and remediation priorities.

## Current snapshot
- Total tracked rules: **135**
- Rules flagged for correction: **60**
- Rules currently aligned: **75**

### Priority phase distribution
- **A_critical:** 5
- **B_high:** 6
- **C_medium:** 18
- **D_low:** 31

## Most common parity flags
| Flag | Rules |
|---|---:|
| `todo_markers` | 22 |
| `fix_gap_suspected` | 20 |
| `suggestion_gap_suspected` | 20 |
| `go_skips` | 11 |
| `severe_invalid_gap` | 5 |
| `severe_js_size_gap` | 4 |
| `moderate_js_size_gap` | 4 |
| `extra_js_skips` | 3 |
| `moderate_invalid_gap` | 2 |
| `missing_js_file` | 1 |
| `missing_go_test` | 1 |
| `local_only_rule` | 1 |

## Top priority rules (immediate focus)
1. `no-useless-default-assignment` — severe invalid/test-size gap + fix parity risk.
2. `no-duplicate-enum-values` — severe invalid/test-size gap.
3. `no-unused-private-class-members` — severe invalid/test-size gap.
4. `strict-void-return` — severe invalid/test-size gap.
5. `no-unused-vars` — missing JS test artifact + fix/suggestion parity risk.
6. `prefer-optional-chain` — moderate invalid/test-size gap + fix/suggestion risk.
7. `await-thenable` — invalid coverage gap.
8. `no-loss-of-precision` — missing Go test coverage.
9. `no-confusing-void-expression` — extra JS skips + Go skips + TODO debt.
10. `no-duplicate-type-constituents` — extra JS skips + Go skips + TODO debt.

## Key problem categories

### 1) Coverage mismatch with upstream
- Several rules still show large JS invalid-case/test-size deltas vs upstream.
- Most acute risk is in `A_critical` rules.

### 2) Fix/suggestion parity risk
- Multiple rules are flagged with suspected autofix/suggestion parity gaps.
- These require explicit branch-by-branch behavior comparison.

### 3) Skip/TODO debt
- Remaining Go/JS skipped tests and TODO/FIXME markers indicate known unclosed parity work.

### 4) Missing test artifacts
- Known holes still include:
  - `no-unused-vars` missing local JS parity artifact.
  - `no-loss-of-precision` missing Go tests.

### 5) Rule inventory drift
- `ban-types` appears as local-only relative to current upstream rule inventory.

## Execution order
1. Close all `A_critical` rules.
2. Resolve `B_high` rules with missing assets and semantic parity gaps.
3. Burn down `C_medium` skip/TODO debt.
4. Finish `D_low` residual parity cleanup and reassess.

## Phase exit criteria (definition of done)

### A_critical exit criteria
- All severe invalid/test-size gaps in `A_critical` are closed or explicitly justified.
- Missing test assets are restored (`no-unused-vars` JS artifact, `no-loss-of-precision` Go tests).
- Any rule with fix/suggestion risk in this phase has explicit parity assertions added.

### B_high exit criteria
- High-risk semantic deltas have parity tests that match upstream intent.
- No new skip markers are introduced.
- Fix/suggestion parity branches are covered by deterministic assertions.

### C_medium exit criteria
- `go_skips` and `extra_js_skips` are reduced to zero, or each remaining case has documented rationale.
- TODO/FIXME markers tied to parity are resolved or converted into tracked issues.

### D_low exit criteria
- Remaining drift is either closed or documented as intentional local divergence.
- Rule inventory decisions (including local-only `ban-types`) are finalized and documented.

## Concrete remediation checklist
- [ ] Port/restore missing `no-unused-vars` JS test artifact.
- [ ] Add/port Go tests for `no-loss-of-precision`.
- [ ] Address top 7 parity-risk rules (scores 26+), with full invalid/fix parity validation.
- [ ] Reduce `go_skips` from 11 to 0 (or document justified exceptions).
- [ ] Resolve TODO/FIXME debt on the 22 flagged rules.
- [ ] Decide whether `ban-types` remains intentionally local-only; if yes, document rationale clearly.

## Validation expectations per rule change
- Run targeted Go tests for the touched rule directory.
- Re-run affected JS parity rule tests and verify invalid/fix/suggestion assertions.
- Confirm no unintended increase in skip counts or TODO/FIXME markers.
- Update this report snapshot numbers when backlog counts materially change.

## Final retained markdown deliverables
- `typescript-eslint-rule-parity-report.md` (this file)
