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

## Top priority rules (immediate focus)
1. `no-useless-default-assignment` — severe invalid/test-size gap + fix parity risk.
2. `no-duplicate-enum-values` — severe invalid/test-size gap.
3. `no-unused-private-class-members` — severe invalid/test-size gap.
4. `strict-void-return` — severe invalid/test-size gap.
5. `no-unused-vars` — missing JS test artifact + fix/suggestion parity risk.
6. `prefer-optional-chain` — moderate invalid/test-size gap + fix/suggestion risk.
7. `await-thenable` — invalid coverage gap.
8. `no-loss-of-precision` — missing Go test coverage.

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

## Deliverables to keep in this cleaned state
- `typescript-eslint-rule-parity-report.md` (this file)
- `typescript-eslint-rule-parity-summary.md` (dashboard snapshot)
- `typescript-eslint-rule-parity-issues-review.md` (action-focused issue list)
