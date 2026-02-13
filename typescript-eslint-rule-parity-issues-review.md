# TypeScript-ESLint Parity — Issues & Problems Review

## Executive snapshot
- Total tracked rules: **135**
- Rules currently flagged for correction: **60**
- Rules currently aligned: **75**
- Phase backlog:
  - **A_critical:** 5
  - **B_high:** 6
  - **C_medium:** 18
  - **D_low:** 31

## Highest-risk items to address first
These are the highest-priority rules where parity risk is currently most concentrated:

1. `no-useless-default-assignment` (40) — severe JS test-size + invalid-case gap, plus suspected fix gap.
2. `no-duplicate-enum-values` (34) — severe JS test-size + invalid-case gap.
3. `no-unused-private-class-members` (34) — severe JS test-size + invalid-case gap.
4. `strict-void-return` (34) — severe JS test-size + invalid-case gap.
5. `no-unused-vars` (32) — missing local JS test file + suspected fix/suggestion gap.
6. `prefer-optional-chain` (30) — moderate JS size/invalid gap + suspected fix/suggestion gap.
7. `await-thenable` (26) — moderate JS size gap + severe invalid-case gap.
8. `no-loss-of-precision` (20) — missing Go test coverage.
9. `no-confusing-void-expression` (19) — extra JS skips + Go skips + TODO debt.
10. `no-duplicate-type-constituents` (19) — extra JS skips + Go skips + TODO debt.

## Systemic problems observed

### 1) Test parity gaps (coverage and depth)
- Severe/moderate test-size and invalid-case deltas are still present on core high-impact rules.
- Impact: high risk of behavioral drift from upstream rule semantics.

### 2) Fix/suggestion parity uncertainty
- `fix_gap_suspected` and `suggestion_gap_suspected` each appear on **20** rules.
- Impact: user-visible autofix/suggestion UX may diverge even when diagnostics match.

### 3) Skip debt in JS + Go tests
- `go_skips`: **11** rules
- `extra_js_skips`: **3** rules
- Impact: known edge cases are not actively enforced by CI parity checks.

### 4) TODO/FIXME implementation debt
- `todo_markers`: **22** rules
- Impact: known parity work remains intentionally incomplete in implementation/test logic.

### 5) Missing test artifacts
- `missing_js_file`: **1** rule (`no-unused-vars`)
- `missing_go_test`: **1** rule (`no-loss-of-precision`)
- Impact: hard coverage holes in otherwise mature parity workflow.

### 6) Registry drift candidate
- `local_only_rule`: **1** rule (`ban-types`)
- Impact: local inventory no longer cleanly mirrors upstream ruleset shape.

## Recommended remediation order

### Phase A (blockers)
- Close all **A_critical** rules first.
- Required outcome: remove severe test-size/invalid-case deltas and confirm fix behavior parity where flagged.

### Phase B (high leverage)
- Resolve all **B_high** rules, prioritizing:
  - missing test files,
  - rules with both semantic and fix/suggestion parity indicators.

### Phase C (quality hardening)
- Burn down skip/TODO debt (`go_skips`, `extra_js_skips`, `todo_markers`).
- Convert skipped cases into deterministic assertions.

### Phase D (tail cleanup)
- Clear low-severity residual mismatches and reconcile local-only registry drift.

## Concrete checklist for next implementation passes
- [ ] Port/restore missing `no-unused-vars` JS test artifact.
- [ ] Add/port Go tests for `no-loss-of-precision`.
- [ ] Address top 7 parity-risk rules (scores 26+), with full invalid/fix parity validation.
- [ ] Reduce `go_skips` from 11 to 0 (or document justified exceptions).
- [ ] Resolve TODO/FIXME debt on the 22 flagged rules.
- [ ] Decide whether `ban-types` remains intentionally local-only; if yes, document rationale clearly.

