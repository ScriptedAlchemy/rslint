# TypeScript-ESLint Parity Issue Plan

This plan is generated from `typescript-eslint-rule-parity-tracker.json`.
Use it to create and track GitHub issues by execution phase.

## Suggested labels

- `area:typescript-eslint-parity`
- `kind:parity`
- `kind:test` (when coverage/test parity is the main gap)
- `kind:fixer` (for autofix/suggestion parity)
- `priority:critical|high|medium|low`

## A_critical (5 rules)

Suggested issue title: `Parity: complete A_critical rule backlog`

Checklist:

- [ ] `no-useless-default-assignment` (score 40) — restore invalid-case coverage (3/23); backfill upstream test scenarios (47/795); verify/restore autofix parity (0/23)
- [ ] `no-duplicate-enum-values` (score 34) — restore invalid-case coverage (5/15); backfill upstream test scenarios (170/415)
- [ ] `no-unused-private-class-members` (score 34) — restore invalid-case coverage (1/46); backfill upstream test scenarios (31/1313)
- [ ] `strict-void-return` (score 34) — restore invalid-case coverage (4/109); backfill upstream test scenarios (66/2735)
- [ ] `no-unused-vars` (score 32) — add missing JS parity test files; verify/restore autofix parity (0/41); verify/restore suggestion parity (0/20)

Issue notes template:

```md
Labels: area:typescript-eslint-parity, kind:parity, priority:critical

Acceptance criteria:
- Go tests pass for touched rules.
- JS parity tests pass for touched rules.
- Parity artifacts are regenerated.
- `pnpm parity:ts-eslint:check` passes.
```

## B_high (6 rules)

Suggested issue title: `Parity: complete B_high rule backlog`

Checklist:

- [ ] `prefer-optional-chain` (score 30) — restore invalid-case coverage (128/247); backfill upstream test scenarios (2114/3715); verify/restore autofix parity (145/262); verify/restore suggestion parity (123/237)
- [ ] `await-thenable` (score 26) — restore invalid-case coverage (18/43); backfill upstream test scenarios (764/1392)
- [ ] `no-loss-of-precision` (score 20) — add missing Go tests
- [ ] `no-confusing-void-expression` (score 19) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (2); remove/justify extra JS skip markers (delta 1)
- [ ] `no-duplicate-type-constituents` (score 19) — remove/resolve Go Skip:true cases (2); close TODO/FIXME parity debt (1); remove/justify extra JS skip markers (delta 2)
- [ ] `no-unsafe-member-access` (score 18) — restore invalid-case coverage (15/20); backfill upstream test scenarios (380/500)

Issue notes template:

```md
Labels: area:typescript-eslint-parity, kind:parity, priority:high

Acceptance criteria:
- Go tests pass for touched rules.
- JS parity tests pass for touched rules.
- Parity artifacts are regenerated.
- `pnpm parity:ts-eslint:check` passes.
```

## C_medium (18 rules)

Suggested issue title: `Parity: complete C_medium rule backlog`

Checklist:

- [ ] `no-base-to-string` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (2)
- [ ] `no-misused-promises` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (12)
- [ ] `no-misused-spread` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (2)
- [ ] `no-unnecessary-type-arguments` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (1)
- [ ] `no-unsafe-assignment` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (3)
- [ ] `only-throw-error` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (2)
- [ ] `prefer-promise-reject-errors` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (2)
- [ ] `unbound-method` (score 13) — remove/resolve Go Skip:true cases (2); close TODO/FIXME parity debt (2)
- [ ] `use-unknown-in-catch-callback-variable` (score 13) — remove/resolve Go Skip:true cases (1); close TODO/FIXME parity debt (1)
- [ ] `consistent-indexed-object-style` (score 12) — verify/restore autofix parity (53/54); verify/restore suggestion parity (2/2)
- [ ] `consistent-type-assertions` (score 12) — verify/restore autofix parity (72/72); verify/restore suggestion parity (39/39)
- [ ] `explicit-member-accessibility` (score 12) — verify/restore autofix parity (117/117); verify/restore suggestion parity (28/28)
- [ ] `no-unnecessary-template-expression` (score 11) — verify/restore autofix parity (117/117); close TODO/FIXME parity debt (1)
- [ ] `no-unnecessary-type-assertion` (score 11) — verify/restore autofix parity (64/67); close TODO/FIXME parity debt (1)
- [ ] `no-unsafe-enum-comparison` (score 11) — verify/restore suggestion parity (19/16); close TODO/FIXME parity debt (20)
- [ ] `promise-function-async` (score 11) — verify/restore autofix parity (24/26); close TODO/FIXME parity debt (2)
- [ ] `require-await` (score 11) — verify/restore suggestion parity (33/33); close TODO/FIXME parity debt (2)
- [ ] `switch-exhaustiveness-check` (score 11) — verify/restore suggestion parity (48/47); close TODO/FIXME parity debt (1)

Issue notes template:

```md
Labels: area:typescript-eslint-parity, kind:parity, priority:medium

Acceptance criteria:
- Go tests pass for touched rules.
- JS parity tests pass for touched rules.
- Parity artifacts are regenerated.
- `pnpm parity:ts-eslint:check` passes.
```

## D_low (31 rules)

Suggested issue title: `Parity: complete D_low rule backlog`

Checklist:

- [ ] `no-empty-function` (score 8) — backfill upstream test scenarios (199/269)
- [ ] `array-type` (score 6) — remove/justify extra JS skip markers (delta 2)
- [ ] `consistent-generic-constructors` (score 6) — verify/restore autofix parity (34/35)
- [ ] `consistent-type-definitions` (score 6) — verify/restore autofix parity (23/23)
- [ ] `consistent-type-exports` (score 6) — verify/restore autofix parity (23/25)
- [ ] `consistent-type-imports` (score 6) — verify/restore autofix parity (74/74)
- [ ] `method-signature-style` (score 6) — verify/restore autofix parity (29/34)
- [ ] `no-empty-interface` (score 6) — verify/restore suggestion parity (1/1)
- [ ] `no-empty-object-type` (score 6) — verify/restore suggestion parity (21/21)
- [ ] `no-import-type-side-effects` (score 6) — verify/restore autofix parity (4/4)
- [ ] `no-non-null-assertion` (score 6) — verify/restore suggestion parity (25/26)
- [ ] `no-restricted-types` (score 6) — verify/restore suggestion parity (0/0)
- [ ] `no-unnecessary-condition` (score 6) — verify/restore suggestion parity (51/51)
- [ ] `no-unnecessary-qualifier` (score 6) — verify/restore autofix parity (9/9)
- [ ] `no-unnecessary-type-constraint` (score 6) — verify/restore suggestion parity (23/23)
- [ ] `no-unnecessary-type-conversion` (score 6) — verify/restore suggestion parity (26/28)
- [ ] `no-unnecessary-type-parameters` (score 6) — verify/restore suggestion parity (76/76)
- [ ] `no-wrapper-object-types` (score 6) — verify/restore autofix parity (14/14)
- [ ] `prefer-enum-initializers` (score 6) — verify/restore suggestion parity (5/5)
- [ ] `prefer-find` (score 6) — verify/restore suggestion parity (28/28)
- [ ] `prefer-function-type` (score 6) — verify/restore autofix parity (18/18)
- [ ] `prefer-nullish-coalescing` (score 6) — verify/restore suggestion parity (140/142)
- [ ] `prefer-regexp-exec` (score 6) — verify/restore autofix parity (10/10)
- [ ] `prefer-return-this-type` (score 6) — verify/restore autofix parity (12/13)
- [ ] `strict-boolean-expressions` (score 6) — verify/restore suggestion parity (105/105)
- [ ] `naming-convention` (score 5) — close TODO/FIXME parity debt (3)
- [ ] `no-floating-promises` (score 5) — close TODO/FIXME parity debt (1)
- [ ] `no-unsafe-argument` (score 5) — close TODO/FIXME parity debt (1)
- [ ] `restrict-template-expressions` (score 5) — close TODO/FIXME parity debt (1)
- [ ] `sort-type-constituents` (score 5) — close TODO/FIXME parity debt (2)
- [ ] `ban-types` (score 4) — decide local-only rule policy

Issue notes template:

```md
Labels: area:typescript-eslint-parity, kind:parity, priority:low

Acceptance criteria:
- Go tests pass for touched rules.
- JS parity tests pass for touched rules.
- Parity artifacts are regenerated.
- `pnpm parity:ts-eslint:check` passes.
```

## Post-phase housekeeping

After closing a phase:
1. Run `pnpm parity:ts-eslint` to refresh all artifacts.
2. Run `pnpm parity:ts-eslint:check`.
3. Confirm phase counts and top-priority ordering changed as expected.

