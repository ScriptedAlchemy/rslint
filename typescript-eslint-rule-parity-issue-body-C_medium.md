## TypeScript-ESLint Parity — C_medium

### Context
- Source artifacts: parity tracker/worklist/issue-plan generated from toolkit.
- Goal: reduce parity gaps for this phase and refresh artifacts.

### Labels
- `area:typescript-eslint-parity`
- `kind:parity`
- `priority:medium`

### Tasklist

```[tasklist]
### C_medium parity tasks
- [ ] no-base-to-string (score 13) — go-skip 1, todo 2
- [ ] no-misused-promises (score 13) — go-skip 1, todo 12
- [ ] no-misused-spread (score 13) — go-skip 1, todo 2
- [ ] no-unnecessary-type-arguments (score 13) — go-skip 1, todo 1
- [ ] no-unsafe-assignment (score 13) — go-skip 1, todo 3
- [ ] only-throw-error (score 13) — go-skip 1, todo 2
- [ ] prefer-promise-reject-errors (score 13) — go-skip 1, todo 2
- [ ] unbound-method (score 13) — go-skip 2, todo 2
- [ ] use-unknown-in-catch-callback-variable (score 13) — go-skip 1, todo 1
- [ ] consistent-indexed-object-style (score 12) — fix 53/54, suggestions 2/2
- [ ] consistent-type-assertions (score 12) — fix 72/72, suggestions 39/39
- [ ] explicit-member-accessibility (score 12) — fix 117/117, suggestions 28/28
- [ ] no-unnecessary-template-expression (score 11) — fix 117/117, todo 1
- [ ] no-unnecessary-type-assertion (score 11) — fix 64/67, todo 1
- [ ] no-unsafe-enum-comparison (score 11) — suggestions 19/16, todo 20
- [ ] promise-function-async (score 11) — fix 24/26, todo 2
- [ ] require-await (score 11) — suggestions 33/33, todo 2
- [ ] switch-exhaustiveness-check (score 11) — suggestions 48/47, todo 1
```

### Acceptance criteria
- [ ] Go tests pass for touched rules.
- [ ] JS parity tests pass for touched rules.
- [ ] Parity artifacts regenerated (`pnpm parity:ts-eslint`).
- [ ] Consistency checks pass (`pnpm parity:ts-eslint:check`).

