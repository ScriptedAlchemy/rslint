## TypeScript-ESLint Parity — A_critical

### Context
- Source artifacts: parity tracker/worklist/issue-plan generated from toolkit.
- Goal: reduce parity gaps for this phase and refresh artifacts.

### Labels
- `area:typescript-eslint-parity`
- `kind:parity`
- `priority:critical`

### Tasklist

```[tasklist]
### A_critical parity tasks
- [ ] no-useless-default-assignment (score 40) — errors 3/23, size 47/795, fix 0/23
- [ ] no-duplicate-enum-values (score 34) — errors 5/15, size 170/415
- [ ] no-unused-private-class-members (score 34) — errors 1/46, size 31/1313
- [ ] strict-void-return (score 34) — errors 4/109, size 66/2735
- [ ] no-unused-vars (score 32) — missing JS test files, fix 0/41, suggestions 0/20
```

### Acceptance criteria
- [ ] Go tests pass for touched rules.
- [ ] JS parity tests pass for touched rules.
- [ ] Parity artifacts regenerated (`pnpm parity:ts-eslint`).
- [ ] Consistency checks pass (`pnpm parity:ts-eslint:check`).

