# TypeScript-ESLint Rule Parity Audit Report
_Generated: 2026-02-13 09:47 UTC_

## Scope
- Upstream compared: `typescript-eslint` main branch (`packages/eslint-plugin/src/rules` + `tests/rules`).
- Local compared: Go rules in `internal/plugins/typescript/rules`, registration in `internal/config/config.go`, JS parity tests in `packages/rslint-test-tools/tests/typescript-eslint/rules`.
- This report focuses on structural/coverage parity signals and concrete mismatches requiring correction.

## Inventory Summary
- Upstream rules: **134**
- Local registered `@typescript-eslint/*` rules: **135**
- Local TS rule directories: **135**
- Rules with any detected deviations needing correction: **60**
- Critical deviations: **7**
- Local-only rules not in upstream current rule set: **ban-types**

## Critical Corrections (Must Fix)
- **await-thenable**: severe invalid-case reduction (18/43 `errors:` assertions).
  - Correction: Expand local JS invalid coverage (errors: 18 vs upstream 43).
  - Correction: Noticeable JS test shrinkage; audit omitted upstream scenarios (line ratio 0.549).
- **no-duplicate-enum-values**: severe JS test shrinkage (170/415 non-empty lines); severe invalid-case reduction (5/15 `errors:` assertions).
  - Correction: Expand local JS invalid coverage (errors: 5 vs upstream 15).
  - Correction: Large JS test shrinkage; backfill upstream scenarios (line ratio 0.410).
- **no-loss-of-precision**: missing Go unit tests.
  - Correction: Add Go unit tests for this rule (at least parity smoke + representative invalid/valid cases).
- **no-unused-private-class-members**: severe JS test shrinkage (31/1313 non-empty lines); severe invalid-case reduction (1/46 `errors:` assertions).
  - Correction: Expand local JS invalid coverage (errors: 1 vs upstream 46).
  - Correction: Large JS test shrinkage; backfill upstream scenarios (line ratio 0.024).
- **no-unused-vars**: missing JS parity test file(s).
  - Correction: Add missing local JS parity test file(s): no-unused-vars/no-unused-vars-enableAutofixRemoval.test.ts.
  - Correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 0 vs upstream 41).
  - Correction: Upstream has suggestions: verify/implement suggestion parity (suggestion assertions 0 vs upstream 20).
- **no-useless-default-assignment**: severe JS test shrinkage (47/795 non-empty lines); severe invalid-case reduction (3/23 `errors:` assertions).
  - Correction: Expand local JS invalid coverage (errors: 3 vs upstream 23).
  - Correction: Large JS test shrinkage; backfill upstream scenarios (line ratio 0.059).
  - Correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 0 vs upstream 23).
- **strict-void-return**: severe JS test shrinkage (66/2735 non-empty lines); severe invalid-case reduction (4/109 `errors:` assertions).
  - Correction: Expand local JS invalid coverage (errors: 4 vs upstream 109).
  - Correction: Large JS test shrinkage; backfill upstream scenarios (line ratio 0.024).

## High-Risk Non-Critical Corrections
- **prefer-optional-chain**: flags = `js-invalid-coverage-reduced, js-test-size-reduced, fix-parity-gap-suspected, suggestion-parity-gap-suspected`.
  - Primary correction: Review reduced local JS invalid coverage (errors: 128 vs upstream 247).
- **no-duplicate-type-constituents**: flags = `extra-js-skips, go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Remove or justify added JS skip markers (2 local vs 0 upstream).
- **no-confusing-void-expression**: flags = `extra-js-skips, go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Remove or justify added JS skip markers (1 local vs 0 upstream).
- **explicit-member-accessibility**: flags = `fix-parity-gap-suspected, suggestion-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 117 vs upstream 117).
- **consistent-type-assertions**: flags = `fix-parity-gap-suspected, suggestion-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 72 vs upstream 72).
- **consistent-indexed-object-style**: flags = `fix-parity-gap-suspected, suggestion-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 53 vs upstream 54).
- **use-unknown-in-catch-callback-variable**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **unbound-method**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=2).
- **switch-exhaustiveness-check**: flags = `todo-fixme-markers, suggestion-parity-gap-suspected`.
  - Primary correction: Resolve TODO/FIXME parity gaps in implementation/tests (markers=1).
- **require-await**: flags = `todo-fixme-markers, suggestion-parity-gap-suspected`.
  - Primary correction: Resolve TODO/FIXME parity gaps in implementation/tests (markers=2).
- **promise-function-async**: flags = `todo-fixme-markers, fix-parity-gap-suspected`.
  - Primary correction: Resolve TODO/FIXME parity gaps in implementation/tests (markers=2).
- **prefer-promise-reject-errors**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **only-throw-error**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **no-unsafe-enum-comparison**: flags = `todo-fixme-markers, suggestion-parity-gap-suspected`.
  - Primary correction: Resolve TODO/FIXME parity gaps in implementation/tests (markers=20).
- **no-unsafe-assignment**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **no-unnecessary-type-assertion**: flags = `todo-fixme-markers, fix-parity-gap-suspected`.
  - Primary correction: Resolve TODO/FIXME parity gaps in implementation/tests (markers=1).
- **no-unnecessary-type-arguments**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **no-unnecessary-template-expression**: flags = `todo-fixme-markers, fix-parity-gap-suspected`.
  - Primary correction: Resolve TODO/FIXME parity gaps in implementation/tests (markers=1).
- **no-misused-spread**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **no-misused-promises**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **no-base-to-string**: flags = `go-skipped-tests, todo-fixme-markers`.
  - Primary correction: Resolve skipped Go test cases (Skip:true count=1).
- **strict-boolean-expressions**: flags = `suggestion-parity-gap-suspected`.
  - Primary correction: Upstream has suggestions: verify/implement suggestion parity (suggestion assertions 105 vs upstream 105).
- **prefer-return-this-type**: flags = `fix-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 12 vs upstream 13).
- **prefer-regexp-exec**: flags = `fix-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 10 vs upstream 10).
- **prefer-nullish-coalescing**: flags = `suggestion-parity-gap-suspected`.
  - Primary correction: Upstream has suggestions: verify/implement suggestion parity (suggestion assertions 140 vs upstream 142).
- **prefer-function-type**: flags = `fix-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 18 vs upstream 18).
- **prefer-find**: flags = `suggestion-parity-gap-suspected`.
  - Primary correction: Upstream has suggestions: verify/implement suggestion parity (suggestion assertions 28 vs upstream 28).
- **prefer-enum-initializers**: flags = `suggestion-parity-gap-suspected`.
  - Primary correction: Upstream has suggestions: verify/implement suggestion parity (suggestion assertions 5 vs upstream 5).
- **no-wrapper-object-types**: flags = `fix-parity-gap-suspected`.
  - Primary correction: Upstream fixable rule: verify/implement missing fix parity (output assertions 14 vs upstream 14).
- **no-unsafe-member-access**: flags = `js-invalid-coverage-reduced, js-test-size-reduced`.
  - Primary correction: Review reduced local JS invalid coverage (errors: 15 vs upstream 20).

## Confirmed Message-ID Parity Gaps (non-base rules)

These are not heuristic-only: each listed message ID exists in upstream rule metadata but is absent in local Go rule source text for the same rule.  
In practice, these usually indicate missing diagnostic variants and/or missing suggestion/fix message wiring.

| Rule | Missing upstream message IDs in local rule |
|---|---|
| `await-thenable` | `invalidPromiseAggregatorInput` |
| `consistent-indexed-object-style` | `preferIndexSignatureSuggestion` |
| `consistent-type-assertions` | `replaceArrayTypeAssertionWithAnnotation`, `replaceArrayTypeAssertionWithSatisfies`, `replaceObjectTypeAssertionWithAnnotation`, `replaceObjectTypeAssertionWithSatisfies` |
| `explicit-member-accessibility` | `addExplicitAccessibility` |
| `no-empty-object-type` | `replaceEmptyInterface`, `replaceEmptyInterfaceWithSuper`, `replaceEmptyObjectType` |
| `no-restricted-types` | `bannedTypeReplacement` |
| `no-unnecessary-condition` | `suggestRemoveOptionalChain` |
| `no-unnecessary-type-constraint` | `removeUnnecessaryConstraint` |
| `no-unnecessary-type-conversion` | `suggestRemove`, `suggestSatisfies` |
| `no-unnecessary-type-parameters` | `replaceUsagesWithConstraint` |
| `no-unsafe-assignment` | `unsafeObjectPattern` |
| `no-unsafe-call` | `errorCall`, `errorCallThis`, `errorNew`, `errorTemplateTag` |
| `no-unsafe-member-access` | `errorComputedMemberAccess`, `errorMemberExpression`, `errorThisMemberExpression` |
| `prefer-enum-initializers` | `defineInitializerSuggestion` |
| `prefer-find` | `preferFindSuggestion` |
| `prefer-optional-chain` | `optionalChainSuggest` |
| `strict-boolean-expressions` | `conditionFixCastBoolean`, `conditionFixCompareArrayLengthNonzero`, `conditionFixCompareArrayLengthZero`, `conditionFixCompareEmptyString`, `conditionFixCompareFalse`, `conditionFixCompareNaN`, `conditionFixCompareNullish`, `conditionFixCompareStringLength`, `conditionFixCompareTrue`, `conditionFixCompareZero`, `conditionFixDefaultEmptyString`, `conditionFixDefaultFalse`, `conditionFixDefaultZero`, `explicitBooleanReturnType` |
| `switch-exhaustiveness-check` | `addMissingCases` |

### Recommended correction workflow for this section
1. For each rule above, diff upstream `messages` + suggestion/fix branches against local Go implementation.
2. Add missing message IDs and wire corresponding diagnostic/suggestion/fix branches.
3. Backfill JS tests to assert the recovered message IDs (especially for suggestion-only branches).
4. Add/expand Go tests to lock each recovered branch.

## Cross-Reference Matrix (Every Rule)

Legend: ✅ none detected, ⚠ needs correction, n/a = not applicable

| Rule | Upstream | Registered | Go test | JS files parity | Invalid coverage | Skip delta (JS) | Go skips | TODO/FIXME | Fix parity signal | Suggestion parity signal | Status |
|---|---:|---:|---:|---|---|---:|---:|---:|---|---|---|
| `adjacent-overload-signatures` | Y | Y | Y | OK | 34/34 | 0 | 0 | 0 | OK | OK | ✅ |
| `array-type` | Y | Y | Y | OK | 105/103 | 2 | 0 | 0 | OK | OK | ⚠ |
| `await-thenable` | Y | Y | Y | OK | 18/43 | 0 | 0 | 0 | OK | OK | ⚠ |
| `ban-ts-comment` | Y | Y | Y | OK | 57/57 | 0 | 0 | 0 | OK | OK | ✅ |
| `ban-tslint-comment` | Y | Y | Y | OK | 8/8 | 0 | 0 | 0 | OK | OK | ✅ |
| `ban-types` | N | Y | Y | OK | n/a | 0 | 0 | 0 | OK | OK | ⚠ |
| `class-literal-property-style` | Y | Y | Y | OK | 19/19 | 0 | 0 | 0 | OK | OK | ✅ |
| `class-methods-use-this` | Y | Y | Y | OK | 62/62 | 0 | 0 | 0 | OK | OK | ✅ |
| `consistent-generic-constructors` | Y | Y | Y | OK | 34/35 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `consistent-indexed-object-style` | Y | Y | Y | OK | 54/55 | 0 | 0 | 0 | ⚠ | ⚠ | ⚠ |
| `consistent-return` | Y | Y | Y | OK | 11/11 | 0 | 0 | 0 | OK | OK | ✅ |
| `consistent-type-assertions` | Y | Y | Y | OK | 101/101 | 0 | 0 | 0 | ⚠ | ⚠ | ⚠ |
| `consistent-type-definitions` | Y | Y | Y | OK | 23/23 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `consistent-type-exports` | Y | Y | Y | OK | 23/25 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `consistent-type-imports` | Y | Y | Y | OK | 74/74 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `default-param-last` | Y | Y | Y | OK | 45/45 | 0 | 0 | 0 | OK | OK | ✅ |
| `dot-notation` | Y | Y | Y | OK | 26/26 | 0 | 0 | 0 | OK | OK | ✅ |
| `explicit-function-return-type` | Y | Y | Y | OK | 59/59 | 0 | 0 | 0 | OK | OK | ✅ |
| `explicit-member-accessibility` | Y | Y | Y | OK | 35/35 | 0 | 0 | 0 | ⚠ | ⚠ | ⚠ |
| `explicit-module-boundary-types` | Y | Y | Y | OK | 64/64 | 0 | 0 | 0 | OK | OK | ✅ |
| `init-declarations` | Y | Y | Y | OK | 26/26 | 0 | 0 | 0 | OK | OK | ✅ |
| `max-params` | Y | Y | Y | OK | 9/9 | 0 | 0 | 0 | OK | OK | ✅ |
| `member-ordering` | Y | Y | Y | OK | 124/124 | 0 | 0 | 0 | OK | OK | ✅ |
| `method-signature-style` | Y | Y | Y | OK | 29/34 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `naming-convention` | Y | Y | Y | OK | 40/48 | 0 | 0 | 3 | OK | OK | ⚠ |
| `no-array-constructor` | Y | Y | Y | OK | 13/13 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-array-delete` | Y | Y | Y | OK | 22/22 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-base-to-string` | Y | Y | Y | OK | 88/93 | 0 | 1 | 2 | OK | OK | ⚠ |
| `no-confusing-non-null-assertion` | Y | Y | Y | OK | 11/11 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-confusing-void-expression` | Y | Y | Y | OK | 57/57 | 1 | 1 | 2 | OK | OK | ⚠ |
| `no-deprecated` | Y | Y | Y | OK | 138/169 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-dupe-class-members` | Y | Y | Y | OK | 10/10 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-duplicate-enum-values` | Y | Y | Y | OK | 5/15 | 0 | 0 | 0 | OK | OK | ⚠ |
| `no-duplicate-type-constituents` | Y | Y | Y | OK | 48/48 | 2 | 2 | 1 | OK | OK | ⚠ |
| `no-dynamic-delete` | Y | Y | Y | OK | 10/10 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-empty-function` | Y | Y | Y | OK | 7/7 | 0 | 0 | 0 | OK | OK | ⚠ |
| `no-empty-interface` | Y | Y | Y | OK | 12/11 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-empty-object-type` | Y | Y | Y | OK | 21/21 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-explicit-any` | Y | Y | Y | OK | 59/59 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-extra-non-null-assertion` | Y | Y | Y | OK | 8/8 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-extraneous-class` | Y | Y | Y | OK | 12/12 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-floating-promises` | Y | Y | Y | OK | 101/101 | -1 | 0 | 1 | OK | OK | ⚠ |
| `no-for-in-array` | Y | Y | Y | OK | 20/20 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-implied-eval` | Y | Y | Y | OK | 22/22 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-import-type-side-effects` | Y | Y | Y | OK | 4/4 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `no-inferrable-types` | Y | Y | Y | OK | 45/45 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-invalid-this` | Y | Y | Y | OK | 1/1 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-invalid-void-type` | Y | Y | Y | OK | 45/45 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-loop-func` | Y | Y | Y | OK | 21/21 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-loss-of-precision` | Y | Y | N | OK | 4/4 | 0 | 0 | 0 | OK | OK | ⚠ |
| `no-magic-numbers` | Y | Y | Y | OK | 36/36 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-meaningless-void-operator` | Y | Y | Y | OK | 3/3 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-misused-new` | Y | Y | Y | OK | 9/6 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-misused-promises` | Y | Y | Y | OK | 90/91 | 0 | 1 | 12 | OK | OK | ⚠ |
| `no-misused-spread` | Y | Y | Y | OK | 91/91 | 0 | 1 | 2 | OK | OK | ⚠ |
| `no-mixed-enums` | Y | Y | Y | OK | 21/21 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-namespace` | Y | Y | Y | OK | 32/32 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-non-null-asserted-nullish-coalescing` | Y | Y | Y | OK | 15/15 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-non-null-asserted-optional-chain` | Y | Y | Y | OK | 10/10 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-non-null-assertion` | Y | Y | Y | OK | 20/22 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-redeclare` | Y | Y | Y | OK | 31/31 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-redundant-type-constituents` | Y | Y | Y | OK | 49/49 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-require-imports` | Y | Y | Y | OK | 22/22 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-restricted-imports` | Y | Y | Y | OK | 27/29 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-restricted-types` | Y | Y | Y | OK | 32/32 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-shadow` | Y | Y | Y | OK | 93/93 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-this-alias` | Y | Y | Y | OK | 6/6 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-type-alias` | Y | Y | Y | OK | 127/127 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unnecessary-boolean-literal-compare` | Y | Y | Y | OK | 28/28 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unnecessary-condition` | Y | Y | Y | OK | 120/120 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-unnecessary-parameter-property-assignment` | Y | Y | Y | OK | 17/17 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unnecessary-qualifier` | Y | Y | Y | OK | 9/9 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `no-unnecessary-template-expression` | Y | Y | Y | OK | 117/117 | 0 | 0 | 1 | ⚠ | OK | ⚠ |
| `no-unnecessary-type-arguments` | Y | Y | Y | OK | 23/23 | 0 | 1 | 1 | OK | OK | ⚠ |
| `no-unnecessary-type-assertion` | Y | Y | Y | OK | 64/67 | 0 | 0 | 1 | ⚠ | OK | ⚠ |
| `no-unnecessary-type-constraint` | Y | Y | Y | OK | 22/22 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-unnecessary-type-conversion` | Y | Y | Y | OK | 26/28 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-unnecessary-type-parameters` | Y | Y | Y | OK | 67/67 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `no-unsafe-argument` | Y | Y | Y | OK | 21/21 | 0 | 0 | 1 | OK | OK | ⚠ |
| `no-unsafe-assignment` | Y | Y | Y | OK | 56/56 | 0 | 1 | 3 | OK | OK | ⚠ |
| `no-unsafe-call` | Y | Y | Y | OK | 21/24 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unsafe-declaration-merging` | Y | Y | Y | OK | 3/3 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unsafe-enum-comparison` | Y | Y | Y | OK | 44/44 | 0 | 0 | 20 | OK | ⚠ | ⚠ |
| `no-unsafe-function-type` | Y | Y | Y | OK | 5/5 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unsafe-member-access` | Y | Y | Y | OK | 15/20 | 0 | 0 | 0 | OK | OK | ⚠ |
| `no-unsafe-return` | Y | Y | Y | OK | 32/32 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unsafe-type-assertion` | Y | Y | Y | OK | 62/62 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unsafe-unary-minus` | Y | Y | Y | OK | 9/9 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unused-expressions` | Y | Y | Y | OK | 23/23 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-unused-private-class-members` | Y | Y | Y | OK | 1/46 | 0 | 0 | 0 | OK | OK | ⚠ |
| `no-unused-vars` | Y | Y | Y | MISS: no-unused-vars/no-unused-vars-enableAutofixRemoval.test.ts | 236/259 | 0 | 0 | 0 | ⚠ | ⚠ | ⚠ |
| `no-use-before-define` | Y | Y | Y | OK | 62/62 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-useless-constructor` | Y | Y | Y | OK | 9/9 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-useless-default-assignment` | Y | Y | Y | OK | 3/23 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `no-useless-empty-export` | Y | Y | Y | OK | 8/8 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-var-requires` | Y | Y | Y | OK | 17/17 | 0 | 0 | 0 | OK | OK | ✅ |
| `no-wrapper-object-types` | Y | Y | Y | OK | 14/14 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `non-nullable-type-assertion-style` | Y | Y | Y | OK | 10/10 | 0 | 0 | 0 | OK | OK | ✅ |
| `only-throw-error` | Y | Y | Y | OK | 44/47 | 0 | 1 | 2 | OK | OK | ⚠ |
| `parameter-properties` | Y | Y | Y | OK | 31/31 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-as-const` | Y | Y | Y | OK | 15/15 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-destructuring` | Y | Y | Y | OK | 37/37 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-enum-initializers` | Y | Y | Y | OK | 4/4 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `prefer-find` | Y | Y | Y | OK | 28/28 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `prefer-for-of` | Y | Y | Y | OK | 18/18 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-function-type` | Y | Y | Y | OK | 18/18 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `prefer-includes` | Y | Y | Y | OK | 29/29 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-literal-enum-member` | Y | Y | Y | OK | 15/15 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-namespace-keyword` | Y | Y | Y | OK | 3/3 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-nullish-coalescing` | Y | Y | Y | OK | 137/139 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `prefer-optional-chain` | Y | Y | Y | OK | 128/247 | 0 | 0 | 0 | ⚠ | ⚠ | ⚠ |
| `prefer-promise-reject-errors` | Y | Y | Y | OK | 82/82 | 0 | 1 | 2 | OK | OK | ⚠ |
| `prefer-readonly` | Y | Y | Y | OK | 82/82 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-readonly-parameter-types` | Y | Y | Y | OK | 39/41 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-reduce-type-parameter` | Y | Y | Y | OK | 14/14 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-regexp-exec` | Y | Y | Y | OK | 10/10 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `prefer-return-this-type` | Y | Y | Y | OK | 12/13 | 0 | 0 | 0 | ⚠ | OK | ⚠ |
| `prefer-string-starts-ends-with` | Y | Y | Y | OK | 67/67 | 0 | 0 | 0 | OK | OK | ✅ |
| `prefer-ts-expect-error` | Y | Y | Y | OK | 8/8 | 0 | 0 | 0 | OK | OK | ✅ |
| `promise-function-async` | Y | Y | Y | OK | 26/28 | 0 | 0 | 2 | ⚠ | OK | ⚠ |
| `related-getter-setter-pairs` | Y | Y | Y | OK | 7/7 | 0 | 0 | 0 | OK | OK | ✅ |
| `require-array-sort-compare` | Y | Y | Y | OK | 16/16 | 0 | 0 | 0 | OK | OK | ✅ |
| `require-await` | Y | Y | Y | OK | 33/33 | 0 | 0 | 2 | OK | ⚠ | ⚠ |
| `restrict-plus-operands` | Y | Y | Y | OK | 60/60 | 0 | 0 | 0 | OK | OK | ✅ |
| `restrict-template-expressions` | Y | Y | Y | OK | 19/22 | 0 | 0 | 1 | OK | OK | ⚠ |
| `return-await` | Y | Y | Y | OK | 43/43 | 0 | 0 | 0 | OK | OK | ✅ |
| `sort-type-constituents` | Y | Y | Y | OK | 19/19 | 0 | 0 | 2 | OK | OK | ⚠ |
| `strict-boolean-expressions` | Y | Y | Y | OK | 117/117 | 0 | 0 | 0 | OK | ⚠ | ⚠ |
| `strict-void-return` | Y | Y | Y | OK | 4/109 | 0 | 0 | 0 | OK | OK | ⚠ |
| `switch-exhaustiveness-check` | Y | Y | Y | OK | 52/51 | 0 | 0 | 1 | OK | ⚠ | ⚠ |
| `triple-slash-reference` | Y | Y | Y | OK | 5/5 | 0 | 0 | 0 | OK | OK | ✅ |
| `typedef` | Y | Y | Y | OK | 34/34 | 0 | 0 | 0 | OK | OK | ✅ |
| `unbound-method` | Y | Y | Y | OK | 51/51 | 0 | 2 | 2 | OK | OK | ⚠ |
| `unified-signatures` | Y | Y | Y | OK | 40/40 | 0 | 0 | 0 | OK | OK | ✅ |
| `use-unknown-in-catch-callback-variable` | Y | Y | Y | OK | 26/26 | 0 | 1 | 1 | OK | OK | ⚠ |

## Correction Backlog by Category

### Registration/Inventory (1 rules)
- `ban-types`: local-only-rule

### Missing test assets (2 rules)
- `no-loss-of-precision`: missing-go-test
- `no-unused-vars`: missing-js-test-file

### JS test coverage reductions (8 rules)
- `await-thenable`: js-invalid-coverage-severe, js-test-size-reduced
- `no-duplicate-enum-values`: js-invalid-coverage-severe, js-test-size-severe
- `no-empty-function`: js-test-size-reduced
- `no-unsafe-member-access`: js-invalid-coverage-reduced, js-test-size-reduced
- `no-unused-private-class-members`: js-invalid-coverage-severe, js-test-size-severe
- `no-useless-default-assignment`: js-invalid-coverage-severe, js-test-size-severe
- `prefer-optional-chain`: js-invalid-coverage-reduced, js-test-size-reduced
- `strict-void-return`: js-invalid-coverage-severe, js-test-size-severe

### Skipped tests (12 rules)
- `array-type`: extra-js-skips
- `no-base-to-string`: go-skipped-tests
- `no-confusing-void-expression`: extra-js-skips, go-skipped-tests
- `no-duplicate-type-constituents`: extra-js-skips, go-skipped-tests
- `no-misused-promises`: go-skipped-tests
- `no-misused-spread`: go-skipped-tests
- `no-unnecessary-type-arguments`: go-skipped-tests
- `no-unsafe-assignment`: go-skipped-tests
- `only-throw-error`: go-skipped-tests
- `prefer-promise-reject-errors`: go-skipped-tests
- `unbound-method`: go-skipped-tests
- `use-unknown-in-catch-callback-variable`: go-skipped-tests

### Known implementation TODO/FIXME gaps (22 rules)
- `naming-convention`: todo-fixme-markers
- `no-base-to-string`: todo-fixme-markers
- `no-confusing-void-expression`: todo-fixme-markers
- `no-duplicate-type-constituents`: todo-fixme-markers
- `no-floating-promises`: todo-fixme-markers
- `no-misused-promises`: todo-fixme-markers
- `no-misused-spread`: todo-fixme-markers
- `no-unnecessary-template-expression`: todo-fixme-markers
- `no-unnecessary-type-arguments`: todo-fixme-markers
- `no-unnecessary-type-assertion`: todo-fixme-markers
- `no-unsafe-argument`: todo-fixme-markers
- `no-unsafe-assignment`: todo-fixme-markers
- `no-unsafe-enum-comparison`: todo-fixme-markers
- `only-throw-error`: todo-fixme-markers
- `prefer-promise-reject-errors`: todo-fixme-markers
- `promise-function-async`: todo-fixme-markers
- `require-await`: todo-fixme-markers
- `restrict-template-expressions`: todo-fixme-markers
- `sort-type-constituents`: todo-fixme-markers
- `switch-exhaustiveness-check`: todo-fixme-markers
- `unbound-method`: todo-fixme-markers
- `use-unknown-in-catch-callback-variable`: todo-fixme-markers

### Autofix parity gaps (suspected) (20 rules)
- `consistent-generic-constructors`: fix-parity-gap-suspected
- `consistent-indexed-object-style`: fix-parity-gap-suspected
- `consistent-type-assertions`: fix-parity-gap-suspected
- `consistent-type-definitions`: fix-parity-gap-suspected
- `consistent-type-exports`: fix-parity-gap-suspected
- `consistent-type-imports`: fix-parity-gap-suspected
- `explicit-member-accessibility`: fix-parity-gap-suspected
- `method-signature-style`: fix-parity-gap-suspected
- `no-import-type-side-effects`: fix-parity-gap-suspected
- `no-unnecessary-qualifier`: fix-parity-gap-suspected
- `no-unnecessary-template-expression`: fix-parity-gap-suspected
- `no-unnecessary-type-assertion`: fix-parity-gap-suspected
- `no-unused-vars`: fix-parity-gap-suspected
- `no-useless-default-assignment`: fix-parity-gap-suspected
- `no-wrapper-object-types`: fix-parity-gap-suspected
- `prefer-function-type`: fix-parity-gap-suspected
- `prefer-optional-chain`: fix-parity-gap-suspected
- `prefer-regexp-exec`: fix-parity-gap-suspected
- `prefer-return-this-type`: fix-parity-gap-suspected
- `promise-function-async`: fix-parity-gap-suspected

### Suggestion parity gaps (suspected) (20 rules)
- `consistent-indexed-object-style`: suggestion-parity-gap-suspected
- `consistent-type-assertions`: suggestion-parity-gap-suspected
- `explicit-member-accessibility`: suggestion-parity-gap-suspected
- `no-empty-interface`: suggestion-parity-gap-suspected
- `no-empty-object-type`: suggestion-parity-gap-suspected
- `no-non-null-assertion`: suggestion-parity-gap-suspected
- `no-restricted-types`: suggestion-parity-gap-suspected
- `no-unnecessary-condition`: suggestion-parity-gap-suspected
- `no-unnecessary-type-constraint`: suggestion-parity-gap-suspected
- `no-unnecessary-type-conversion`: suggestion-parity-gap-suspected
- `no-unnecessary-type-parameters`: suggestion-parity-gap-suspected
- `no-unsafe-enum-comparison`: suggestion-parity-gap-suspected
- `no-unused-vars`: suggestion-parity-gap-suspected
- `prefer-enum-initializers`: suggestion-parity-gap-suspected
- `prefer-find`: suggestion-parity-gap-suspected
- `prefer-nullish-coalescing`: suggestion-parity-gap-suspected
- `prefer-optional-chain`: suggestion-parity-gap-suspected
- `require-await`: suggestion-parity-gap-suspected
- `strict-boolean-expressions`: suggestion-parity-gap-suspected
- `switch-exhaustiveness-check`: suggestion-parity-gap-suspected

## Notes / Interpretation
- `fix-parity-gap-suspected` and `suggestion-parity-gap-suspected` are flagged when upstream metadata + test assertions indicate fix/suggestion behavior that is absent or reduced locally. They should be manually confirmed rule-by-rule before implementation.
- For rules that extend base ESLint rules, metadata/message differences can be legitimate; this report focuses on actionable parity signals (tests, skips, TODOs, missing assets).
- All findings above are from direct source/test cross-reference, not from runtime fuzzing of every case.
