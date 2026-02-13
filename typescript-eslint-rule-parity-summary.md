# TypeScript-ESLint Rule Parity Summary Dashboard
Snapshot retained as part of the cleaned markdown-only parity deliverables.

## Headline metrics
- Total tracked rules: **135**
- Rules needing correction (`priority_score > 0`): **60**
- Rules currently aligned (`priority_score = 0`): **75**

## Phase distribution
| Phase | Rules |
|---|---:|
| `A_critical` | 5 |
| `B_high` | 6 |
| `C_medium` | 18 |
| `D_low` | 31 |
| `aligned` | 75 |

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

## Top 15 highest priority rules
| Rank | Rule | Score | Flags |
|---:|---|---:|---|
| 1 | `no-useless-default-assignment` | 40 | `severe_js_size_gap|severe_invalid_gap|fix_gap_suspected` |
| 2 | `no-duplicate-enum-values` | 34 | `severe_js_size_gap|severe_invalid_gap` |
| 3 | `no-unused-private-class-members` | 34 | `severe_js_size_gap|severe_invalid_gap` |
| 4 | `strict-void-return` | 34 | `severe_js_size_gap|severe_invalid_gap` |
| 5 | `no-unused-vars` | 32 | `missing_js_file|fix_gap_suspected|suggestion_gap_suspected` |
| 6 | `prefer-optional-chain` | 30 | `moderate_js_size_gap|moderate_invalid_gap|fix_gap_suspected|suggestion_gap_suspected` |
| 7 | `await-thenable` | 26 | `moderate_js_size_gap|severe_invalid_gap` |
| 8 | `no-loss-of-precision` | 20 | `missing_go_test` |
| 9 | `no-confusing-void-expression` | 19 | `extra_js_skips|go_skips|todo_markers` |
| 10 | `no-duplicate-type-constituents` | 19 | `extra_js_skips|go_skips|todo_markers` |
| 11 | `no-unsafe-member-access` | 18 | `moderate_js_size_gap|moderate_invalid_gap` |
| 12 | `no-base-to-string` | 13 | `go_skips|todo_markers` |
| 13 | `no-misused-promises` | 13 | `go_skips|todo_markers` |
| 14 | `no-misused-spread` | 13 | `go_skips|todo_markers` |
| 15 | `no-unnecessary-type-arguments` | 13 | `go_skips|todo_markers` |

## Suggested execution order
1. Complete all `A_critical` rules.
2. Burn down `B_high` rules with largest test-coverage deficits.
3. Resolve `C_medium` skip/TODO debt and fix/suggestion parity gaps.
4. Close `D_low` tail items and reassess score distribution.

