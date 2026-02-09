# prefer-find

## Rule Details

Prefer `.find(...)` over `.filter(...)[0]` and `.filter(...).at(0)` when only
the first matching element is needed.

Examples of **incorrect** code for this rule:

```ts
const value = arr.filter(x => predicate(x))[0];
const value2 = arr.filter(x => predicate(x)).at(0);
```

Examples of **correct** code:

```ts
const value = arr.find(x => predicate(x));
```

## Original Documentation

- https://typescript-eslint.io/rules/prefer-find
