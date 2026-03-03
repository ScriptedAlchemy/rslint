# explicit-module-boundary-types

## Rule Details

Require explicit argument and return types on exported module boundaries.

Examples of **incorrect** code for this rule:

```ts
export function foo(a) {
  return a;
}
```

Examples of **correct** code:

```ts
export function foo(a: string): string {
  return a;
}
```

## Original Documentation

- https://typescript-eslint.io/rules/explicit-module-boundary-types
