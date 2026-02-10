# no-unnecessary-qualifier

## Rule Details

Disallow namespace/type qualifiers when the referenced symbol is already
available in the current scope.

Examples of **incorrect** code for this rule:

```ts
namespace A {
  export const x = 1;
  const y = A.x;
}
```

Examples of **correct** code for this rule:

```ts
namespace A {
  export const x = 1;
  const y = x;
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-unnecessary-qualifier
