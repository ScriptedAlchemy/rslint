# no-wrapper-object-types

## Rule Details

Disallow JavaScript wrapper object types in type positions and prefer primitive
types instead (for example `Number` -> `number`).

Examples of **incorrect** code for this rule:

```ts
let value: Number;
```

Examples of **correct** code for this rule:

```ts
let value: number;
```

## Original Documentation

https://typescript-eslint.io/rules/no-wrapper-object-types
