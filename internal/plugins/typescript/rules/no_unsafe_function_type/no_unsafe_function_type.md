# no-unsafe-function-type

## Rule Details

Disallow usage of the broad `Function` type and prefer explicit function
signatures.

Examples of **incorrect** code for this rule:

```ts
let value: Function;
```

Examples of **correct** code for this rule:

```ts
let value: () => void;
```

## Original Documentation

https://typescript-eslint.io/rules/no-unsafe-function-type
