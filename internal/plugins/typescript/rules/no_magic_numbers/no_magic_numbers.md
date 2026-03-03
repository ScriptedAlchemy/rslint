# no-magic-numbers

## Rule Details

Disallow magic numbers, with TypeScript-aware ignore options.

Examples of **incorrect** code for this rule:

```ts
const timeout = 3000;
```

Examples of **correct** code:

```ts
const DEFAULT_TIMEOUT = 3000;
```

## Original Documentation

- https://typescript-eslint.io/rules/no-magic-numbers
