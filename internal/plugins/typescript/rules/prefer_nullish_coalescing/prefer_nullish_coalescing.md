# prefer-nullish-coalescing

## Rule Details

Prefer nullish coalescing (`??` / `??=`) over logical OR (`||` / `||=`) or
equivalent ternaries when the intent is to handle only `null` / `undefined`.

Examples of **incorrect** code for this rule:

```ts
const result = value || fallback;
```

Examples of **correct** code for this rule:

```ts
const result = value ?? fallback;
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-nullish-coalescing
