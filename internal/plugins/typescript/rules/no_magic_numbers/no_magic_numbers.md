# no-magic-numbers

## Rule Details

Disallow numeric literals in TypeScript-specific contexts unless explicitly
ignored by options.

Examples of **incorrect** code for this rule:

```ts
type Foo = 1;
```

Examples of **correct** code for this rule:

```ts
type Foo = 1;
```

with config:

```json
{ "ignoreNumericLiteralTypes": true }
```

## Original Documentation

https://typescript-eslint.io/rules/no-magic-numbers
