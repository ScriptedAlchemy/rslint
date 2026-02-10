# no-restricted-types

## Rule Details

Disallow specific type annotations configured via the `types` option.

Examples of **incorrect** code for this rule:

```ts
let value: number;
```

with config:

```json
{ "types": { "number": "Use Ok instead." } }
```

Examples of **correct** code for this rule:

```ts
let value: Ok;
```

## Original Documentation

https://typescript-eslint.io/rules/no-restricted-types
