# no-restricted-imports

## Rule Details

Disallow specified modules from being imported.

Examples of **incorrect** code for this rule:

```ts
import x from "legacy-lib";
```

Examples of **correct** code:

```ts
import x from "modern-lib";
```

## Original Documentation

- https://typescript-eslint.io/rules/no-restricted-imports
