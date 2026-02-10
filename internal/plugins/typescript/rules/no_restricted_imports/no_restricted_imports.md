# no-restricted-imports

## Rule Details

Disallow importing from configured modules or path patterns.

Examples of **incorrect** code for this rule:

```ts
import foo from 'import1';
```

with config:

```json
["import1"]
```

Examples of **correct** code for this rule:

```ts
import foo from 'allowed-module';
```

## Original Documentation

https://typescript-eslint.io/rules/no-restricted-imports
