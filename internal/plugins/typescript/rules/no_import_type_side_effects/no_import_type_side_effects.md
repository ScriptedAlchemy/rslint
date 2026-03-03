# no-import-type-side-effects

## Rule Details

Disallow imports where every named specifier is marked `type` inline, and
prefer a top-level `import type` qualifier instead.

Examples of **incorrect** code for this rule:

```ts
import { type A, type B } from 'mod';
```

Examples of **correct** code for this rule:

```ts
import type { A, B } from 'mod';
```

## Original Documentation

https://typescript-eslint.io/rules/no-import-type-side-effects
