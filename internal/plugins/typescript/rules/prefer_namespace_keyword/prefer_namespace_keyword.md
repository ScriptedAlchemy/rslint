# prefer-namespace-keyword

## Rule Details

Prefer `namespace` over `module` when declaring internal modules.

Examples of **incorrect** code for this rule:

```typescript
module Foo {}
declare module Bar {}
```

Examples of **correct** code for this rule:

```typescript
namespace Foo {}
declare namespace Bar {}
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-namespace-keyword
