# member-ordering

## Rule Details

Enforce a consistent ordering of members in:

- class declarations / expressions
- interfaces
- type literals

Supported option shape follows the upstream rule structure with per-target overrides:

- `default`
- `classes`
- `classExpressions`
- `interfaces`
- `typeLiterals`

Each config supports:

- `memberTypes`
- `order`
- `optionalityOrder`

Examples of **incorrect** code:

```ts
interface Foo {
  b: string;
  a: string;
}
```

Examples of **correct** code:

```ts
interface Foo {
  a: string;
  b: string;
}
```

## Original Documentation

- https://typescript-eslint.io/rules/member-ordering
