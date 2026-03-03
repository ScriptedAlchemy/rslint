# no-unused-expressions

## Rule Details

Disallow unused expressions.

This TypeScript extension keeps the base `no-unused-expressions` behavior and
also handles TypeScript expression wrappers such as `as`, non-null assertions,
and type assertions.

Examples of **incorrect** code for this rule:

```ts
foo as any;
foo!;
a?.b;
```

Examples of **correct** code for this rule:

```ts
foo();
new Foo<string>();
import('./foo');
```

## Original Documentation

- https://typescript-eslint.io/rules/no-unused-expressions
