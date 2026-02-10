# no-unused-expressions

## Rule Details

Disallow expression statements that have no effect.

Examples of **incorrect** code for this rule:

```ts
foo as any;
a?.b;
```

Examples of **correct** code for this rule:

```ts
foo();
new Foo();
import('./file');
```

## Original Documentation

https://typescript-eslint.io/rules/no-unused-expressions
