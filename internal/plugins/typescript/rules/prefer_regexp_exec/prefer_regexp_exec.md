# prefer-regexp-exec

## Rule Details

Prefer `RegExp#exec()` over `String#match()` when not using global regular
expression semantics.

Examples of **incorrect** code for this rule:

```ts
'something'.match(/thing/);
```

Examples of **correct** code for this rule:

```ts
/thing/.exec('something');
'something'.match(/thing/g);
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-regexp-exec
