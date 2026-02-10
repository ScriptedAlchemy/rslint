# no-redeclare

## Rule Details

Disallow variable/type/member redeclarations in the same scope.

Examples of **incorrect** code for this rule:

```ts
var a = 1;
var a = 2;
```

Examples of **correct** code for this rule:

```ts
var a = 1;
```

## Original Documentation

https://typescript-eslint.io/rules/no-redeclare
