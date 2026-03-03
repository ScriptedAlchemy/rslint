# no-unnecessary-type-constraint

## Rule Details

Disallow type parameter constraints that are always implied, such as
`extends any` and `extends unknown`.

Examples of **incorrect** code for this rule:

```ts
function data<T extends any>() {}
```

Examples of **correct** code for this rule:

```ts
function data<T>() {}
```

## Original Documentation

https://typescript-eslint.io/rules/no-unnecessary-type-constraint
