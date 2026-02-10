# prefer-find

## Rule Details

Prefer `Array#find` over `Array#filter(...)[0]` and `Array#filter(...).at(0)`.

Examples of **incorrect** code for this rule:

```ts
arr.filter(item => item.active)[0];
arr.filter(item => item.active).at(0);
```

Examples of **correct** code for this rule:

```ts
arr.find(item => item.active);
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-find
