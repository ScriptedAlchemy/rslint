# prefer-for-of

## Rule Details

Enforce using `for...of` instead of simple index-based `for` loops when
iterating arrays.

Examples of **incorrect** code for this rule:

```ts
for (let i = 0; i < arr.length; i++) {
  console.log(arr[i]);
}
```

Examples of **correct** code:

```ts
for (const item of arr) {
  console.log(item);
}
```

## Original Documentation

- https://typescript-eslint.io/rules/prefer-for-of
