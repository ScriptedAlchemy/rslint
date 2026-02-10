# prefer-for-of

## Rule Details

Prefer `for-of` loops instead of index-based `for` loops when the index is only
used to read from the iterated array.

Examples of **incorrect** code for this rule:

```ts
for (let i = 0; i < arr.length; i++) {
  console.log(arr[i]);
}
```

Examples of **correct** code for this rule:

```ts
for (const item of arr) {
  console.log(item);
}
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-for-of
