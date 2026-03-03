# prefer-enum-initializers

## Rule Details

Require each enum member value to be explicitly initialized.

Examples of **incorrect** code for this rule:

```ts
enum Status {
  Pending,
  Done = 1,
}
```

Examples of **correct** code:

```ts
enum Status {
  Pending = 0,
  Done = 1,
}
```

## Original Documentation

- https://typescript-eslint.io/rules/prefer-enum-initializers
