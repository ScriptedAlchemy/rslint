# prefer-enum-initializers

## Rule Details

Require explicit initializers on enum members.

Examples of **incorrect** code for this rule:

```ts
enum Direction {
  Up,
}
```

Examples of **correct** code for this rule:

```ts
enum Direction {
  Up = 1,
}
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-enum-initializers
