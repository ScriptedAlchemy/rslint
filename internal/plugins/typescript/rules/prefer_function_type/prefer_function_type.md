# prefer-function-type

## Rule Details

Enforce using function types instead of interfaces/type literals with only call
signatures.

Examples of **incorrect** code for this rule:

```ts
interface Fn {
  (value: string): number;
}
```

Examples of **correct** code:

```ts
type Fn = (value: string) => number;
```

## Original Documentation

- https://typescript-eslint.io/rules/prefer-function-type
