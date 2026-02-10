# prefer-function-type

## Rule Details

Prefer function type aliases over interfaces or type literals that only declare a
single call signature.

Examples of **incorrect** code for this rule:

```ts
interface Foo {
  (): string;
}
```

```ts
type Foo = {
  (): string;
};
```

Examples of **correct** code for this rule:

```ts
type Foo = () => string;
```

## Original Documentation

https://typescript-eslint.io/rules/prefer-function-type
