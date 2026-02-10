# method-signature-style

## Rule Details

Enforce a consistent style for callable members in object/interface types:
either method syntax or function-property syntax.

Examples of **incorrect** code for the default (`property`) style:

```ts
interface Foo {
  bar(): void;
}
```

Examples of **correct** code for the default (`property`) style:

```ts
interface Foo {
  bar: () => void;
}
```

## Original Documentation

https://typescript-eslint.io/rules/method-signature-style
