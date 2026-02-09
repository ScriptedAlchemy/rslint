# method-signature-style

## Rule Details

Enforce whether interface/type members should be written as:

- method shorthand signatures (`foo(a: A): B`) or
- function property signatures (`foo: (a: A) => B`)

Default style is `"property"`.

Examples of **incorrect** code for the default (`"property"`) style:

```ts
interface A {
  foo(x: string): number;
}
```

Examples of **correct** code:

```ts
interface A {
  foo: (x: string) => number;
}
```

## Original Documentation

- https://typescript-eslint.io/rules/method-signature-style
