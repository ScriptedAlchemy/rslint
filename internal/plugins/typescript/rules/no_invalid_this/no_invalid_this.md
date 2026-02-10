# no-invalid-this

## Rule Details

Disallow `this` usage in contexts where it is likely invalid.

Examples of **incorrect** code for this rule:

```ts
function foo() {
  return this;
}
```

Examples of **correct** code for this rule:

```ts
class A {
  foo() {
    return this;
  }
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-invalid-this
