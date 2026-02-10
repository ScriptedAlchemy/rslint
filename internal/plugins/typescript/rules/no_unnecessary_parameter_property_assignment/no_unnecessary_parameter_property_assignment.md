# no-unnecessary-parameter-property-assignment

## Rule Details

Disallow redundant assignments to class fields that are already initialized by
parameter properties.

Examples of **incorrect** code for this rule:

```ts
class Foo {
  constructor(public foo: string) {
    this.foo = foo;
  }
}
```

Examples of **correct** code for this rule:

```ts
class Foo {
  constructor(public foo: string) {}
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-unnecessary-parameter-property-assignment
