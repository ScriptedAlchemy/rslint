# no-empty-object-type

## Rule Details

Disallow accidentally using empty object types.

This rule reports:

- empty interfaces
- empty interfaces that only extend a single interface
- empty type literals (`{}`) outside of intersection helper patterns

Examples of **incorrect** code for this rule:

```ts
interface Foo {}
type Bar = {};
```

Examples of **correct** code for this rule:

```ts
interface Foo {
  value: string;
}

type Bar = object;
type Baz<T> = T & {};
```

## Original Documentation

- https://typescript-eslint.io/rules/no-empty-object-type
