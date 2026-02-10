# no-empty-object-type

## Rule Details

Disallow empty interfaces and empty object type literals (`{}`), which are often
broader than intended.

Examples of **incorrect** code for this rule:

```ts
interface Foo {}
type Foo = {};
```

Examples of **correct** code for this rule:

```ts
interface Foo {
  value: string;
}
type Foo = {
  value: string;
};
```

## Original Documentation

https://typescript-eslint.io/rules/no-empty-object-type
