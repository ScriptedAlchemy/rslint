# no-unsafe-declaration-merging

## Rule Details

Disallow class/interface declaration merging with the same name in the same
scope.

Examples of **incorrect** code for this rule:

```ts
interface Foo {}
class Foo {}
```

Examples of **correct** code for this rule:

```ts
interface Foo {}
class Bar implements Foo {}
```

## Original Documentation

https://typescript-eslint.io/rules/no-unsafe-declaration-merging
