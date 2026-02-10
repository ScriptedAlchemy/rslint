# no-useless-constructor

## Rule Details

Disallow constructors that do not add behavior beyond what JavaScript already
provides by default.

Examples of **incorrect** code for this rule:

```ts
class A {
  constructor() {}
}
```

```ts
class A extends B {
  constructor(foo) {
    super(foo);
  }
}
```

Examples of **correct** code for this rule:

```ts
class A {
  private constructor() {}
}
```

```ts
class A extends B {
  constructor(foo) {
    super(foo, 1);
  }
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-useless-constructor
