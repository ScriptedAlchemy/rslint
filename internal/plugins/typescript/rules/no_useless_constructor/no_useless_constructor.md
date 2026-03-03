# no-useless-constructor

## Rule Details

Disallow unnecessary constructors.

This rule reports constructors that do not add behavior beyond what JavaScript
already provides:

- empty constructors on classes without `extends`
- forwarding constructors in derived classes that only call `super(...)` with
  the same parameters

Examples of **incorrect** code for this rule:

```ts
class A {
  constructor() {}
}

class B extends A {
  constructor(x, y) {
    super(x, y);
  }
}
```

Examples of **correct** code for this rule:

```ts
class A {
  constructor(private readonly name: string) {}
}

class B extends A {
  constructor(x, y) {
    super(x);
  }
}
```

## Original Documentation

- https://typescript-eslint.io/rules/no-useless-constructor
