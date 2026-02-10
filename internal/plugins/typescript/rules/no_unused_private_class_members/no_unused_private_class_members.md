# no-unused-private-class-members

## Rule Details

Disallow declaring ECMAScript private class members that are never used.

Examples of **incorrect** code for this rule:

```ts
class A {
  #x = 1;
}
```

Examples of **correct** code for this rule:

```ts
class A {
  #x = 1;
  getX() {
    return this.#x;
  }
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-unused-private-class-members
