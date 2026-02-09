# parameter-properties

## Rule Details

Require or disallow parameter properties in class constructors.

Examples of **incorrect** code for the default (`class-property`) mode:

```ts
class User {
  constructor(public name: string) {}
}
```

Examples of **correct** code:

```ts
class User {
  name: string;
  constructor(name: string) {
    this.name = name;
  }
}
```

## Original Documentation

- https://typescript-eslint.io/rules/parameter-properties
