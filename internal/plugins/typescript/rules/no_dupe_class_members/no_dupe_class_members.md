# no-dupe-class-members

## Rule Details

Disallow duplicate class members with the same name.

Examples of **incorrect** code for this rule:

```typescript
class A {
  foo() {}
  foo() {}
}
```

Examples of **correct** code for this rule:

```typescript
class A {
  foo() {}
  bar() {}
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-dupe-class-members
