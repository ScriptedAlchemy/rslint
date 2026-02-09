# no-confusing-non-null-assertion

## Rule Details

Disallow non-null assertions in confusing locations where they can be mistaken for negations.

Examples of **incorrect** code for this rule:

```typescript
a! == b;
a! in b;
```

Examples of **correct** code for this rule:

```typescript
a == b;
(a!) in b;
```

## Original Documentation

https://typescript-eslint.io/rules/no-confusing-non-null-assertion
