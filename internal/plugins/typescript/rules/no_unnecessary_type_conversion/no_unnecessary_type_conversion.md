# no-unnecessary-type-conversion

## Rule Details

Disallow type-conversion idioms when the input is already of the target
primitive type.

Examples of **incorrect** code for this rule:

```ts
String('asdf');
Number(123);
!!true;
```

Examples of **correct** code for this rule:

```ts
String(1);
Number('2');
!!0;
```

## Original Documentation

https://typescript-eslint.io/rules/no-unnecessary-type-conversion
