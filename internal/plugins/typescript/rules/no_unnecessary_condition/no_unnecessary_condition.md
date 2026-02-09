# no-unnecessary-condition

## Rule Details

Disallow conditionals where the checked value is statically always truthy,
always falsy, always nullish, or never nullish.

Examples of **incorrect** code for this rule:

```ts
declare const value: string;
if (value) {
  doSomething();
}
```

Examples of **correct** code for this rule:

```ts
declare const value: string | undefined;
if (value) {
  doSomething();
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-unnecessary-condition
