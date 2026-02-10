# no-loop-func

## Rule Details

Disallow function declarations or expressions inside loops when they capture
loop variables in unsafe ways.

Examples of **incorrect** code for this rule:

```ts
for (var i = 0; i < 10; i++) {
  const fn = () => i;
}
```

Examples of **correct** code for this rule:

```ts
for (let i = 0; i < 10; i++) {
  const fn = () => i;
}
```

## Original Documentation

https://typescript-eslint.io/rules/no-loop-func
