# unified-signatures

Disallow overload lists that can be merged into one signature.

This rule reports overloads that only differ by:

- a single parameter type (`A` vs `B`) that can be represented as `A | B`
- an extra optional parameter
- an extra rest parameter

## Options

```json
{
  "@typescript-eslint/unified-signatures": [
    "error",
    {
      "ignoreDifferentlyNamedParameters": false,
      "ignoreOverloadsWithDifferentJSDoc": false
    }
  ]
}
```

- `ignoreDifferentlyNamedParameters`:
  - When `true`, overload pairs with different static parameter names at the same position are ignored.
- `ignoreOverloadsWithDifferentJSDoc`:
  - When `true`, overload pairs with different nearest leading block comments are ignored.
