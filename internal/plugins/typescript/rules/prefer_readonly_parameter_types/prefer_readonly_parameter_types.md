# prefer-readonly-parameter-types

Require function parameters to use readonly-compatible types.

This rule helps prevent accidental mutation of values passed into functions.
It checks parameters on runtime function-like nodes and type-signature nodes.

## Options

```json
{
  "@typescript-eslint/prefer-readonly-parameter-types": [
    "error",
    {
      "checkParameterProperties": true,
      "ignoreInferredTypes": false,
      "treatMethodsAsReadonly": false,
      "allow": []
    }
  ]
}
```

- `checkParameterProperties`: Whether constructor parameter properties are checked.
- `ignoreInferredTypes`: Skip parameters without an explicit type annotation.
- `treatMethodsAsReadonly`: Treat method members as readonly when checking object types.
- `allow`: Type or value specifiers that are exempt from readonly checking.
