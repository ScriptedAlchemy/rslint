# explicit-member-accessibility

Require explicit accessibility modifiers on class members.

## What this rule checks

- class methods, constructors, accessors, and properties
- constructor parameter properties

## Options

- `accessibility`: `"explicit"` (default), `"no-public"`, `"off"`
- `overrides`: per-member overrides for `accessors`, `constructors`, `methods`, `parameterProperties`, and `properties`
- `ignoredMethodNames`: method names to ignore
