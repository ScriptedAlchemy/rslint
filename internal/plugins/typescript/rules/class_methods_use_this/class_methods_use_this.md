# class-methods-use-this

## Rule Details

Enforce that non-static class methods and accessors use `this` (or `super`) in their implementation.

This helps identify instance members that do not rely on instance state and may be better represented as static methods or standalone functions.

## Options

- `exceptMethods`: list of method names to ignore.
- `enforceForClassFields` (default: `true`): whether to enforce for class field function initializers.
- `ignoreOverrideMethods` (default: `false`): ignore members marked with `override`.
- `ignoreClassesThatImplementAnInterface` (default: `false`):
  - `true`: ignore all members in classes with `implements`.
  - `"public-fields"`: ignore only public members in classes with `implements`.

## Original Documentation

- https://typescript-eslint.io/rules/class-methods-use-this
