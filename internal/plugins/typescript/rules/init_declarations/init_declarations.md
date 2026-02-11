# init-declarations

Require or disallow initialization in variable declarations.

## Options

- `"always"` (default): require initializers for variable declarations.
- `"never"`: disallow initializers (except `const` declarations).
- second option object: `{ ignoreForLoopInit: true }` to ignore `for` loop initializers in `"never"` mode.

## TypeScript-specific behavior

- `declare` variable declarations are ignored in `"always"` mode.
- variable declarations inside `declare namespace` blocks are ignored in `"always"` mode.

