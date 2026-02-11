# ban-tslint-comment

Disallow legacy `tslint:enable` / `tslint:disable` comments.

## Rule Details

This rule reports comments matching TSLint enable/disable directives:

- `// tslint:disable-next-line`
- `// tslint:disable-line`
- `/* tslint:disable */`
- `/* tslint:enable */`

## Examples

### ❌ Incorrect

```ts
/* tslint:disable */
const value = 1;
```

```ts
someCode(); // tslint:disable-line
```

### ✅ Correct

```ts
// regular comment
const value = 1;
```

