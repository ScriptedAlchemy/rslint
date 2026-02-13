# Rslint contribution guide

Thank you for your interest in contributing to Rslint! Before you start your contribution, please take a moment to read the following guidelines.

## Setup the environment

Install [Node.js](https://nodejs.org/) and [Go](https://go.dev/) first.

## Build locally

Build the project:

```bash
# init typescript-go submodule
git submodule update --init --recursive
pnpm install
pnpm build
```

Test the setup:

```bash
# Run all tests
pnpm test

# Run Go tests only
pnpm run test:go

# Run linting
pnpm run lint

# Run type checking
pnpm run typecheck

# Check code formatting
pnpm run format:check
```

## Test the CLI

After building, you can test the rslint CLI:

```bash
# Test the binary
./packages/rslint/bin/rslint --help


# Lint the project itself
./packages/rslint/bin/rslint --config rslint.json
```

## Maintain TypeScript-ESLint parity artifacts

If you are working on TypeScript-ESLint rule parity, use the parity toolkit:

- Guide: `typescript-eslint-rule-parity-guide.md`

Commands:

```bash
# Refresh upstream reference + regenerate all parity artifacts
pnpm parity:ts-eslint

# Run all consistency checks (and verify-clean when artifacts are clean)
pnpm parity:ts-eslint:check:all

# Enforce clean parity-artifact tree before reproducibility verification
pnpm parity:ts-eslint:check:clean

# Strict gate: all checks + fail if critical parity backlog remains
pnpm parity:ts-eslint:check:strict

# Strict gate + clean-tree enforcement for reproducibility verification
pnpm parity:ts-eslint:check:strict:clean

# Unified gates (strict clean checks + thresholded health/doctor gates)
pnpm parity:ts-eslint:gate:red
pnpm parity:ts-eslint:gate:yellow

# Refresh canonical markdown + JSON parity diff artifacts
pnpm parity:ts-eslint:diff:refresh
```

## Debugging VSCode Extension

To Debug the VSCode Extension:

1. **Setup launch configuration**

```bash
cp .vscode/launch.template.json .vscode/launch.json
```

2. **Start debugging**

- Open the Command Palette (`Cmd+Shift+P`)
- Run `Debug: Start Debugging` or press `F5`
- Alternatively, go to the `Run and Debug` sidebar and select `Run Extension`
