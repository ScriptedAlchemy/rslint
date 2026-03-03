// Forked and modified from https://github.com/typescript-eslint/typescript-eslint/blob/16c344ec7d274ea542157e0f19682dd1930ab838/packages/rule-tester/src/RuleTester.ts#L4

import path from 'node:path';
import fs from 'node:fs';
import { test, describe, expect } from '@rstest/core';
import { applyFixes, lint, LintResponse, type Diagnostic } from '@rslint/core';
import assert from 'node:assert';
import type { LanguageOptions as RslintLanguageOptions } from '@rslint/core';

interface TsDiagnostic {
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  messageId?: string;
  suggestions?: any[] | null;
  data?: any;
  type?: any;
  output?: string;
}
function toCamelCase(name: string): string {
  return name.replace(/-([a-z])/g, g => g[1].toUpperCase());
}
// check whether rslint diagnostics and typescript-eslint diagnostics are semantic equal
function checkDiagnosticEqual(
  rslintDiagnostic: Diagnostic[],
  tsDiagnostic: TsDiagnostic[],
) {
  assert(
    rslintDiagnostic.length === tsDiagnostic.length,
    `Length mismatch: ${rslintDiagnostic.length} !== ${tsDiagnostic.length}`,
  );
  for (let i = 0; i < rslintDiagnostic.length; i++) {
    const rslintDiag = rslintDiagnostic[i];
    const tsDiag = tsDiagnostic[i];
    // check rule match
    assert(
      toCamelCase(rslintDiag.messageId) === tsDiag.messageId,
      `Message mismatch: ${rslintDiag.messageId} !== ${tsDiag.messageId}`,
    );

    // check range match
    // tsDiag sometimes doesn't have line and column, so we need to check that
    if (tsDiag.line) {
      assert(
        rslintDiag.range.start.line === tsDiag.line,
        `Start line mismatch: ${rslintDiag.range.start.line} !== ${tsDiag.line}`,
      );
    }
    if (tsDiag.endLine) {
      assert(
        rslintDiag.range.end.line === tsDiag.endLine,
        `End line mismatch: ${rslintDiag.range.end.line} !== ${tsDiag.endLine}`,
      );
    }
    if (tsDiag.column) {
      assert(
        rslintDiag.range.start.column === tsDiag.column,
        `Start column mismatch: ${rslintDiag.range.start.column} !== ${tsDiag.column}`,
      );
    }
    if (tsDiag.endColumn) {
      assert(
        rslintDiag.range.end.column === tsDiag.endColumn,
        `End column mismatch: ${rslintDiag.range.end.column} !== ${tsDiag.endColumn}`,
      );
    }
  }
}

interface RuleTesterOptions {
  languageOptions?: {
    globals?: any;
    parser?: any;
    parserOptions?: {
      project?: string;
      tsconfigRootDir?: string;
      projectService?: boolean;
      ecmaFeatures?: any;
      ecmaVersion?: number;
      sourceType?: 'module' | 'script';
      jsxPragma?: string | null;
      jsxFragmentName?: string;
      emitDecoratorMetadata?: boolean;
      isolatedDeclarations?: boolean;
      experimentalDecorators?: boolean;
      lib?: string[];
    };
  };
}

function resolveVirtualEntry(
  virtualBaseDir: string,
  useProjectFixtureFile: boolean,
  isJSX: boolean | undefined,
  filename?: string,
): string {
  if (filename) {
    if (filename.endsWith('.d.ts')) {
      return path.resolve(virtualBaseDir, 'virtual.d.ts');
    }
    if (filename.endsWith('.mts')) {
      return path.resolve(virtualBaseDir, 'virtual.mts');
    }
    if (filename.endsWith('.cts')) {
      return path.resolve(virtualBaseDir, 'virtual.cts');
    }
    return path.isAbsolute(filename)
      ? filename
      : path.resolve(virtualBaseDir, filename);
  }
  return path.resolve(
    virtualBaseDir,
    useProjectFixtureFile
      ? isJSX
        ? 'react.tsx'
        : 'file.ts'
      : isJSX
        ? 'virtual.tsx'
        : 'virtual.ts',
  );
}

export type InvalidTestCase<T = any, U = any> = {
  code: string;
  filename?: string;
  errors: TsDiagnostic[];
  options?: any;
  only?: boolean;
  skip?: boolean;
  output?: string | null | string[];
  languageOptions?: RuleTesterOptions['languageOptions'];
};
export type ValidTestCase<T = any> =
  | string
  | {
      filename?: string;
      code: string;
      options?: any;
      only?: boolean;
      skip?: boolean;
      languageOptions?: RuleTesterOptions['languageOptions'];
      name?: string;
    };

function mergeLanguageOptions(
  base?: RuleTesterOptions['languageOptions'],
  override?: RuleTesterOptions['languageOptions'],
): RuleTesterOptions['languageOptions'] | undefined {
  if (!base && !override) {
    return undefined;
  }

  const baseParser = base?.parserOptions;
  const overrideParser = override?.parserOptions;

  return {
    ...(base ?? {}),
    ...(override ?? {}),
    parserOptions:
      baseParser || overrideParser
        ? {
            ...(baseParser ?? {}),
            ...(overrideParser ?? {}),
            ecmaFeatures:
              baseParser?.ecmaFeatures || overrideParser?.ecmaFeatures
                ? {
                    ...(baseParser?.ecmaFeatures ?? {}),
                    ...(overrideParser?.ecmaFeatures ?? {}),
                  }
                : undefined,
          }
        : undefined,
  };
}

function toRslintLanguageOptions(
  languageOptions?: RuleTesterOptions['languageOptions'],
): RslintLanguageOptions | undefined {
  if (!languageOptions) {
    return undefined;
  }

  const parserOptions = languageOptions.parserOptions
    ? {
        ...languageOptions.parserOptions,
        // rslint parserOptions expects string here; null means "unset" in upstream tests.
        jsxPragma:
          languageOptions.parserOptions.jsxPragma === null
            ? undefined
            : languageOptions.parserOptions.jsxPragma,
      }
    : undefined;

  return {
    globals: languageOptions.globals,
    parserOptions,
  };
}

function getTypescriptEslintFixturesRootDir(): string {
  return path.resolve(
    '../../packages/rslint-test-tools/tests/typescript-eslint/fixtures',
  );
}

let cachedKnownRuleNames: Set<string> | null = null;

function getKnownRuleNames(): Set<string> {
  if (cachedKnownRuleNames) {
    return cachedKnownRuleNames;
  }

  const candidates = [
    path.resolve(process.cwd(), '../../internal/plugins/typescript/rules'),
    path.resolve(process.cwd(), '../../../internal/plugins/typescript/rules'),
    path.resolve(process.cwd(), 'internal/plugins/typescript/rules'),
  ];

  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) {
      continue;
    }

    const names = new Set(
      fs
        .readdirSync(candidate, { withFileTypes: true })
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name.replaceAll('_', '-')),
    );
    cachedKnownRuleNames = names;
    return names;
  }

  cachedKnownRuleNames = new Set();
  return cachedKnownRuleNames;
}

function resolveCanonicalRuleName(runLabel: string): string {
  const known = getKnownRuleNames();
  if (known.size === 0 || known.has(runLabel)) {
    return runLabel;
  }

  let candidate = runLabel;
  while (candidate.includes('-')) {
    candidate = candidate.slice(0, candidate.lastIndexOf('-'));
    if (known.has(candidate)) {
      return candidate;
    }
  }

  return runLabel;
}

const rootDir: string = getTypescriptEslintFixturesRootDir();
const defaultRuleTesterOptions: RuleTesterOptions = {
  languageOptions: {
    parserOptions: {
      project: './tsconfig.json',
      tsconfigRootDir: rootDir,
    },
  },
};
export class RuleTester {
  options: RuleTesterOptions;
  constructor(options: RuleTesterOptions = defaultRuleTesterOptions) {
    this.options = options;
  }
  public defineRule(
    rule: string,
    options: {
      create: (context: any) => void;
      meta: any;
      defaultOptions?: any;
    },
  ) {}
  public run(
    ruleName: string,
    cases: {
      valid: ValidTestCase[];
      invalid: InvalidTestCase[];
    },
  ) {
    const suiteName = ruleName;
    const normalizedRuleName = ruleName.trim().split(/\s+/)[0] || ruleName;
    const canonicalRuleName = resolveCanonicalRuleName(normalizedRuleName);
    describe(suiteName, () => {
      ruleName = '@typescript-eslint/' + canonicalRuleName;
      let cwd =
        this.options.languageOptions?.parserOptions?.tsconfigRootDir ||
        process.cwd();
      const config = path.resolve(cwd, './rslint.json');

      // test whether case has only
      let hasOnly =
        cases.valid.some(x => {
          if (typeof x === 'object' && x.only) {
            return true;
          } else {
            return false;
          }
        }) || cases.invalid.some(x => x.only);
      test('valid', async () => {
        for (const validCase of cases.valid) {
          if (typeof validCase === 'object' && validCase.skip) {
            continue;
          }
          if (hasOnly) {
            if (typeof validCase === 'string') {
              continue;
            }
            if (!validCase.only) {
              continue;
            }
          }
          const code =
            typeof validCase === 'string' ? validCase : validCase.code;
          const caseLanguageOptions =
            typeof validCase === 'string'
              ? undefined
              : validCase.languageOptions;
          const languageOptions = mergeLanguageOptions(
            this.options.languageOptions,
            caseLanguageOptions,
          );
          const isJSX = languageOptions?.parserOptions?.ecmaFeatures?.jsx;
          const caseTsconfigRootDir =
            languageOptions?.parserOptions?.tsconfigRootDir;
          const virtualBaseDir = caseTsconfigRootDir || cwd;
          const useProjectFixtureFile =
            !!caseTsconfigRootDir && caseTsconfigRootDir !== cwd;

          const options =
            typeof validCase === 'string' ? [] : validCase.options || [];
          let virtual_entry = resolveVirtualEntry(
            virtualBaseDir,
            useProjectFixtureFile,
            isJSX,
            typeof validCase === 'string' ? undefined : validCase.filename,
          );
          // workaround for this hardcoded path https://github.com/typescript-eslint/typescript-eslint/blob/main/packages/eslint-plugin/tests/rules/no-floating-promises.test.ts#L712
          if (Array.isArray(options)) {
            for (const opt of options) {
              if (Array.isArray(opt.allowForKnownSafeCalls)) {
                for (const item of opt.allowForKnownSafeCalls) {
                  if (item.path) {
                    item.path = virtual_entry;
                  }
                }
              }
            }
          }
          const diags = await lint({
            config,
            workingDirectory: cwd,
            fileContents: {
              [virtual_entry]: code,
            },
            ruleOptions: {
              [ruleName]: options,
            },
            languageOptions: toRslintLanguageOptions(languageOptions),
          });

          assert(
            diags.diagnostics?.length === 0,
            `Expected no diagnostics for valid case, but got: ${JSON.stringify(diags)} \nwith code:\n${code}`,
          );
        }
      });
      test('invalid', async t => {
        for (const item of cases.invalid) {
          const {
            code,
            errors,
            only = false,
            skip = false,
            output,
            options = [],
          } = item;
          if (skip) {
            continue;
          }
          if (hasOnly && !only) {
            continue;
          }
          const languageOptions = mergeLanguageOptions(
            this.options.languageOptions,
            item.languageOptions,
          );
          const isJSX = languageOptions?.parserOptions?.ecmaFeatures?.jsx;
          const caseTsconfigRootDir =
            languageOptions?.parserOptions?.tsconfigRootDir;
          const virtualBaseDir = caseTsconfigRootDir || cwd;
          const useProjectFixtureFile =
            !!caseTsconfigRootDir && caseTsconfigRootDir !== cwd;
          const test_virtual_entry = resolveVirtualEntry(
            virtualBaseDir,
            useProjectFixtureFile,
            isJSX,
            item.filename,
          );
          const lintCase = async (caseCode: string) =>
            lint({
              config,
              workingDirectory: cwd,
              fileContents: {
                [test_virtual_entry]: caseCode,
              },
              ruleOptions: {
                [ruleName]: options,
              },
              languageOptions: toRslintLanguageOptions(languageOptions),
            });
          const diags = await lintCase(code);

          assert(
            diags.diagnostics?.length > 0,
            `Expected diagnostics for invalid case: ${code}`,
          );
          // eslint-disable-next-line
          checkDiagnosticEqual(diags.diagnostics, errors);
          const outputs: string[] = [];
          let currentCode = code;
          let currentDiagnostics = diags.diagnostics ?? [];
          for (let pass = 0; pass < 10; pass++) {
            const fixedCode = await applyFixes({
              fileContent: currentCode,
              diagnostics: currentDiagnostics,
            });
            const fixedOutputs = fixedCode.fixedContent ?? [];
            if (fixedOutputs.length === 0) {
              break;
            }
            const nextCode = fixedOutputs[fixedOutputs.length - 1];
            if (nextCode === currentCode) {
              break;
            }
            currentCode = nextCode;
            outputs.push(nextCode);
            const nextDiagnostics = await lintCase(currentCode);
            currentDiagnostics = nextDiagnostics.diagnostics ?? [];
            if (currentDiagnostics.length === 0) {
              break;
            }
          }

          const hasOutput = Object.prototype.hasOwnProperty.call(item, 'output');
          if (hasOutput) {
            if (output == null) {
              if (outputs.length) {
                expect(outputs[0]).toBe(code);
              }
            } else if (Array.isArray(output)) {
              expect(outputs.length).toBeGreaterThan(0);
              expect(outputs).toEqual(output);
            } else {
              expect(outputs.length).toBeGreaterThan(0);
              expect(outputs[0]).toBe(output);
              expect(outputs).toEqual([output]);
            }

            expect(
              filterSnapshot({
                ...diags,
                code,
                output,
              }),
            ).toMatchSnapshot();
          } else {
            assert(
              outputs.length === 0 || outputs[0] === code,
              "The rule fixed the code. Please add 'output' property.",
            );
            expect(filterSnapshot({ ...diags, code })).toMatchSnapshot();
          }
        }
      });
    });
  }
}
// remove unnecessary props from diagnostics, return optional filtered LintResponse
function filterSnapshot(
  diags: LintResponse & { output?: string | string[] | null; code?: string },
): LintResponse {
  for (const diag of diags.diagnostics ?? []) {
    delete diag.filePath;
    delete diag.fixes;
  }
  return diags;
}
/**
 * Simple no-op tag to mark code samples as "should not format with prettier"
 *   for the plugin-test-formatting lint rule
 */
export function noFormat(raw: TemplateStringsArray, ...keys: string[]): string {
  return String.raw({ raw }, ...keys);
}

export type RunTests<T, U> = any;

export type TestCaseError<T> = any;
