import { RuleTester } from '@typescript-eslint/rule-tester';

import { getFixturesRootDir } from '../RuleTester';

const rootDir = getFixturesRootDir();
const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: {
      project: './tsconfig.json',
      tsconfigRootDir: rootDir,
    },
  },
});

ruleTester.run('no-useless-default-assignment', {
  valid: [
    `
function withOptional(a: number | undefined = 1) {
  return a;
}
    `,
    `
const { a = 1 }: { a?: number } = {};
    `,
  ],
  invalid: [
    {
      code: `
function basic(a: number = 1) {
  return a;
}
      `,
      errors: [{ messageId: 'uselessDefaultAssignment' }],
    },
    {
      code: `
function optional(a: number | undefined = undefined) {
  return a;
}
      `,
      errors: [{ messageId: 'preferOptionalSyntax' }],
    },
    {
      code: `
const { a = undefined }: { a?: number } = {};
      `,
      errors: [{ messageId: 'uselessUndefined' }],
    },
  ],
});
