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
    `
[1, 2, 3, undefined].map((a = 42) => a + 1);
    `,
    `
function test(a: any = 'default') {
  return a;
}
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
      output: `
function basic(a: number) {
  return a;
}
      `,
    },
    {
      code: `
function optional(a: number | undefined = undefined) {
  return a;
}
      `,
      errors: [{ messageId: 'preferOptionalSyntax' }],
      output: `
function optional(a?: number | undefined) {
  return a;
}
      `,
    },
    {
      code: `
const { a = undefined }: { a?: number } = {};
      `,
      errors: [{ messageId: 'uselessUndefined' }],
      output: `
const { a }: { a?: number } = {};
      `,
    },
    {
      code: `
function withObject({ foo = '' }: { foo: string }) {
  return foo;
}
      `,
      errors: [{ messageId: 'uselessDefaultAssignment' }],
      output: `
function withObject({ foo }: { foo: string }) {
  return foo;
}
      `,
    },
    {
      code: `
[1, 2, 3].map((a = 42) => a + 1);
      `,
      errors: [{ messageId: 'uselessDefaultAssignment' }],
      output: `
[1, 2, 3].map((a) => a + 1);
      `,
    },
    {
      code: `
interface B {
  foo: (b: boolean | string) => void;
}

const h: B = {
  foo: (b = false) => {},
};
      `,
      errors: [{ messageId: 'uselessDefaultAssignment' }],
      output: `
interface B {
  foo: (b: boolean | string) => void;
}

const h: B = {
  foo: (b) => {},
};
      `,
    },
    {
      code: `
const [a = undefined] = [];
      `,
      errors: [{ messageId: 'uselessUndefined' }],
      output: `
const [a] = [];
      `,
    },
  ],
});
