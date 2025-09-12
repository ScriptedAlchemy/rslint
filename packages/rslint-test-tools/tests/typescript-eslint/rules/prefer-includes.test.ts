import { RuleTester } from '@typescript-eslint/rule-tester';

import { getFixturesRootDir } from '../RuleTester';

const rootPath = getFixturesRootDir();

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: {
      project: './tsconfig.json',
      tsconfigRootDir: rootPath,
    },
  },
});

ruleTester.run('prefer-includes', {
  valid: [
    `
      function f(a: string): void {
        a.indexOf(b);
      }
    `,
    `
      function f(a: string): void {
        a.indexOf(b) + 0;
      }
    `,
    `
      function f(a: string | { value: string }): void {
        a.indexOf(b) !== -1;
      }
    `,
    `
      type UserDefined = {
        indexOf(x: any): number; // don't have 'includes'
      };
      function f(a: UserDefined): void {
        a.indexOf(b) !== -1;
      }
    `,
    `
      type UserDefined = {
        indexOf(x: any, fromIndex?: number): number;
        includes(x: any): boolean; // different parameters
      };
      function f(a: UserDefined): void {
        a.indexOf(b) !== -1;
      }
    `,
  ],
  invalid: [
    {
      code: `
        function f(a: string): void {
          a.indexOf(b) !== -1;
        }
      `,
      errors: [{ messageId: 'preferIncludes' }],
      output: `
        function f(a: string): void {
          a.includes(b);
        }
      `,
    },
    {
      code: `
        function f(a: string): void {
          a.indexOf(b) === -1;
        }
      `,
      errors: [{ messageId: 'preferIncludes' }],
      output: `
        function f(a: string): void {
          !a.includes(b);
        }
      `,
    },
    {
      code: `
        function f(a?: string): void {
          a?.indexOf(b) === -1;
        }
      `,
      errors: [{ messageId: 'preferIncludes' }],
      output: null,
    },
    {
      code: `
        function f(a: Uint8Array): void {
          a.indexOf(b) !== -1;
        }
      `,
      errors: [{ messageId: 'preferIncludes' }],
      output: `
        function f(a: Uint8Array): void {
          a.includes(b);
        }
      `,
    },
  ],
});
