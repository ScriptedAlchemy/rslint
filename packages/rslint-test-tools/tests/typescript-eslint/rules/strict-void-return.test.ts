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

ruleTester.run('strict-void-return', {
  valid: [
    `
declare function takesVoid(cb: () => void): void;
takesVoid(() => {});
    `,
    `
declare function takesVoid(cb: () => void): void;
takesVoid(function (): void {
  return;
});
    `,
    {
      code: `
declare function takesVoid(cb: () => void): void;
const cb = () => (0 as any);
takesVoid(cb);
      `,
      options: [{ allowReturnAny: true }],
    },
  ],
  invalid: [
    {
      code: `
declare function takesVoid(cb: () => void): void;
takesVoid(() => 1);
      `,
      errors: [{ messageId: 'nonVoidReturn' }],
    },
    {
      code: `
declare function takesVoid(cb: () => void): void;
takesVoid(async () => {});
      `,
      errors: [{ messageId: 'asyncFunc' }],
    },
    {
      code: `
declare function takesVoid(cb: () => void): void;
const cb = () => 1;
takesVoid(cb);
      `,
      errors: [{ messageId: 'nonVoidFunc' }],
    },
    {
      code: `
type VoidFn = () => void;
const cb: VoidFn = () => {
  return 1;
};
      `,
      errors: [{ messageId: 'nonVoidReturn' }],
    },
  ],
});
