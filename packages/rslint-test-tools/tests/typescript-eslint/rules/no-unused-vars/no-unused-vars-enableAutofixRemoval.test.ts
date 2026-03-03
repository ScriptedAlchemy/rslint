import { RuleTester } from '@typescript-eslint/rule-tester';

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: {
      ecmaFeatures: {},
      ecmaVersion: 6,
      sourceType: 'module',
    },
  },
});

ruleTester.run('no-unused-vars', {
  valid: [
    `
import { Used } from 'module';
export { Used };
    `,
  ],
  invalid: [
    {
      code: `
import Unused from 'module';
export {};
      `,
      errors: [
        {
          data: {
            action: 'defined',
            additional: '',
            varName: 'Unused',
          },
          messageId: 'unusedVar',
        },
      ],
      options: [
        {
          enableAutofixRemoval: {
            imports: true,
          },
        } as any,
      ],
    },
  ],
});
