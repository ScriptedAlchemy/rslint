import { RuleTester } from '@typescript-eslint/rule-tester';

const ruleTester = new RuleTester();

ruleTester.run('no-unused-private-class-members', {
  valid: [
    `
class A {
  #value = 1;
  getValue() {
    return this.#value;
  }
}
    `,
  ],
  invalid: [
    {
      code: `
class A {
  #value = 1;
}
      `,
      errors: [
        {
          line: 3,
          column: 3,
          messageId: 'unusedPrivateClassMember',
        },
      ],
      output: null,
    },
  ],
});

