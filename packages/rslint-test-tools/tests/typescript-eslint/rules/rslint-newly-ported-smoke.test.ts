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

ruleTester.run('explicit-module-boundary-types', {
  valid: ['export function foo(a: string): string { return a; }'],
  invalid: [
    {
      code: 'export function foo(a: string) { return a; }',
      errors: [{ messageId: 'missingReturnType' }],
    },
  ],
});

ruleTester.run('no-magic-numbers', {
  valid: [{ code: 'const value = 1;', options: [{ ignore: ['1'] }] }],
  invalid: [
    {
      code: 'const value = 42;',
      errors: [{ messageId: 'noMagic' }],
    },
  ],
});

ruleTester.run('no-restricted-imports', {
  valid: ['import foo from "foo";'],
  invalid: [
    {
      code: 'import foo from "foo";',
      options: ['foo'],
      errors: [{ messageId: 'path' }],
    },
  ],
});

ruleTester.run('no-type-alias', {
  valid: [{ code: 'type Foo = string;', options: [{ allowAliases: 'always' }] }],
  invalid: [
    {
      code: 'type Foo = string;',
      errors: [{ messageId: 'noTypeAlias' }],
    },
  ],
});

ruleTester.run('parameter-properties', {
  valid: ['class A { constructor(name: string) {} }'],
  invalid: [
    {
      code: 'class A { constructor(public name: string) {} }',
      errors: [{ messageId: 'preferClassProperty' }],
    },
  ],
});

ruleTester.run('prefer-destructuring', {
  valid: ['const { foo } = obj;'],
  invalid: [
    {
      code: 'const foo = obj.foo;',
      errors: [{ messageId: 'preferDestructuring' }],
    },
  ],
});

ruleTester.run('prefer-function-type', {
  valid: ['type Fn = (value: string) => number;'],
  invalid: [
    {
      code: 'interface Fn { (value: string): number }',
      errors: [{ messageId: 'functionTypeOverCallableType' }],
    },
  ],
});

ruleTester.run('sort-type-constituents', {
  valid: ['type A = number | string;'],
  invalid: [
    {
      code: 'type A = string | number;',
      errors: [{ messageId: 'notSortedNamed' }],
    },
  ],
});

ruleTester.run('typedef', {
  valid: ['const foo: string = "bar";'],
  invalid: [
    {
      code: 'const foo = "bar";',
      errors: [{ messageId: 'expectedTypedef' }],
    },
  ],
});

ruleTester.run('naming-convention', {
  valid: ['class UserName {}; const userName = 1;'],
  invalid: [
    {
      code: 'class userName {};',
      errors: [{ messageId: 'doesNotMatchFormat' }],
    },
  ],
});

ruleTester.run('no-invalid-this', {
  valid: ['class A { method() { return this.value; } }'],
  invalid: [
    {
      code: 'function foo() { return this; }',
      errors: [{ messageId: 'unexpectedThis' }],
    },
  ],
});

ruleTester.run('no-loop-func', {
  valid: ['const fn = () => 1;'],
  invalid: [
    {
      code: 'for (var i = 0; i < 1; i++) { const fn = () => i; }',
      errors: [{ messageId: 'unsafeRefs' }],
    },
  ],
});

ruleTester.run('no-redeclare', {
  valid: ['const a = 1; { const a = 2; }'],
  invalid: [
    {
      code: 'const a = 1; const a = 2;',
      errors: [{ messageId: 'redeclared' }],
    },
  ],
});

ruleTester.run('no-shadow', {
  valid: ['const a = 1; const b = () => a;'],
  invalid: [
    {
      code: 'const a = 1; function f() { const a = 2; }',
      errors: [{ messageId: 'noShadow' }],
    },
  ],
});

ruleTester.run('no-unnecessary-parameter-property-assignment', {
  valid: ['class A { constructor(public name: string) {} }'],
  invalid: [
    {
      code: 'class A { constructor(public name: string) { this.name = name; } }',
      errors: [{ messageId: 'unnecessaryAssign' }],
    },
  ],
});

ruleTester.run('no-unused-private-class-members', {
  valid: ['class A { #value = 1; getValue() { return this.#value; } }'],
  invalid: [
    {
      code: 'class A { #value = 1; }',
      errors: [{ messageId: 'unusedPrivateClassMember' }],
    },
  ],
});

ruleTester.run('no-use-before-define', {
  valid: ['const a = 1; console.log(a);'],
  invalid: [
    {
      code: 'console.log(a); const a = 1;',
      errors: [{ messageId: 'noUseBeforeDefine' }],
    },
  ],
});

ruleTester.run('no-deprecated', {
  valid: ['const value = 1; value;'],
  invalid: [
    {
      code: '/** @deprecated */ const oldValue = 1; oldValue;',
      errors: [{ messageId: 'deprecated' }],
    },
  ],
});

ruleTester.run('no-restricted-types', {
  valid: [{ code: 'type A = number;', options: ['Foo'] }],
  invalid: [
    {
      code: 'type Foo = number; type A = Foo;',
      options: ['Foo'],
      errors: [{ messageId: 'bannedTypeMessage' }],
    },
  ],
});

ruleTester.run('no-unnecessary-qualifier', {
  valid: ['type T = number;'],
  invalid: [
    {
      code: 'namespace A { export type B = number; const x: A.B = 3; }',
      errors: [{ messageId: 'unnecessaryQualifier' }],
    },
  ],
});

ruleTester.run('no-unnecessary-type-conversion', {
  valid: ['const a = value as string;'],
  invalid: [
    {
      code: 'const a = (value as string) as string;',
      errors: [{ messageId: 'unnecessaryTypeConversion' }],
    },
  ],
});

ruleTester.run('no-unnecessary-type-parameters', {
  valid: ['function id<T>(value: T): T { return value; }'],
  invalid: [
    {
      code: 'function foo<T>(value: string): string { return value; }',
      errors: [{ messageId: 'unnecessaryTypeParameter' }],
    },
  ],
});

ruleTester.run('no-unsafe-declaration-merging', {
  valid: ['interface Foo { props: string } (function bar() { class Foo {} })()'],
  invalid: [
    {
      code: 'interface Foo {} class Foo {}',
      errors: [{ messageId: 'unsafeMerging' }, { messageId: 'unsafeMerging' }],
    },
  ],
});

ruleTester.run('no-unsafe-function-type', {
  valid: ['type Fn = () => void;'],
  invalid: [
    {
      code: 'type Fn = Function;',
      errors: [{ messageId: 'bannedFunctionType' }],
    },
  ],
});

ruleTester.run('prefer-optional-chain', {
  valid: ['value?.name'],
  invalid: [
    {
      code: 'value && value.name',
      errors: [{ messageId: 'preferOptionalChain' }],
    },
  ],
});

ruleTester.run('strict-boolean-expressions', {
  valid: ['if (value === 1) {}'],
  invalid: [
    {
      code: 'const value: string = "x"; if (value) {}',
      errors: [{ messageId: 'conditionErrorOther' }],
    },
  ],
});
