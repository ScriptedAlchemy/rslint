package no_dupe_class_members

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoDupeClassMembersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoDupeClassMembersRule, []rule_tester.ValidTestCase{
		{
			Code: `
class A {
  foo() {}
  bar() {}
}
			`,
		},
		{
			Code: `
class A {
  static foo() {}
  foo() {}
}
			`,
		},
		{
			Code: `
class A {
  get foo() {}
  set foo(value) {}
}
			`,
		},
		{
			Code: `
class A {
  static foo() {}
  get foo() {}
  set foo(value) {}
}
			`,
		},
		{
			Code: `
class A {
  foo() {}
}
class B {
  foo() {}
}
			`,
		},
		{
			Code: `
class A {
  [foo]() {}
  foo() {}
}
			`,
		},
		{
			Code: `
class A {
  foo() {}
  bar() {}
  baz() {}
}
			`,
		},
		{
			Code: `
class A {
  *foo() {}
  *bar() {}
  *baz() {}
}
			`,
		},
		{
			Code: `
class A {
  get foo() {}
  get bar() {}
  get baz() {}
}
			`,
		},
		{
			Code: `
class A {
  1() {}
  2() {}
}
			`,
		},
		{
			Code: `
class Foo {
  foo(a: string): string;
  foo(a: number): number;
  foo(a: any): any {}
}
			`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
class A {
  foo() {}
  foo() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 11},
			},
		},
		{
			Code: `
!class A {
  foo() {}
  foo() {}
};
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 11},
			},
		},
		{
			Code: `
class A {
  'foo'() {}
  'foo'() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 13},
			},
		},
		{
			Code: `
class A {
  10() {}
  1e1() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 11},
			},
		},
		{
			Code: `
class A {
  foo() {}
  foo() {}
  foo() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 11},
				{MessageId: "unexpected", Line: 5, Column: 3, EndLine: 5, EndColumn: 11},
			},
		},
		{
			Code: `
class A {
  static foo() {}
  static foo() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 18},
			},
		},
		{
			Code: `
class A {
  foo() {}
  get foo() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 15},
			},
		},
		{
			Code: `
class A {
  set foo(value) {}
  foo() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 11},
			},
		},
		{
			Code: `
class A {
  foo;
  foo = 42;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 12},
			},
		},
		{
			Code: `
class A {
  foo;
  foo() {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpected", Line: 4, Column: 3, EndLine: 4, EndColumn: 11},
			},
		},
	})
}
