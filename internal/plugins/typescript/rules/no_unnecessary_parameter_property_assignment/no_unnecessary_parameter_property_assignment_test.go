package no_unnecessary_parameter_property_assignment

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryParameterPropertyAssignmentRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryParameterPropertyAssignmentRule, []rule_tester.ValidTestCase{
		{Code: "class Foo { constructor(foo: string) {} }"},
		{Code: "class Foo { constructor(private foo: string) { this.foo = bar; } }"},
		{Code: "class Foo { constructor(private foo: string) { this.bar = () => { this.foo = foo; }; } }"},
		{Code: "class Foo { constructor(public foo: number) { this.foo += foo; } }"},
		{Code: "class Foo { constructor(public foo: number) { { const foo = 1; this.foo = foo; } } }"},
		{Code: "class Foo { constructor(public foo: number) { this[name] = foo; } }"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "class Foo { constructor(public foo: string) { this.foo = foo; } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryAssign", Line: 1, Column: 45},
			},
		},
		{
			Code: "class Foo { constructor(public foo?: string) { this.foo = foo!; } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryAssign", Line: 1, Column: 46},
			},
		},
		{
			Code: "class Foo { constructor(public foo?: string) { this.foo = foo as any; } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryAssign", Line: 1, Column: 46},
			},
		},
		{
			Code: "class Foo { constructor(public foo: string) { this.foo ||= foo; } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryAssign", Line: 1, Column: 45},
			},
		},
		{
			Code: "class Foo { constructor(private foo: string) { this['foo'] = foo; } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryAssign", Line: 1, Column: 46},
			},
		},
		{
			Code: "class Foo { constructor(private foo: string) { (() => { this.foo = foo; })(); } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryAssign", Line: 1, Column: 56},
			},
		},
	})
}
