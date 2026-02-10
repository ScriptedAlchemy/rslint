package prefer_function_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferFunctionTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferFunctionTypeRule, []rule_tester.ValidTestCase{
		{Code: "interface Foo { (): void; bar: number; }"},
		{Code: "interface Foo { bar: string; }\ninterface Bar extends Foo { (): void; }"},
		{Code: "type Foo = (x: string) => number;"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "interface Foo { (): string; }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "functionTypeOverCallableType", Line: 1, Column: 17},
			},
		},
		{
			Code: "type Foo = { (): string; };",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "functionTypeOverCallableType", Line: 1, Column: 14},
			},
		},
		{
			Code: "interface Foo { (arg: this): void; }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpectedThisOnFunctionOnlyInterface", Line: 1, Column: 23},
			},
		},
	})
}
