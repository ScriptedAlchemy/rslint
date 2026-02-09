package prefer_function_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferFunctionTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferFunctionTypeRule, []rule_tester.ValidTestCase{
		{Code: `type Fn = (value: string) => number;`},
		{Code: `interface Fn { (value: string): number; foo: string }`},
		{Code: `interface Fn extends Something { (value: string): number }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `interface Fn { (value: string): number }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "functionTypeOverCallableType", Line: 1, Column: 16}},
		},
		{
			Code:   `type Fn = { (value: string): number };`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "functionTypeOverCallableType", Line: 1, Column: 13}},
		},
	})
}
