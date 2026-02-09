package no_unsafe_function_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnsafeFunctionTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnsafeFunctionTypeRule, []rule_tester.ValidTestCase{
		{Code: `type Fn = () => void;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `type Fn = Function;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "bannedFunctionType", Line: 1, Column: 11}},
		},
	})
}
