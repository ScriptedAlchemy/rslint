package no_unsafe_function_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnsafeFunctionTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnsafeFunctionTypeRule, []rule_tester.ValidTestCase{
		{Code: "let value: () => void;"},
		{Code: "{ type Function = () => void; let value: Function; }"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "let value: Function;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedFunctionType", Line: 1, Column: 12},
			},
		},
		{
			Code: "interface Weird extends Function {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedFunctionType", Line: 1, Column: 25},
			},
		},
	})
}
