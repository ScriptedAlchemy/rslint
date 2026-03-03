package no_wrapper_object_types

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoWrapperObjectTypesRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoWrapperObjectTypesRule, []rule_tester.ValidTestCase{
		{Code: "let value: number;"},
		{Code: "type Number = 0 | 1; let value: Number;"},
		{Code: "class MyClass extends Number {}"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "let value: Number;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedClassType", Line: 1, Column: 12},
			},
		},
		{
			Code: "interface MyInterface extends Number {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedClassType", Line: 1, Column: 31},
			},
		},
		{
			Code: "class MyClass implements Number {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedClassType", Line: 1, Column: 26},
			},
		},
	})
}
