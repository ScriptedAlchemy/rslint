package no_unnecessary_type_constraint

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryTypeConstraintRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryTypeConstraintRule, []rule_tester.ValidTestCase{
		{Code: "function data<T extends number>() {}"},
		{Code: "const data = <T extends string>() => {};"},
		{Code: "type TODO = any; function data<T extends TODO>() {}"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "function data<T extends any>() {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryConstraint", Line: 1, Column: 15},
			},
		},
		{
			Code: "function data<T extends unknown>() {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryConstraint", Line: 1, Column: 15},
			},
		},
		{
			Code: "interface Data<T extends unknown> {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryConstraint", Line: 1, Column: 16},
			},
		},
	})
}
