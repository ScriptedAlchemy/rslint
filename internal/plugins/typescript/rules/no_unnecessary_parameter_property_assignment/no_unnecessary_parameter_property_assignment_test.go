package no_unnecessary_parameter_property_assignment

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryParameterPropertyAssignmentRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryParameterPropertyAssignmentRule, []rule_tester.ValidTestCase{
		{Code: `class A { constructor(public name: string) {} }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `class A { constructor(public name: string) { this.name = name; } }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unnecessaryAssign", Line: 1, Column: 46}},
		},
	})
}
