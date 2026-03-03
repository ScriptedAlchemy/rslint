package no_unnecessary_qualifier

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryQualifierRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryQualifierRule, []rule_tester.ValidTestCase{
		{Code: `namespace X { export type T = number; } namespace Y { const x: X.T = 3; }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `namespace A { export type B = number; const x: A.B = 3; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unnecessaryQualifier", Line: 1, Column: 48}},
		},
	})
}
