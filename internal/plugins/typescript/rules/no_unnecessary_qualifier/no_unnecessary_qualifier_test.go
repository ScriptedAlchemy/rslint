package no_unnecessary_qualifier

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryQualifierRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryQualifierRule, []rule_tester.ValidTestCase{
		{Code: `type A = string;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `namespace N { export type A = string; } type B = N.A;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unnecessaryQualifier", Line: 1, Column: 50}},
		},
	})
}
