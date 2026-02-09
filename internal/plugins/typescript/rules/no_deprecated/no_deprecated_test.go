package no_deprecated

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoDeprecatedRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoDeprecatedRule, []rule_tester.ValidTestCase{
		{Code: `const value = 1; value;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `/** @deprecated */ const oldValue = 1; oldValue;`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "deprecated", Line: 1, Column: 40},
			},
		},
	})
}
