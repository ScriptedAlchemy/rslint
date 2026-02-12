package naming_convention

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNamingConventionRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NamingConventionRule, []rule_tester.ValidTestCase{
		{Code: `class UserName {}; const userName = 1;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `class userName {}; const UserName = 1;`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "doesNotMatchFormat", Line: 1, Column: 7},
				{MessageId: "doesNotMatchFormat", Line: 1, Column: 26},
			},
		},
	})
}
