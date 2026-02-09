package prefer_enum_initializers

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferEnumInitializersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferEnumInitializersRule, []rule_tester.ValidTestCase{
		{Code: `enum E { A = 0, B = 1 }`},
		{Code: `enum E { A = "A", B = "B" }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `enum E { A, B = 1 }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "defineInitializer", Line: 1, Column: 10}},
		},
		{
			Code:   `enum E { A = 0, B }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "defineInitializer", Line: 1, Column: 17}},
		},
	})
}
