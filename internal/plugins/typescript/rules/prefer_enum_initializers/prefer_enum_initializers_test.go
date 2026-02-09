package prefer_enum_initializers

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferEnumInitializersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferEnumInitializersRule, []rule_tester.ValidTestCase{
		{Code: "enum Direction { Up = 1 }"},
		{Code: "enum Direction {}"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "enum Direction { Up }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "defineInitializer", Line: 1, Column: 18},
			},
		},
		{
			Code: "enum Direction { Up, Down }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "defineInitializer", Line: 1, Column: 18},
				{MessageId: "defineInitializer", Line: 1, Column: 22},
			},
		},
	})
}
