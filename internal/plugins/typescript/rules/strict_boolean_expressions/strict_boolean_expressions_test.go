package strict_boolean_expressions

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestStrictBooleanExpressionsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &StrictBooleanExpressionsRule, []rule_tester.ValidTestCase{
		{Code: `declare const value: boolean; if (value) {}`},
		{Code: `const value: string = "x"; if (value) {}`, Options: map[string]any{"allowString": true}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const value: {} = {}; if (value) {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "conditionErrorOther", Line: 1, Column: 27}},
		},
		{
			Code:   `const value: string = "x"; if (value) {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "conditionErrorOther", Line: 1, Column: 32}},
		},
	})
}
