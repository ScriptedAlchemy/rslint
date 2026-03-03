package explicit_function_return_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestExplicitFunctionReturnTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &ExplicitFunctionReturnTypeRule, []rule_tester.ValidTestCase{
		{Code: `function test(): number { return 1; }`},
		{Code: `const fn: () => number = () => 1;`, Options: []interface{}{map[string]interface{}{"allowTypedFunctionExpressions": true}}},
		{Code: `const fn = () => 1 as const;`, Options: []interface{}{map[string]interface{}{"allowDirectConstAssertionInArrowFunctions": true}}},
		{Code: `const foo = (function () { return 1; })();`, Options: []interface{}{map[string]interface{}{"allowIIFEs": true}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `function test() { return 1; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingReturnType"}},
		},
		{
			Code: `const fn = () => 1;`,
			Options: []interface{}{
				map[string]interface{}{
					"allowExpressions": false,
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingReturnType"}},
		},
		{
			Code:   `class A { method() { return 1; } }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingReturnType"}},
		},
		{
			Code:   `const foo = (function () { return 1; })();`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingReturnType"}},
		},
	})
}
