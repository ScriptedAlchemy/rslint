package typedef

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestTypedefRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &TypedefRule, []rule_tester.ValidTestCase{
		{Code: `const foo: string = "bar";`},
		{Code: `function foo(a) {}`, Options: map[string]interface{}{"parameter": false}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const foo = "bar";`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "expectedTypedef", Line: 1, Column: 7}},
		},
		{
			Code:    `function foo(a) {}`,
			Options: map[string]interface{}{"parameter": true, "variableDeclaration": false},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "expectedTypedef", Line: 1, Column: 14}},
		},
	})
}
