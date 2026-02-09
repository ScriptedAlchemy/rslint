package prefer_destructuring

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferDestructuringRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferDestructuringRule, []rule_tester.ValidTestCase{
		{Code: `const { foo } = obj;`},
		{Code: `const foo = fn();`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const foo = obj.foo;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferDestructuring", Line: 1, Column: 7}},
		},
	})
}
