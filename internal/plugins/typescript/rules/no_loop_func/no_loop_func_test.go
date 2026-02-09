package no_loop_func

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoLoopFuncRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoLoopFuncRule, []rule_tester.ValidTestCase{
		{Code: `const fn = () => 1;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `for (let i = 0; i < 1; i++) { const fn = () => i; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unsafeRefs", Line: 1, Column: 42}},
		},
	})
}
