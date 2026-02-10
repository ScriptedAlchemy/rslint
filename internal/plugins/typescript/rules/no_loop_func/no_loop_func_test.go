package no_loop_func

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoLoopFuncRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoLoopFuncRule, []rule_tester.ValidTestCase{
		{Code: `const fn = () => 1;`},
		{Code: `for (let i = 0; i < 1; i++) { const fn = () => i; }`},
		{Code: `let a = 0; for (let i = 0; i < 1; i++) { const fn = function() { return a; }; }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `for (var i = 0; i < 1; i++) { const fn = function() { return i; }; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unsafeRefs"}},
		},
	})
}
