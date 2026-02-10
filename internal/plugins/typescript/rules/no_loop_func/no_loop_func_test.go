package no_loop_func

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoLoopFuncRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoLoopFuncRule, []rule_tester.ValidTestCase{
		{
			Code: `
for (let i = 0; i < 10; i++) {
  function foo() {
    i;
  }
}
			`,
		},
		{
			Code: `
for (var i = 0; i < 10; i++) {
  function foo(j: number) {
    j;
  }
}
			`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
for (var i = 0; i < 10; i++) {
  function foo() {
    i;
  }
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unsafeRefs", Line: 3},
			},
		},
		{
			Code: `
for (var i in xs) {
  const foo = () => i;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unsafeRefs", Line: 3},
			},
		},
	})
}
