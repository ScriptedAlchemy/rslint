package no_use_before_define

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUseBeforeDefineRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUseBeforeDefineRule, []rule_tester.ValidTestCase{
		{Code: `const a = 1; console.log(a);`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `console.log(a); const a = 1;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noUseBeforeDefine", Line: 1, Column: 13}},
		},
	})
}
