package prefer_optional_chain

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferOptionalChainRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferOptionalChainRule, []rule_tester.ValidTestCase{
		{Code: `value?.name`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `value && value.name`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferOptionalChain", Line: 1, Column: 1}},
		},
	})
}
