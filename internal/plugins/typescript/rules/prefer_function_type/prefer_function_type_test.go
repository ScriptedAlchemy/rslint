package prefer_function_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferFunctionTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferFunctionTypeRule, []rule_tester.ValidTestCase{
		{Code: "const _v = 1;"},
	}, []rule_tester.InvalidTestCase{})
}
