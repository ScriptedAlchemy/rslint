package no_unnecessary_type_parameters

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryTypeParametersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryTypeParametersRule, []rule_tester.ValidTestCase{
		{Code: "const _v = 1;"},
	}, []rule_tester.InvalidTestCase{})
}
