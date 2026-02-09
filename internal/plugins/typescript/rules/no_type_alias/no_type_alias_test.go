package no_type_alias

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoTypeAliasRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoTypeAliasRule, []rule_tester.ValidTestCase{
		{Code: `interface Foo { bar: string }`},
		{Code: `type Foo = string`, Options: map[string]interface{}{"allowAliases": "always"}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `type Foo = string`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noTypeAlias", Line: 1, Column: 1}},
		},
	})
}
