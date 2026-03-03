package no_restricted_types

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoRestrictedTypesRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoRestrictedTypesRule, []rule_tester.ValidTestCase{
		{Code: `type A = number; type B = A;`, Options: []interface{}{"Foo"}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:    `type Foo = number; type A = Foo;`,
			Options: []interface{}{"Foo"},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "bannedTypeMessage", Line: 1, Column: 29}},
		},
	})
}
