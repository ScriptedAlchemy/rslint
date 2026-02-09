package no_unused_private_class_members

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnusedPrivateClassMembersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnusedPrivateClassMembersRule, []rule_tester.ValidTestCase{
		{Code: `class A { #value = 1; getValue() { return this.#value; } }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `class A { #value = 1; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedPrivateClassMember", Line: 1, Column: 11}},
		},
	})
}
