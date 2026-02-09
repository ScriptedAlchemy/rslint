package no_invalid_this

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoInvalidThisRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoInvalidThisRule, []rule_tester.ValidTestCase{
		{Code: `class A { method() { return this.value; } }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `function foo() { return this; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unexpectedThis", Line: 1, Column: 25}},
		},
	})
}
