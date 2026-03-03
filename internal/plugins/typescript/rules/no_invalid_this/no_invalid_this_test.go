package no_invalid_this

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoInvalidThisRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoInvalidThisRule, []rule_tester.ValidTestCase{
		{Code: `class A { method() { return this.value; } }`},
		{Code: `function foo(this: { value: string }) { return this.value; }`},
		{Code: `function Foo() { return this; }`},
		{Code: `const obj = { foo: function () { return this; } };`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `function foo() { return this; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unexpectedThis", Line: 1, Column: 25}},
		},
		{
			Code:    `function Foo() { return this; }`,
			Options: []interface{}{map[string]interface{}{"capIsConstructor": false}},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "unexpectedThis", Line: 1, Column: 25}},
		},
	})
}
