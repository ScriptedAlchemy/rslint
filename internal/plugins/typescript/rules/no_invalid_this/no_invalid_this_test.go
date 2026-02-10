package no_invalid_this

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoInvalidThisRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoInvalidThisRule, []rule_tester.ValidTestCase{
		{
			Code: `
class A {
  foo() {
    return this;
  }
}
			`,
		},
		{
			Code: `
function foo(this: { prop: string }) {
  return this.prop;
}
			`,
		},
		{
			Code: `
function Foo() {
  return this;
}
			`,
		},
		{
			Code: `
const obj = {
  foo: function () {
    return this;
  },
};
			`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
function foo() {
  return this;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpectedThis", Line: 3},
			},
		},
		{
			Code: `
console.log(this);
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unexpectedThis", Line: 2},
			},
		},
	})
}
