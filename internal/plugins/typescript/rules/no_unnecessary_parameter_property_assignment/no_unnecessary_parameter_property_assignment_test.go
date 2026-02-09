package no_unnecessary_parameter_property_assignment

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryParameterPropertyAssignmentRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryParameterPropertyAssignmentRule, []rule_tester.ValidTestCase{
		{Code: `class A { constructor(public name: string) {} }`},
		{Code: `class Foo {
  constructor(public foo: number) {
    this.foo = foo;
  }
  init = (() => {
    this.foo += 1;
  })();
}`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `class A { constructor(public name: string) { this.name = name; } }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unnecessaryAssign", Line: 1, Column: 46}},
		},
		{
			Code: `class Foo {
  constructor(private foo: string) {
    (() => {
      this.foo = foo;
    })();
  }
}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unnecessaryAssign", Line: 4, Column: 7}},
		},
	})
}
