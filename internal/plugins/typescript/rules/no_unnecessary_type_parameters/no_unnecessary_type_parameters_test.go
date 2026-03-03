package no_unnecessary_type_parameters

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryTypeParametersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryTypeParametersRule, []rule_tester.ValidTestCase{
		{Code: `function id<T>(value: T): T { return value; }`},
		{Code: `const fn = <T>(value: T) => value;`},
		{Code: `type Fn = <T>(input: T) => typeof input;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `function foo<T>(value: string): string { return value; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "sole", Line: 1, Column: 14}},
		},
		{
			Code: `
class Joiner<T extends string | number> {
  join(el: T, other: string) {
    return [el, other].join(',');
  }
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "sole", Line: 2, Column: 14}},
		},
	})
}
