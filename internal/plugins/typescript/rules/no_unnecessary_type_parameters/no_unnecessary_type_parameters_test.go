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
		{Code: `function makeMap<K, V>() { return new Map<K, V>(); }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `function foo<T>(value: string): string { return value; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "sole", Line: 1, Column: 14}},
		},
	})
}
