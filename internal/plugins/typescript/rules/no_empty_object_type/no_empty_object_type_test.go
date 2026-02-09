package no_empty_object_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoEmptyObjectTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoEmptyObjectTypeRule, []rule_tester.ValidTestCase{
		{Code: `interface Base { name: string }`},
		{Code: `let value: object;`},
		{Code: `type MyNonNullable<T> = T & {};`},
		{Code: `type Base = {};`, Options: map[string]interface{}{"allowObjectTypes": "always"}},
		{Code: `interface Base {}`, Options: map[string]interface{}{"allowInterfaces": "always"}},
		{Code: `interface BaseProps {}`, Options: map[string]interface{}{"allowWithName": "Props$"}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `interface Base {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noEmptyInterface", Line: 1, Column: 11}},
		},
		{
			Code: `
interface Parent {
  name: string;
}
interface Child extends Parent {}
`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noEmptyInterfaceWithSuper", Line: 5, Column: 11}},
		},
		{
			Code:   `type Empty = {};`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noEmptyObject", Line: 1, Column: 14}},
		},
	})
}
