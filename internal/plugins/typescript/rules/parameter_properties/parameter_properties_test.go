package parameter_properties

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestParameterPropertiesRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &ParameterPropertiesRule, []rule_tester.ValidTestCase{
		{Code: `class A { constructor(name: string) {} }`},
		{Code: `class A { name: string; constructor(name: string) { this.name = name; } }`, Options: map[string]interface{}{"prefer": "class-property"}},
		{Code: `class A { constructor(public name: string) {} }`, Options: map[string]interface{}{"prefer": "parameter-property"}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `class A { constructor(public name: string) {} }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferClassProperty", Line: 1, Column: 23}},
		},
		{
			Code:    `class A { name: string; constructor(name: string) { this.name = name; } }`,
			Options: map[string]interface{}{"prefer": "parameter-property"},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "preferParameterProperty", Line: 1, Column: 11}},
		},
	})
}
