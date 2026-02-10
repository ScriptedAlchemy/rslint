package no_magic_numbers

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoMagicNumbersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoMagicNumbersRule, []rule_tester.ValidTestCase{
		{Code: `const value = 42;`},
		{Code: `const value = 1;`, Options: map[string]interface{}{"ignore": []interface{}{"1"}}},
		{Code: `enum Foo { A = 1 }`, Options: map[string]interface{}{"ignoreEnums": true}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const value = 42;`,
			Options: map[string]interface{}{
				"enforceConst": true,
			},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noMagic", Line: 1, Column: 15}},
		},
		{
			Code:   `type Foo = -1;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noMagic", Line: 1, Column: 12}},
		},
	})
}
