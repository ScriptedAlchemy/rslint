package no_magic_numbers

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoMagicNumbersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoMagicNumbersRule, []rule_tester.ValidTestCase{
		{
			Code:    "type Foo = 1;",
			Options: []interface{}{map[string]interface{}{"ignoreNumericLiteralTypes": true}},
		},
		{
			Code: `
enum foo {
  SECOND = 1000,
  NEG = -1,
}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreEnums": true}},
		},
		{
			Code: `
class Foo {
  readonly A = 1;
  private readonly B = 100n;
}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreReadonlyClassProperties": true}},
		},
		{
			Code:    "type Foo = Bar[1 | -2];",
			Options: []interface{}{map[string]interface{}{"ignoreTypeIndexes": true}},
		},
		{
			Code:    "type Foo = -7e-8;",
			Options: []interface{}{map[string]interface{}{"ignore": []interface{}{-7e-8}}},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:    "type Foo = 1;",
			Options: []interface{}{map[string]interface{}{"ignoreNumericLiteralTypes": false}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noMagic", Line: 1, Column: 12},
			},
		},
		{
			Code: `
interface Foo {
  bar: 1;
}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreNumericLiteralTypes": true}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noMagic", Line: 3, Column: 8},
			},
		},
		{
			Code: `
enum foo {
  SECOND = 1000,
  NEG = -1,
}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreEnums": false}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noMagic", Line: 3, Column: 12},
				{MessageId: "noMagic", Line: 4, Column: 9},
			},
		},
		{
			Code: `
type Foo = {
  [K in 0 | 1 | 2]: 0;
};
			`,
			Options: []interface{}{map[string]interface{}{"ignoreTypeIndexes": true}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noMagic", Line: 3, Column: 9},
				{MessageId: "noMagic", Line: 3, Column: 13},
				{MessageId: "noMagic", Line: 3, Column: 17},
				{MessageId: "noMagic", Line: 3, Column: 21},
			},
		},
		{
			Code:    "type Foo = -4n;",
			Options: []interface{}{map[string]interface{}{"ignore": []interface{}{"4n"}}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noMagic", Line: 1, Column: 12},
			},
		},
	})
}
