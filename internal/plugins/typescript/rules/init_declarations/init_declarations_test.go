package init_declarations

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestInitDeclarationsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &InitDeclarationsRule, []rule_tester.ValidTestCase{
		{Code: "var foo = null;"},
		{Code: "let foo = 1;", Options: []interface{}{"always"}},
		{Code: "const foo = 1;", Options: []interface{}{"never"}},
		{Code: "declare const foo: number;", Options: []interface{}{"always"}},
		{Code: "for (var i = 0; i < 1; i++) {}", Options: []interface{}{"never", map[string]interface{}{"ignoreForLoopInit": true}}},
		{Code: "for (var foo of []) {}", Options: []interface{}{"never", map[string]interface{}{"ignoreForLoopInit": true}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:    "let foo: string;",
			Options: []interface{}{"always"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "initialized"},
			},
		},
		{
			Code:    "let foo: string = 'bar';",
			Options: []interface{}{"never"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "notInitialized"},
			},
		},
		{
			Code:    "for (var foo of []) {}",
			Options: []interface{}{"never"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "notInitialized"},
			},
		},
		{
			Code: `
namespace myLib {
  let numberOfGreetings: number;
}
      `,
			Options: []interface{}{"always"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "initialized"},
			},
		},
	})
}
