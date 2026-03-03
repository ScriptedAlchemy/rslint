package no_redeclare

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoRedeclareRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoRedeclareRule, []rule_tester.ValidTestCase{
		{Code: `const a = 1; { const a = 2; }`},
		{
			Code: `
function a(): string;
function a(): number;
function a() {
  return '';
}
			`,
		},
		{
			Code: `
interface A {}
interface A {}
			`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const a = 1; const a = 2;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "redeclared", Line: 1, Column: 20}},
		},
		{
			Code:   `var a = 3; var a = 10;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "redeclared", Line: 1, Column: 16}},
		},
		{
			Code:   `/*global b:false*/ var b = 1;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "redeclaredBySyntax", Line: 1, Column: 24}},
		},
		{
			Code: `
function a() {}
function a() {}
			`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "redeclared", Line: 3, Column: 10}},
		},
		{
			Code: `
class A {}
class A {}
namespace A {}
			`,
			Options: []interface{}{
				map[string]interface{}{
					"ignoreDeclarationMerge": true,
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "redeclared", Line: 3, Column: 7}},
		},
	})
}
