package explicit_module_boundary_types

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestExplicitModuleBoundaryTypesRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &ExplicitModuleBoundaryTypesRule, []rule_tester.ValidTestCase{
		{Code: `export function foo(a: string): number { return a.length; }`},
		{Code: `function foo(a) { return a; }`},
		{Code: `export const foo = (a: string): number => a.length;`},
		{Code: `export function foo(a: any): number { return 1; }`, Options: map[string]interface{}{"allowArgumentsExplicitlyTypedAsAny": true}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `export function foo(a: string) { return a.length; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingReturnType", Line: 1, Column: 1}},
		},
		{
			Code:   `export function foo(a): number { return 1; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingArgType", Line: 1, Column: 21}},
		},
		{
			Code:   `export function foo(a: any): number { return 1; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "anyTypedArg", Line: 1, Column: 21}},
		},
	})
}
