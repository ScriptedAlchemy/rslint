package no_redeclare

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoRedeclareRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoRedeclareRule, []rule_tester.ValidTestCase{
		{
			Code: `
function a(): string;
function a(): number;
function a() {}
			`,
		},
		{
			Code: `
interface A {}
interface A {}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreDeclarationMerge": true}},
		},
		{
			Code:    "var Object = 0;",
			Options: []interface{}{map[string]interface{}{"builtinGlobals": false}},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
var a = 3;
var a = 10;
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "redeclared", Line: 3},
			},
		},
		{
			Code:    "var Object = 0;",
			Options: []interface{}{map[string]interface{}{"builtinGlobals": true}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "redeclaredAsBuiltin", Line: 1},
			},
		},
		{
			Code: `
interface A {}
interface A {}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreDeclarationMerge": false}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "redeclared", Line: 3},
			},
		},
		{
			Code: `
class A {}
class A {}
			`,
			Options: []interface{}{map[string]interface{}{"ignoreDeclarationMerge": true}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "redeclared", Line: 3},
			},
		},
	})
}
