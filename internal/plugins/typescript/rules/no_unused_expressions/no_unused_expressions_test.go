package no_unused_expressions

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnusedExpressionsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnusedExpressionsRule, []rule_tester.ValidTestCase{
		{Code: "foo();"},
		{Code: "new Foo<string>();"},
		{Code: "import('./foo');"},
		{Code: "function f(){ 'use strict'; return 1; }"},
		{Code: "foo && foo();", Options: []interface{}{map[string]interface{}{"allowShortCircuit": true}}},
		{Code: "foo ? bar() : baz();", Options: []interface{}{map[string]interface{}{"allowTernary": true}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "a?.b;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedExpression", Line: 1, Column: 1},
			},
		},
		{
			Code: "foo && foo.bar;",
			Options: []interface{}{map[string]interface{}{
				"allowShortCircuit": true,
			}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedExpression", Line: 1, Column: 1},
			},
		},
		{
			Code: "foo as any;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedExpression", Line: 1, Column: 1},
			},
		},
		{
			Code: "module Foo { const foo = true; 'use strict'; }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedExpression", Line: 1, Column: 32},
			},
		},
	})
}
