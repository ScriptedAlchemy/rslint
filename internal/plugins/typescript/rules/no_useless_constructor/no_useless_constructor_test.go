package no_useless_constructor

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUselessConstructorRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUselessConstructorRule, []rule_tester.ValidTestCase{
		{Code: "class A {}"},
		{Code: "class A { private constructor() {} }"},
		{Code: "class A { constructor(private name: string) {} }"},
		{Code: "class A extends B { constructor(foo, bar) { super(foo, bar, 1); } }"},
		{Code: "class A extends B { constructor() {} }"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "class A { constructor() {} }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noUselessConstructor", Line: 1, Column: 11},
			},
		},
		{
			Code: "class A extends B { constructor(foo) { super(foo); } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noUselessConstructor", Line: 1, Column: 21},
			},
		},
		{
			Code: "class A extends B { constructor(a, b, ...c) { super(a, b, ...c); } }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noUselessConstructor", Line: 1, Column: 21},
			},
		},
	})
}
