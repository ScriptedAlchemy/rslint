package no_useless_constructor

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUselessConstructorRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUselessConstructorRule, []rule_tester.ValidTestCase{
		{Code: `class A {}`},
		{Code: `class A { constructor(private name: string) {} }`},
		{Code: `class A extends B { constructor() {} }`},
		{Code: `class A extends B { constructor(foo, bar) { super(foo); } }`},
		{Code: `class A extends B { constructor(a = f()) { super(...arguments); } }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `class A { constructor() {} }`,
			Errors: []rule_tester.InvalidTestCaseError{{
				MessageId: "noUselessConstructor",
				Line:      1,
				Column:    11,
			}},
		},
		{
			Code: `class A extends B { constructor() { super(); } }`,
			Errors: []rule_tester.InvalidTestCaseError{{
				MessageId: "noUselessConstructor",
				Line:      1,
				Column:    21,
			}},
		},
		{
			Code: `class A extends B { constructor(foo, bar, ...rest) { super(foo, bar, ...rest); } }`,
			Errors: []rule_tester.InvalidTestCaseError{{
				MessageId: "noUselessConstructor",
				Line:      1,
				Column:    21,
			}},
		},
		{
			Code: `class A extends B { constructor(a, b, ...c) { super(...arguments); } }`,
			Errors: []rule_tester.InvalidTestCaseError{{
				MessageId: "noUselessConstructor",
				Line:      1,
				Column:    21,
			}},
		},
	})
}
