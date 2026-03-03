package no_unsafe_declaration_merging

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnsafeDeclarationMergingRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnsafeDeclarationMergingRule, []rule_tester.ValidTestCase{
		{Code: `class A {} interface B {}`},
		{Code: `interface Foo { props: string } (function bar() { class Foo {} })()`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `class A {} interface A {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unsafeMerging", Line: 1, Column: 22}, {MessageId: "unsafeMerging", Line: 1, Column: 7}},
		},
	})
}
