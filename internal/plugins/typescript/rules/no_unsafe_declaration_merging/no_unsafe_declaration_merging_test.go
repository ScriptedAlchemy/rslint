package no_unsafe_declaration_merging

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnsafeDeclarationMergingRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnsafeDeclarationMergingRule, []rule_tester.ValidTestCase{
		{Code: "interface Foo {}\nclass Bar implements Foo {}"},
		{Code: "namespace Foo {}\nnamespace Foo {}"},
		{Code: "interface Foo {}\n(function(){ class Foo {} })();"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "interface Foo {}\nclass Foo {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unsafeMerging", Line: 1, Column: 11},
				{MessageId: "unsafeMerging", Line: 2, Column: 7},
			},
		},
		{
			Code: "declare global {\n  interface Foo {}\n  class Foo {}\n}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unsafeMerging", Line: 2, Column: 13},
				{MessageId: "unsafeMerging", Line: 3, Column: 9},
			},
		},
	})
}
