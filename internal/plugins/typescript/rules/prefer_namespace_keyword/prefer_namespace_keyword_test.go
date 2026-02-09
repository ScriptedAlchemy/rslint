package prefer_namespace_keyword

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferNamespaceKeywordRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferNamespaceKeywordRule, []rule_tester.ValidTestCase{
		{Code: "declare module 'foo';"},
		{Code: "declare module 'foo' {}"},
		{Code: "namespace foo {}"},
		{Code: "declare namespace foo {}"},
		{Code: "declare global {}"},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   "module foo {}",
			Output: []string{"namespace foo {}"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "useNamespace", Line: 1, Column: 1, EndLine: 1, EndColumn: 14},
			},
		},
		{
			Code:   "declare module foo {}",
			Output: []string{"declare namespace foo {}"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "useNamespace", Line: 1, Column: 1, EndLine: 1, EndColumn: 22},
			},
		},
		{
			Code: `
declare module foo {
  declare module bar {}
}
			`,
			Output: []string{
				`
declare namespace foo {
  declare namespace bar {}
}
			`,
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "useNamespace", Line: 2, Column: 1, EndLine: 4, EndColumn: 2},
				{MessageId: "useNamespace", Line: 3, Column: 3, EndLine: 3, EndColumn: 24},
			},
		},
	})
}
