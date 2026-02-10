package method_signature_style

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestMethodSignatureStyleRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &MethodSignatureStyleRule, []rule_tester.ValidTestCase{
		{Code: "interface Test { f: (a: string) => number; }"},
		{Code: "type Test = { get f(): number };"},
		{Code: "interface Test { f(a: string): number; }", Options: []interface{}{"method"}},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "interface Test { f(a: string): number; }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "errorMethod", Line: 1, Column: 18},
			},
		},
		{
			Code:    "type Test = { f: (a: string) => number };",
			Options: []interface{}{"method"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "errorProperty", Line: 1, Column: 15},
			},
		},
	})
}
