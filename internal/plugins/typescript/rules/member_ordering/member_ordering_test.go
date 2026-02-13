package member_ordering

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestMemberOrderingRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &MemberOrderingRule, []rule_tester.ValidTestCase{
		{
			Code: `
interface Foo {
  a: string;
  b: string;
}
`,
			Options: map[string]interface{}{
				"default": map[string]interface{}{
					"memberTypes": "never",
					"order":       "alphabetically",
				},
			},
		},
		{
			Code: `
interface Foo {
  a?: string;
  b?: string;
  c: string;
}
`,
			Options: map[string]interface{}{
				"default": map[string]interface{}{
					"memberTypes":      "never",
					"order":            "as-written",
					"optionalityOrder": "optional-first",
				},
			},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
interface Foo {
  b: string;
  a: string;
}
`,
			Options: map[string]interface{}{
				"default": map[string]interface{}{
					"memberTypes": "never",
					"order":       "alphabetically",
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "incorrectOrder", Line: 4, Column: 3},
			},
		},
		{
			Code: `
interface Foo {
  a?: string;
  b: string;
}
`,
			Options: map[string]interface{}{
				"default": map[string]interface{}{
					"memberTypes":      "never",
					"order":            "as-written",
					"optionalityOrder": "required-first",
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "incorrectRequiredMembersOrder", Line: 3, Column: 3},
			},
		},
		{
			Code: `
interface Foo {
  [k: string]: string;
  a: string;
}
`,
			Options: map[string]interface{}{
				"default": map[string]interface{}{
					"memberTypes": []interface{}{"field", "signature"},
					"order":       "as-written",
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "incorrectGroupOrder", Line: 4, Column: 3},
			},
		},
	})
}
