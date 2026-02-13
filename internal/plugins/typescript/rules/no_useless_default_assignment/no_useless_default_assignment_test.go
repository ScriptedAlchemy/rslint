package no_useless_default_assignment

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUselessDefaultAssignmentRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUselessDefaultAssignmentRule, []rule_tester.ValidTestCase{
		{Code: `function withOptional(a: number | undefined = 1) { return a; }`},
		{Code: `const { a = 1 }: { a?: number } = {};`},
		{
			Code:     `const value = 1;`,
			TSConfig: "tsconfig.unstrict.json",
			Options: map[string]any{
				"allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing": true,
			},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `function basic(a: number = 1) { return a; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "uselessDefaultAssignment"}},
		},
		{
			Code:   `function optional(a: number | undefined = undefined) { return a; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferOptionalSyntax"}},
		},
		{
			Code:   `const { a = undefined }: { a?: number } = {};`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "uselessUndefined"}},
		},
		{
			Code:     `const value = 1;`,
			TSConfig: "tsconfig.unstrict.json",
			Errors:   []rule_tester.InvalidTestCaseError{{MessageId: "noStrictNullCheck"}},
		},
	})
}
