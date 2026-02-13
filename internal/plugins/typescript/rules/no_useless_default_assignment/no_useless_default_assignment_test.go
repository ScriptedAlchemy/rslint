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
			Output: []string{`function basic(a: number) { return a; }`},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "uselessDefaultAssignment"}},
		},
		{
			Code:   `function optional(a: number | undefined = undefined) { return a; }`,
			Output: []string{`function optional(a?: number | undefined) { return a; }`},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferOptionalSyntax"}},
		},
		{
			Code:   `const { a = undefined }: { a?: number } = {};`,
			Output: []string{`const { a }: { a?: number } = {};`},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "uselessUndefined"}},
		},
		{
			Code:   `function withObject({ foo = "" }: { foo: string }) { return foo; }`,
			Output: []string{`function withObject({ foo }: { foo: string }) { return foo; }`},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "uselessDefaultAssignment"}},
		},
		{
			Code: `
interface B {
	foo: (b: boolean | string) => void;
}

const h: B = {
	foo: (b = false) => {},
};
			`,
			Output: []string{`
interface B {
	foo: (b: boolean | string) => void;
}

const h: B = {
	foo: (b) => {},
};
			`},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "uselessDefaultAssignment"}},
		},
		{
			Code:     `const value = 1;`,
			TSConfig: "tsconfig.unstrict.json",
			Errors:   []rule_tester.InvalidTestCaseError{{MessageId: "noStrictNullCheck"}},
		},
	})
}
