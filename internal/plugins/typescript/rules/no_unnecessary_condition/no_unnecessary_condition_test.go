package no_unnecessary_condition

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryConditionRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryConditionRule,
		[]rule_tester.ValidTestCase{
			// Valid cases - conditions that are necessary
			{Code: `
declare const x: string | null;
if (x) {
	console.log(x);
}`},
			{Code: `
declare const x: number | undefined;
while (x) {
	console.log(x);
}`},
			{Code: `
declare const x: boolean;
if (x) {
	console.log('true');
}`},
			{Code: `
function test<T>(a: T) {
	return a ?? 'default';
}`},
			{Code: `
function foo<T extends object>(arg: T, key: keyof T): void {
	arg[key] ?? 'default';
}`},
			{Code: `
declare const b1: boolean;
declare const b2: true;
const x = b1 && b2;
`},
			{Code: `
declare const x: string;
if (x) {
	console.log(x);
}`},
			// Valid with allowConstantLoopConditions
			{
				Code:    `while (true) { break; }`,
				Options: map[string]any{"allowConstantLoopConditions": true},
			},
		},
		[]rule_tester.InvalidTestCase{
			// Always truthy literal conditions
			{
				Code: `
const x = true;
if (x) {
	console.log(x);
}`,
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "alwaysTruthy",
					Line:      3,
					Column:    5,
				}},
			},
			{
				Code: `
const x = true;
const y = false;
if (x === y) {}
`,
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "comparisonBetweenLiteralTypes",
					Line:      4,
					Column:    5,
				}},
			},
			{
				Code: `
declare const b1: object | true;
if (b1) {}
`,
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "alwaysTruthy",
					Line:      3,
					Column:    5,
				}},
			},
			// Always falsy conditions
			{
				Code: `
declare const x: null;
if (x) {
	console.log(x);
}`,
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "alwaysFalsy",
					Line:      3,
					Column:    5,
				}},
			},
			// Never type
			{
				Code: `
declare const x: never;
if (x) {
	console.log(x);
}`,
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "never",
					Line:      3,
					Column:    5,
				}},
			},
			// Unnecessary nullish coalescing
			{
				Code: `
declare const x: string;
const y = x ?? 'default';`,
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "neverNullish",
					Line:      3,
					Column:    11,
				}},
			},
			{
				Code: `
[1, 3, 5].filter(() => true);
[1, 2, 3].find(() => {
	return false;
});
`,
				Errors: []rule_tester.InvalidTestCaseError{
					{
						MessageId: "alwaysTruthy",
						Line:      2,
						Column:    24,
					},
					{
						MessageId: "alwaysFalsy",
						Line:      4,
						Column:    9,
					},
				},
			},
			{
				Code: `
function truthy() {
	return [];
}
function falsy() {}
[1, 3, 5].filter(truthy);
[1, 2, 3].find(falsy);
[1, 2, 3].findLastIndex(falsy);
`,
				Errors: []rule_tester.InvalidTestCaseError{
					{
						MessageId: "alwaysTruthyFunc",
						Line:      6,
						Column:    18,
					},
					{
						MessageId: "alwaysFalsyFunc",
						Line:      7,
						Column:    16,
					},
					{
						MessageId: "alwaysFalsyFunc",
						Line:      8,
						Column:    25,
					},
				},
			},
		},
	)
}

func TestNoUnnecessaryConditionRuleWithStrictNullChecks(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryConditionRule,
		[]rule_tester.ValidTestCase{
			{
				Code:    `declare const x: any; if (x) { }`,
				Options: map[string]any{"allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing": true},
			},
		},
		[]rule_tester.InvalidTestCase{
			{
				Code:    `const x = null; if (x) { }`,
				Options: map[string]any{"allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing": true},
				Errors: []rule_tester.InvalidTestCaseError{{
					MessageId: "alwaysFalsy",
					Line:      1,
					Column:    21,
				}},
			},
		},
	)
}
