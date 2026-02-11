package unified_signatures

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestUnifiedSignaturesRule(t *testing.T) {
	rule_tester.RunRuleTester(
		fixtures.GetRootDir(),
		"tsconfig.json",
		t,
		&UnifiedSignaturesRule,
		[]rule_tester.ValidTestCase{
			// Valid: Different parameter types that can't be unified
			{Code: `function f(x: number): void; function f(x: string, y: number): void;`},

			// Valid: Different return types
			{Code: `function f(x: number): number; function f(x: string): string;`},

			// Valid: Significantly different signatures
			{Code: `function f(): void; function f(a: number, b: number, c: number): void;`},

			// Valid: Constructor overloads with different parameters
			{Code: `class C { constructor(); constructor(x: number, y: string); }`},

			// Valid: Ignore overloads with different leading JSDoc block comments
			{
				Code: `/** @deprecated */
declare function f(x: number): unknown;
declare function f(x: boolean): unknown;`,
				Options: []interface{}{
					map[string]interface{}{
						"ignoreOverloadsWithDifferentJSDoc": true,
					},
				},
			},
		},
		[]rule_tester.InvalidTestCase{
			{
				Code: `function f(x: number): void;
function f(x: string): void;
function f(x: number | string): void {}`,
				Errors: []rule_tester.InvalidTestCaseError{
					{
						MessageId: "singleParameterDifference",
						Line:      2,
						Column:    12,
					},
				},
			},
		},
	)
}
