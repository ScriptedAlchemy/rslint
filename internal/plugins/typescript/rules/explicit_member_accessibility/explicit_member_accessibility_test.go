package explicit_member_accessibility

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestExplicitMemberAccessibilityRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &ExplicitMemberAccessibilityRule, []rule_tester.ValidTestCase{
		{Code: `class Test { public x: number; public getX() { return this.x; } }`},
		{Code: `class Test { x: number; getX() { return this.x; } }`, Options: []interface{}{map[string]interface{}{"accessibility": "no-public"}}},
		{Code: `class Test { constructor(public foo: number) {} }`, Options: []interface{}{map[string]interface{}{"accessibility": "no-public"}}},
		{Code: `class Test { constructor(readonly foo: number) {} }`, Options: []interface{}{map[string]interface{}{"overrides": map[string]interface{}{"constructors": "off", "parameterProperties": "off"}}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `class Test {
  x: number;
}`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "missingAccessibility", Line: 2, Column: 3, EndLine: 2, EndColumn: 4},
			},
		},
		{
			Code: `class Test {
  getX() { return 1; }
}`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "missingAccessibility", Line: 2, Column: 3, EndLine: 2, EndColumn: 7},
			},
		},
		{
			Code: `class Test {
  public x: number;
}`,
			Options: []interface{}{map[string]interface{}{"accessibility": "no-public"}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unwantedPublicAccessibility", Line: 2, Column: 3, EndLine: 2, EndColumn: 9},
			},
		},
		{
			Code: `class Test {
  constructor(readonly foo: number) {}
}`,
			Options: []interface{}{map[string]interface{}{"overrides": map[string]interface{}{"constructors": "off", "parameterProperties": "explicit"}}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "missingAccessibility", Line: 2, Column: 15, EndLine: 2, EndColumn: 27},
			},
		},
	})
}
