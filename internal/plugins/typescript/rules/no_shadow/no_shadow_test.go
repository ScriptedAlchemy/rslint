package no_shadow

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoShadowRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoShadowRule, []rule_tester.ValidTestCase{
		{Code: `const a = 1; const b = () => a;`},
		{
			Code:    `function foo(cb) { (function (cb) { cb(42); })(cb); }`,
			Options: []interface{}{map[string]interface{}{"allow": []interface{}{"cb"}}},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const a = 1; function f() { const a = 2; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noShadow", Line: 1, Column: 35}},
		},
		{
			Code:   `{ let a; } function a() {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noShadow"}},
		},
	})
}
