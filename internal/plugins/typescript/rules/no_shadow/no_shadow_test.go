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
		{
			Code: `for (const a in [].find(a => true)) {
}`,
			Options: []interface{}{map[string]interface{}{"ignoreOnInitialization": true}},
		},
		{
			Code:    `const { a } = (({ a }) => ({ a }))();`,
			Options: []interface{}{map[string]interface{}{"ignoreOnInitialization": true}},
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
		{
			Code: `
import type { Foo } from 'bar';
declare module 'baz' {
  export interface Foo {
    x: string;
  }
}
`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "noShadow"}},
		},
		{
			Code: `
let x = foo((x, y) => {});
let y;
`,
			Options: []interface{}{map[string]interface{}{"hoist": "functions"}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noShadow"},
			},
		},
		{
			Code: `
const args = 1;
function foo<T extends (...args: any[]) => any>(fn: T, args: any[]) {}
`,
			Options: []interface{}{map[string]interface{}{"ignoreTypeValueShadow": false}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noShadow"},
			},
		},
	})
}
