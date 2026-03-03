package no_unused_expressions

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnusedExpressionsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnusedExpressionsRule, []rule_tester.ValidTestCase{
		{Code: `import("./foo");`},
		{Code: `new Foo<string>();`},
		{Code: `foo();`},
		{Code: `test.age?.toLocaleString();`},
		{Code: `foo && foo?.();`, Options: map[string]interface{}{"allowShortCircuit": true}},
		{Code: `foo ? import("./foo") : import("./bar");`, Options: map[string]interface{}{"allowTernary": true}},
		{Code: `
function foo() {
  "use strict";
  return 1;
}`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `a?.b;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 1, Column: 1}},
		},
		{
			Code:   `Map<string, string>;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 1, Column: 1}},
		},
		{
			Code:   `foo!;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 1, Column: 1}},
		},
		{
			Code:   `foo as any;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 1, Column: 1}},
		},
		{
			Code:   `if (0) 0;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 1, Column: 8}},
		},
		{
			Code:    `foo && foo?.bar;`,
			Options: map[string]interface{}{"allowShortCircuit": true},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 1, Column: 1}},
		},
		{
			Code: `
module Foo {
  const foo = true;
  "use strict";
}
`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedExpression", Line: 4, Column: 3}},
		},
	})
}
