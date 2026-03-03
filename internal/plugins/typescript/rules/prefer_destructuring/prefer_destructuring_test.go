package prefer_destructuring

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferDestructuringRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferDestructuringRule, []rule_tester.ValidTestCase{
		{Code: `const { foo } = obj;`},
		{Code: `const foo = fn();`},
		{Code: `const foo: string = obj.foo;`},
		{
			Code:    `const y = obj.foo;`,
			Options: []interface{}{map[string]interface{}{"object": true}},
		},
		{
			Code: `
type Box = { 0: string };
declare const x: Box;
const y = x[0];
`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const foo = obj.foo;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferDestructuring", Line: 1, Column: 7}},
		},
		{
			Code: `
declare const xs: string[];
const first = xs[0];
`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferDestructuring", Line: 3, Column: 7}},
		},
		{
			Code:    `const foo: string = obj.foo;`,
			Options: []interface{}{map[string]interface{}{"object": true}, map[string]interface{}{"enforceForDeclarationWithTypeAnnotation": true}},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "preferDestructuring", Line: 1, Column: 7}},
		},
		{
			Code: `
type Box = { 0: string };
declare const x: Box;
const y = x[0];
`,
			Options: []interface{}{
				map[string]interface{}{"array": true, "object": true},
				map[string]interface{}{"enforceForRenamedProperties": true},
			},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferDestructuring", Line: 4, Column: 7}},
		},
	})
}
