package prefer_readonly_parameter_types

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferReadonlyParameterTypesDebugCases(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferReadonlyParameterTypesRule, []rule_tester.ValidTestCase{
		{Code: "function foo(arg: Readonly<[string]>) {}"},
		{Code: "function foo(arg: string | ReadonlyArray<string>) {}"},
		{
			Code: `
class Foo {
  readonly bang = 1;
}
interface Foo {
  readonly prop: string;
}
interface Foo {
  readonly prop2: string;
}
function foo(arg: Foo) {}
`,
		},
		{
			Code: `
interface Test extends ReadonlyArray<string> {
  readonly property: boolean;
}
function foo(arg: Readonly<Test>) {}
`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
function foo(arg: {
  readonly foo: {
    bar: string;
  };
}) {}
`,
			Errors: []rule_tester.InvalidTestCaseError{
				{
					MessageId: "shouldBeReadonly",
				},
			},
		},
		{
			Code: `
interface Foo {
  prop: Bar;
}
interface Bar {
  readonly prop: Foo;
}
function foo(arg: Readonly<Foo>) {}
`,
			Errors: []rule_tester.InvalidTestCaseError{
				{
					MessageId: "shouldBeReadonly",
				},
			},
		},
	})
}
