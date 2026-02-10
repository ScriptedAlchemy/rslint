package no_unnecessary_qualifier

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryQualifierRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryQualifierRule, []rule_tester.ValidTestCase{
		{
			Code: `
namespace X {
  export type T = number;
}

namespace Y {
  export const x: X.T = 3;
}
			`,
		},
		{
			Code: `
namespace X {
  export type T = number;
  namespace Y {
    type T = string;
    const x: X.T = 0;
  }
}
			`,
		},
		{
			Code: `
namespace Foo {
  export function bar() {
    return Foo.One;
  }
}
			`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
namespace A {
  export type B = number;
  const x: A.B = 3;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryQualifier"},
			},
		},
		{
			Code: `
namespace A {
  export const x = 3;
  export const y = A.x;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryQualifier"},
			},
		},
		{
			Code: `
enum A {
  B,
  C = A.B,
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryQualifier"},
			},
		},
		{
			Code: `
import * as Foo from './foo';
declare module './foo' {
  const x: Foo.T = 3;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryQualifier"},
			},
		},
	})
}
