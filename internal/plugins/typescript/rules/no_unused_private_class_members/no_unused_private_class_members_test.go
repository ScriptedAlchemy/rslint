package no_unused_private_class_members

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnusedPrivateClassMembersRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnusedPrivateClassMembersRule, []rule_tester.ValidTestCase{
		{
			Code: `
class A {
  #x = 1;
  test() {
    return this.#x;
  }
}
			`,
		},
		{
			Code: `
class A {
  #x = 1;
  nested = class {
    #x = 2;
  };
  test() {
    return this.#x;
  }
}
			`,
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
class A {
  #x = 1;
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedPrivateClassMember", Line: 3},
			},
		},
		{
			Code: `
class A {
  #x = 1;
  #y = 2;
  test() {
    return this.#x;
  }
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedPrivateClassMember", Line: 4},
			},
		},
	})
}
