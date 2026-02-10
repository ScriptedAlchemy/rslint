package parameter_properties

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestParameterPropertiesRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &ParameterPropertiesRule, []rule_tester.ValidTestCase{
		{
			Code: `
class Foo {
  constructor(readonly name: string) {}
}
			`,
			Options: []interface{}{map[string]interface{}{"allow": []interface{}{"readonly"}}},
		},
		{
			Code: `
class Foo {
  public age: number;
  constructor(age: string) {
    this.age = age;
  }
}
			`,
			Options: []interface{}{map[string]interface{}{"prefer": "parameter-property"}},
		},
		{
			Code: `
class Foo {
  public age: string;
  constructor(age: string) {
    console.log('unrelated');
    this.age = age;
  }
}
			`,
			Options: []interface{}{map[string]interface{}{"prefer": "parameter-property"}},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
class Foo {
  constructor(private name: string) {}
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferClassProperty", Line: 3},
			},
		},
		{
			Code: `
class Foo {
  member: string;

  constructor(member: string) {
    this.member = member;
  }
}
			`,
			Options: []interface{}{map[string]interface{}{"prefer": "parameter-property"}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferParameterProperty", Line: 3},
			},
		},
		{
			Code: `
class Foo {
  public member: string;
  constructor(member: string) {
    this.member = member;
  }
}
			`,
			Options: []interface{}{
				map[string]interface{}{
					"allow":  []interface{}{"protected", "private", "readonly"},
					"prefer": "parameter-property",
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferParameterProperty", Line: 3},
			},
		},
	})
}
