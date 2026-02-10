package no_empty_object_type

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoEmptyObjectTypeRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoEmptyObjectTypeRule, []rule_tester.ValidTestCase{
		{Code: "interface Foo { value: string }"},
		{Code: "type Foo = { value: string };"},
		{Code: "interface Foo extends Bar {}", Options: []interface{}{map[string]interface{}{"allowInterfaces": "with-single-extends"}}},
		{Code: "type AllowedProps = {};", Options: []interface{}{map[string]interface{}{"allowWithName": "Props$"}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "interface Foo {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noEmptyInterface", Line: 1, Column: 11},
			},
		},
		{
			Code: "interface Foo extends Bar {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noEmptyInterfaceWithSuper", Line: 1, Column: 11},
			},
		},
		{
			Code: "type Foo = {};",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "noEmptyObject", Line: 1, Column: 12},
			},
		},
	})
}
