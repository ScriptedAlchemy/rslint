package no_restricted_types

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoRestrictedTypesRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoRestrictedTypesRule, []rule_tester.ValidTestCase{
		{Code: "let f = Object();", Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"Object": true}}}},
		{Code: "let e: namespace.Object;", Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"Object": true}}}},
		{Code: "let value: _.NS.Banned;", Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"NS.Banned": true}}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:    "let value: number;",
			Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"number": "Use Ok instead."}}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedTypeMessage", Line: 1, Column: 12},
			},
		},
		{
			Code:    "let value: [];",
			Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"[]": "Use unknown[] instead."}}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedTypeMessage", Line: 1, Column: 12},
			},
		},
		{
			Code:    "let value: NS.Banned;",
			Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"NS.Banned": "Use NS.Ok instead."}}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedTypeMessage", Line: 1, Column: 12},
			},
		},
		{
			Code:    "class Derived implements Banned {}",
			Options: []interface{}{map[string]interface{}{"types": map[string]interface{}{"Banned": "Use Ok instead."}}},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "bannedTypeMessage", Line: 1, Column: 26},
			},
		},
	})
}
