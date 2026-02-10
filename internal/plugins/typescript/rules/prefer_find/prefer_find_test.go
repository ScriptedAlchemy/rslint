package prefer_find

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferFindRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferFindRule, []rule_tester.ValidTestCase{
		{Code: "declare const arr: readonly string[]; arr.filter(item => item === 'aha')[1];"},
		{Code: "declare const arr: string[]; arr.filter(item => item === 'aha').at(1);"},
		{Code: "declare const notNecessarilyAnArray: unknown[] | undefined | null | string; notNecessarilyAnArray?.filter(item => true)[0];"},
		{Code: "[].filter(() => true)?.[0];"},
		{Code: "[].filter?.(() => true)[0];"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `
declare const arr: string[];
arr.filter(item => item === 'aha')[0];
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferFind", Line: 3},
			},
		},
		{
			Code: `
declare const arr: readonly string[];
arr.filter(item => item === 'aha').at(0);
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferFind", Line: 3},
			},
		},
		{
			Code: `
const idxToLookUp = -0.12635678;
[1, 2, 3].filter(x => x > 0).at(idxToLookUp);
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferFind", Line: 3},
			},
		},
		{
			Code: `
declare const nullableArray: unknown[] | undefined | null;
nullableArray?.filter(item => true)[0];
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferFind", Line: 3},
			},
		},
	})
}
