package prefer_for_of

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferForOfRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferForOfRule, []rule_tester.ValidTestCase{
		{Code: "for (let i = 0; i < arr.length; i++) { arr[i] = 0; }"},
		{Code: "for (let i = 0; i < arr.length; i++) { doMath(i); }"},
		{Code: "for (let i = 0; i < arr1.length; i++) { const x = arr1[i] === arr2[i]; }"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "for (let i = 0; i < arr.length; i++) { console.log(arr[i]); }",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferForOf", Line: 1, Column: 1},
			},
		},
		{
			Code: "for (let x = 0; x < arr.length; x++) {}",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "preferForOf", Line: 1, Column: 1},
			},
		},
	})
}
