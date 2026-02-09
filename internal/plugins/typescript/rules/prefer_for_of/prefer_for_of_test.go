package prefer_for_of

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferForOfRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferForOfRule, []rule_tester.ValidTestCase{
		{Code: `for (const value of arr) { console.log(value); }`},
		{Code: `for (let i = 1; i < arr.length; i++) { console.log(arr[i]); }`},
		{Code: `for (let i = 0; i <= arr.length; i++) { console.log(arr[i]); }`},
		{Code: `for (let i = 0; i < arr.length; i += 2) { console.log(arr[i]); }`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `for (let i = 0; i < arr.length; i++) { console.log(arr[i]); }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferForOf", Line: 1, Column: 1}},
		},
		{
			Code:   `for (let i = 0; i < arr.length; ++i) { console.log(arr[i]); }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferForOf", Line: 1, Column: 1}},
		},
		{
			Code:   `for (let i = 0; i < arr.length; i = i + 1) { console.log(arr[i]); }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferForOf", Line: 1, Column: 1}},
		},
	})
}
