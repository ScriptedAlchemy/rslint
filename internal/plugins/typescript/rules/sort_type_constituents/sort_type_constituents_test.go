package sort_type_constituents

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestSortTypeConstituentsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &SortTypeConstituentsRule, []rule_tester.ValidTestCase{
		{Code: `type A = number | string;`},
		{Code: `type A = A & B & C;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `type A = string | number;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "notSorted", Line: 1, Column: 10}},
		},
		{
			Code:   `type A = C & A;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "notSorted", Line: 1, Column: 10}},
		},
	})
}
