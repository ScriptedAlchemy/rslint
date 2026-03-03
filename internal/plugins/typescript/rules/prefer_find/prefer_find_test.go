package prefer_find

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferFindRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferFindRule, []rule_tester.ValidTestCase{
		{Code: `const x = [1,2,3].find(v => v > 1);`},
		{Code: `const x = [1,2,3].filter(v => v > 1)[1];`},
		{Code: `const x = [1,2,3].filter(v => v > 1).at(1);`},
		{Code: `const y = obj.filter(v => v > 1)[0];`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const x = [1,2,3].filter(v => v > 1)[0];`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferFind", Line: 1, Column: 11}},
		},
		{
			Code:   `const x = [1,2,3].filter(v => v > 1).at(0);`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferFind", Line: 1, Column: 11}},
		},
		{
			Code:   `const x = [1,2,3].filter(v => v > 1)['0'];`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "preferFind", Line: 1, Column: 11}},
		},
	})
}
