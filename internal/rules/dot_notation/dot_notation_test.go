package dot_notation

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/rule_tester"
	"github.com/web-infra-dev/rslint/internal/rules/fixtures"
)

func TestDotNotationRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &DotNotationRule, []rule_tester.ValidTestCase{
		// Valid cases
		{Code: "a.b;"},
		{Code: "a['12'];"},
		{Code: "a[b];"},
		{Code: "a[0];"},
	}, []rule_tester.InvalidTestCase{
		// Invalid cases
		{
			Code: "a['b'];",
			Errors: []rule_tester.InvalidTestCaseError{
				{
					MessageId: "useDot",
					Line:      1,
					Column:    2,
				},
			},
		},
		{
			Code: "a['test'];",
			Errors: []rule_tester.InvalidTestCaseError{
				{
					MessageId: "useDot",
					Line:      1,
					Column:    2,
				},
			},
		},
	})
}
