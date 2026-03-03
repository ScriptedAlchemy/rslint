package no_loss_of_precision

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoLossOfPrecisionRule(t *testing.T) {
	rule_tester.RunRuleTester(
		fixtures.GetRootDir(),
		"tsconfig.json",
		t,
		&NoLossOfPrecisionRule,
		[]rule_tester.ValidTestCase{
			{Code: `const value = 9007199254740991;`},
			{Code: `const value = 0x1FFFFFFFFFFFFF;`},
		},
		[]rule_tester.InvalidTestCase{
			{
				Code:   `const value = 9007199254740993;`,
				Errors: []rule_tester.InvalidTestCaseError{{MessageId: "no-loss-of-precision"}},
			},
			{
				Code:   `const value = 0x20000000000001;`,
				Errors: []rule_tester.InvalidTestCaseError{{MessageId: "no-loss-of-precision"}},
			},
		},
	)
}
