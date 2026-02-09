package no_unnecessary_type_conversion

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryTypeConversionRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryTypeConversionRule, []rule_tester.ValidTestCase{
		{Code: `const a = value as string;`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const a = (value as string) as string;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unnecessaryTypeConversion", Line: 1, Column: 11}},
		},
	})
}
