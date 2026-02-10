package prefer_regexp_exec

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferRegexpExecRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferRegexpExecRule, []rule_tester.ValidTestCase{
		{Code: "'something'.match(/thing/g);"},
		{Code: "const a = { match: (s: RegExp) => 'x' }; a.match(/thing/);"},
		{Code: "function f(s: string | string[]) { s.match(/e/); }"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "'something'.match(/thing/);",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "regExpExecOverStringMatch", Line: 1, Column: 13},
			},
		},
		{
			Code: "const text = 'something';\nconst search = /thing/;\ntext.match(search);",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "regExpExecOverStringMatch", Line: 3, Column: 6},
			},
		},
		{
			Code: "const text = 'something';\nconst search = 'thing';\ntext.match(search);",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "regExpExecOverStringMatch", Line: 3, Column: 6},
			},
		},
	})
}
