package ban_tslint_comment

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestBanTslintCommentRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &BanTslintCommentRule, []rule_tester.ValidTestCase{
		{Code: "let a: readonly any[] = [];"},
		{Code: "let a = new Array();"},
		{Code: "// some other comment"},
		{Code: "// TODO: this is a comment that mentions tslint"},
		{Code: "/* another comment that mentions tslint */"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "/* tslint:disable */",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "commentDetected"},
			},
			Output: []string{""},
		},
		{
			Code: "/* tslint:enable */",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "commentDetected"},
			},
			Output: []string{""},
		},
		{
			Code: "/* tslint:disable:rule1 rule2 */",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "commentDetected"},
			},
			Output: []string{""},
		},
		{
			Code: "// tslint:disable-next-line",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "commentDetected"},
			},
			Output: []string{""},
		},
		{
			Code: "someCode(); // tslint:disable-line",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "commentDetected"},
			},
			Output: []string{"someCode();"},
		},
		{
			Code: `
const woah = doSomeStuff();
// tslint:disable-line
console.log(woah);
      `,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "commentDetected"},
			},
			Output: []string{`
const woah = doSomeStuff();
console.log(woah);
      `},
		},
	})
}
