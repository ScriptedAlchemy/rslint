package prefer_regexp_exec

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestPreferRegExpExecRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &PreferRegExpExecRule, []rule_tester.ValidTestCase{
		{Code: `const value = "foo"; /foo/g.exec(value);`},
		{Code: `const value = "foo"; value.match(/foo/g);`},
		{Code: `const value = "foo"; value.match(pattern);`},
		{Code: `const value = "foo"; value.search(/foo/);`},
		{Code: `const value: { match(v: string): any } = { match: () => null as any }; value.match("foo");`},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `const value = "foo"; value.match(/foo/);`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "regExpExecOverStringMatch", Line: 1, Column: 28}},
		},
		{
			Code:   `const value = "foo"; value.match("foo");`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "regExpExecOverStringMatch", Line: 1, Column: 28}},
		},
		{
			Code: `
const value = "foo";
const reg: RegExp = /foo/;
value.match(reg);`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "regExpExecOverStringMatch", Line: 4, Column: 7}},
		},
	})
}
