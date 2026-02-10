package no_unnecessary_type_conversion

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoUnnecessaryTypeConversionRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnnecessaryTypeConversionRule, []rule_tester.ValidTestCase{
		{Code: "String(1);"},
		{Code: "+'2';"},
		{Code: "~~'2';"},
		{Code: "Boolean(0);"},
		{Code: "BigInt(3);"},
		{Code: "new String('asdf');"},
		{
			Code: `
function String(value: unknown) {
  return value;
}
String('asdf');
export {};
			`,
		},
		{Code: "String(new String());"},
		{Code: "new String().toString();"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "String('asdf');",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "'asdf'.toString();",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "'' + 'asdf';",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "'asdf' + '';",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "Number(123);",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "+123;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "~~123;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "!!true;",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: "BigInt(3n);",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: `
function f<T extends string>(x: T) {
  return String(x);
}
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
		{
			Code: `
let str = 'asdf';
str += '';
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unnecessaryTypeConversion"},
			},
		},
	})
}
