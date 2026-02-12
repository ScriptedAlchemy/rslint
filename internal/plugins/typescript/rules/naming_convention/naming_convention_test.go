package naming_convention

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNamingConventionRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NamingConventionRule, []rule_tester.ValidTestCase{
		{Code: `class UserName {}; const userName = 1;`},
		{
			Code: `
        declare const ANY_UPPER_CASE: any;
        declare const ANY_UPPER_CASE: any | null;
        declare const ANY_UPPER_CASE: any | null | undefined;

        declare const string_camelCase: string;
        declare const string_camelCase: string | null;
        declare const string_camelCase: string | null | undefined;
        declare const string_camelCase: 'a' | null | undefined;
        declare const string_camelCase: string | 'a' | null | undefined;

        declare const number_camelCase: number;
        declare const number_camelCase: number | null;
        declare const number_camelCase: number | null | undefined;
        declare const number_camelCase: 1 | null | undefined;
        declare const number_camelCase: number | 2 | null | undefined;

        declare const boolean_camelCase: boolean;
        declare const boolean_camelCase: boolean | null;
        declare const boolean_camelCase: boolean | null | undefined;
        declare const boolean_camelCase: true | null | undefined;
        declare const boolean_camelCase: false | null | undefined;
        declare const boolean_camelCase: true | false | null | undefined;
      `,
			Options: []interface{}{
				map[string]interface{}{
					"format":    []interface{}{"UPPER_CASE"},
					"modifiers": []interface{}{"const"},
					"prefix":    []interface{}{"ANY_"},
					"selector":  "variable",
				},
				map[string]interface{}{
					"format":   []interface{}{"camelCase"},
					"prefix":   []interface{}{"string_"},
					"selector": "variable",
					"types":    []interface{}{"string"},
				},
				map[string]interface{}{
					"format":   []interface{}{"camelCase"},
					"prefix":   []interface{}{"number_"},
					"selector": "variable",
					"types":    []interface{}{"number"},
				},
				map[string]interface{}{
					"format":   []interface{}{"camelCase"},
					"prefix":   []interface{}{"boolean_"},
					"selector": "variable",
					"types":    []interface{}{"boolean"},
				},
			},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code: `class userName {}; const UserName = 1;`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "doesNotMatchFormat", Line: 1, Column: 7},
				{MessageId: "doesNotMatchFormat", Line: 1, Column: 26},
			},
		},
		{
			Code: `
        declare const function_camelCase1: () => void;
        declare const function_camelCase2: (() => void) | null;
        declare const function_camelCase3: (() => void) | null | undefined;
        declare const function_camelCase4:
          | (() => void)
          | (() => string)
          | null
          | undefined;
      `,
			Options: []interface{}{
				map[string]interface{}{
					"format":   []interface{}{"snake_case"},
					"prefix":   []interface{}{"function_"},
					"selector": "variable",
					"types":    []interface{}{"function"},
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "doesNotMatchFormatTrimmed"},
				{MessageId: "doesNotMatchFormatTrimmed"},
				{MessageId: "doesNotMatchFormatTrimmed"},
				{MessageId: "doesNotMatchFormatTrimmed"},
			},
		},
		{
			Code: `
        let unused_foo = 'a';
        const _unused_foo = 1;
        interface IFoo {}
        class IBar {}
        function fooBar() {}
      `,
			Options: []interface{}{
				map[string]interface{}{
					"custom": map[string]interface{}{
						"match": false,
						"regex": "^unused_\\w",
					},
					"format":            []interface{}{"snake_case"},
					"leadingUnderscore": "allow",
					"selector":          "default",
				},
				map[string]interface{}{
					"custom": map[string]interface{}{
						"match": false,
						"regex": "^I[A-Z]",
					},
					"format":   []interface{}{"strictCamelCase"},
					"selector": "typeLike",
				},
				map[string]interface{}{
					"custom": map[string]interface{}{
						"match": true,
						"regex": "function",
					},
					"format":            []interface{}{"camelCase"},
					"leadingUnderscore": "allow",
					"selector":          "function",
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "satisfyCustom"},
				{MessageId: "satisfyCustom"},
				{MessageId: "satisfyCustom"},
				{MessageId: "satisfyCustom"},
				{MessageId: "satisfyCustom"},
			},
		},
		{
			Code: `
        type Foo = {
          'foo     Bar': string;
          '': string;
          '0': string;
          'foo': string;
          'foo-bar': string;
          '#foo-bar': string;
        };

        interface Bar {
          'boo-----foo': string;
        }
      `,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "doesNotMatchFormat"},
				{MessageId: "doesNotMatchFormat"},
				{MessageId: "doesNotMatchFormat"},
				{MessageId: "doesNotMatchFormat"},
				{MessageId: "doesNotMatchFormat"},
				{MessageId: "doesNotMatchFormat"},
			},
		},
		{
			Code: `
        const syncbar1 = () => {};
        function syncBar2() {}
        const syncBar3 = function syncBar4() {};

        const AsyncBar1 = async () => {};
        const async_bar1 = async () => {};
        const async_bar3 = async function async_bar4() {};
        async function async_bar2() {}
        const asyncBar5 = async function async_bar6() {};
      `,
			Options: []interface{}{
				map[string]interface{}{
					"format":   []interface{}{"camelCase"},
					"selector": "default",
				},
				map[string]interface{}{
					"format":    []interface{}{"snake_case"},
					"modifiers": []interface{}{"async"},
					"selector":  []interface{}{"variable", "function"},
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "doesNotMatchFormat"},
				{MessageId: "doesNotMatchFormat"},
			},
		},
	})
}
