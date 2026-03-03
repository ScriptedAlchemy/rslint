package no_unused_vars

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestParseGlobalCommentRangesUnicodeColumns(t *testing.T) {
	ranges := parseGlobalCommentRanges("/*global 変数, 数*/\n変数;")
	r, ok := ranges["数"]
	if !ok {
		t.Fatalf("expected range for 数")
	}
	if r.Pos() != 17 {
		t.Fatalf("expected 数 start byte offset 17, got %d", r.Pos())
	}

	surrogateRanges := parseGlobalCommentRanges("/*global 𠮷𩸽, 𠮷*/\n𠮷𩸽;")
	surrogateRange, ok := surrogateRanges["𠮷"]
	if !ok {
		t.Fatalf("expected range for 𠮷")
	}
	if surrogateRange.Pos() != 19 {
		t.Fatalf("expected 𠮷 start byte offset 19, got %d", surrogateRange.Pos())
	}
}

func TestNoUnusedVarsRule(t *testing.T) {
	validTestCases := []rule_tester.ValidTestCase{
		{Code: `const foo = 5; console.log(foo);`},
		{Code: `function foo() {} foo();`},
		{Code: `function foo(bar) { console.log(bar); } foo(1);`},
		{Code: `try {} catch (e) { console.log(e); }`},
		{Code: `const { foo, ...rest } = { foo: 1, bar: 2 }; console.log(rest);`, Options: map[string]interface{}{"ignoreRestSiblings": true}},
		{Code: `const _foo = 1;`, Options: map[string]interface{}{"varsIgnorePattern": "^_"}},
		{Code: `function foo(bar) {} foo(1);`, Options: map[string]interface{}{"args": "none"}},
		{Code: `try {} catch (e) {}`, Options: map[string]interface{}{"caughtErrors": "none"}},
		{Code: `export const foo = 1;`},
		{Code: `import type { Foo } from "./foo"; const bar: Foo = {}; console.log(bar);`},
		{Code: `interface Base {} const a: Base = {}; console.log(a);`},
		{Code: `interface Foo { bar: string; } export const Foo = "bar";`},
		{Code: `enum FormFieldIds { PHONE = "phone", EMAIL = "email" } export interface IFoo { fieldName: FormFieldIds; }`},
		{Code: `namespace foo.bar { export interface User { name: string; } }`},
		{
			Code: `let _a, b; _a = 1; ({ _a, ...b } = foo); b;`,
			Options: map[string]interface{}{
				"destructuredArrayIgnorePattern": "^_",
				"ignoreRestSiblings":             true,
			},
		},
		{
			Code: `
let _x, y;
_x = 1;
[_x, y] = foo;
y;
let _a, b;
_a = 1;
({ _a, ...b } = foo);
b;
			`,
			Options: map[string]interface{}{
				"destructuredArrayIgnorePattern": "^_",
				"ignoreRestSiblings":             true,
			},
		},
		{
			Code: `
let _x, y;
_x = 1;
[_x, y] = foo;
y;
let _a, b;
_a = 1;
({ _a, ...b } = foo);
b;
			`,
			Options: []interface{}{
				map[string]interface{}{
					"destructuredArrayIgnorePattern": "^_",
					"ignoreRestSiblings":             true,
				},
			},
		},
		{
			Code: `
var _timer;
function f() {
  _timer = setTimeout(function () {}, _timer ? 100 : 0);
}
f();
			`,
		},
	}

	invalidTestCases := []rule_tester.InvalidTestCase{
		{
			Code:   `const foo = 5;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 7}},
		},
		{
			Code:   `function foo() {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 10}},
		},
		{
			Code: `function foo(bar) {}`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedVar", Line: 1, Column: 10},
				{MessageId: "unusedVar", Line: 1, Column: 14},
			},
		},
		{
			Code:   `try {} catch (e) {}`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 15}},
		},
		{
			Code:   `let foo = 5; foo = 10;`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 14}},
		},
		{
			Code:    `const foo = 1; type Bar = typeof foo;`,
			Options: map[string]interface{}{"vars": "all"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "usedOnlyAsType", Line: 1, Column: 7},
				{MessageId: "unusedVar", Line: 1, Column: 21},
			},
		},
		{
			Code:    `const foo = 1;`,
			Options: map[string]interface{}{"varsIgnorePattern": "^_"},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 7}},
		},
		{
			Code:    `const _foo = 1; console.log(_foo);`,
			Options: map[string]interface{}{"varsIgnorePattern": "^_", "reportUsedIgnorePattern": true},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "usedIgnoredVar", Line: 1, Column: 7}},
		},
		{
			Code:   `interface Foo { bar: string; baz: Foo["bar"]; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 11}},
		},
		{
			Code:   `namespace Foo { const Foo = 1; console.log(Foo); }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "unusedVar", Line: 1, Column: 11}},
		},
		{
			Code: `
let _a, b;
foo.forEach(item => {
  [a, b] = item;
});
			`,
			Options: map[string]interface{}{
				"destructuredArrayIgnorePattern": "^_",
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedVar", Line: 2, Column: 5},
				{MessageId: "unusedVar", Line: 2, Column: 9},
			},
		},
		{
			Code: `
(function (obj) {
  var name;
  for (name in obj) {
    i();
    return;
  }
})({});
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedVar", Line: 4, Column: 8},
			},
		},
		{
			Code: `
var a = 0;
a++;
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedVar", Line: 3, Column: 1},
			},
		},
		{
			Code: `
var a = 0;
a += a + 1;
			`,
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "unusedVar", Line: 3, Column: 1},
			},
		},
	}

	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoUnusedVarsRule, validTestCases, invalidTestCases)
}
