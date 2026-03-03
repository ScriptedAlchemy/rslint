package class_methods_use_this

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestClassMethodsUseThisRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &ClassMethodsUseThisRule, []rule_tester.ValidTestCase{
		{
			Code: `class A { method() { this; } }`,
		},
		{
			Code: `class A implements B { method() {} }`,
			Options: []interface{}{
				map[string]interface{}{
					"ignoreClassesThatImplementAnInterface": true,
				},
			},
		},
		{
			Code: `class A { override method() {} }`,
			Options: []interface{}{
				map[string]interface{}{
					"ignoreOverrideMethods": true,
				},
			},
		},
		{
			Code: `class A { field = () => {}; }`,
			Options: []interface{}{
				map[string]interface{}{
					"enforceForClassFields": false,
				},
			},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `class A { method() {} }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingThis"}},
		},
		{
			Code:   `class A { accessor field = () => {}; }`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingThis"}},
		},
		{
			Code: `class A implements B { private method() {} }`,
			Options: []interface{}{
				map[string]interface{}{
					"ignoreClassesThatImplementAnInterface": "public-fields",
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "missingThis"}},
		},
	})
}
