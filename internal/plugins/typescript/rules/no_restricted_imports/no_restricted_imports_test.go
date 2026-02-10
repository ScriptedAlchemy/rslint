package no_restricted_imports

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoRestrictedImportsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoRestrictedImportsRule, []rule_tester.ValidTestCase{
		{Code: "import foo from 'foo';"},
		{Code: "import foo from 'foo';", Options: []interface{}{"import1", "import2"}},
		{
			Code: "import type { Bar } from 'import-foo';",
			Options: []interface{}{
				map[string]interface{}{
					"paths": []interface{}{
						map[string]interface{}{
							"allowTypeImports": true,
							"importNames":      []interface{}{"Bar"},
							"message":          "Please use Bar from /import-bar/baz/ instead.",
							"name":             "import-foo",
						},
					},
				},
			},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:    "import foo from 'import1';",
			Options: []interface{}{"import1", "import2"},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "path", Line: 1},
			},
		},
		{
			Code: "import { Bar } from 'import-foo';",
			Options: []interface{}{
				map[string]interface{}{
					"paths": []interface{}{
						map[string]interface{}{
							"importNames": []interface{}{"Bar"},
							"message":     "Please use Bar from /import-bar/baz/ instead.",
							"name":        "import-foo",
						},
					},
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "importNameWithCustomMessage", Line: 1},
			},
		},
		{
			Code: "export { foo } from 'import1/private/foo';",
			Options: []interface{}{
				map[string]interface{}{
					"patterns": []interface{}{
						map[string]interface{}{
							"group":   []interface{}{"import1/private/*"},
							"message": "usage of import1 private modules not allowed.",
						},
					},
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "patternWithCustomMessage", Line: 1},
			},
		},
		{
			Code: "export * from 'import1';",
			Options: []interface{}{
				"import1",
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "path", Line: 1},
			},
		},
		{
			Code: "import { Bar, type Baz } from 'import-foo';",
			Options: []interface{}{
				map[string]interface{}{
					"paths": []interface{}{
						map[string]interface{}{
							"allowTypeImports": true,
							"importNames":      []interface{}{"Bar", "Baz"},
							"message":          "Please use Bar and Baz from /import-bar/baz/ instead.",
							"name":             "import-foo",
						},
					},
				},
			},
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "importNameWithCustomMessage", Line: 1},
				{MessageId: "importNameWithCustomMessage", Line: 1},
			},
		},
	})
}
