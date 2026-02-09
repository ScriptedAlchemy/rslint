package no_restricted_imports

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoRestrictedImportsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoRestrictedImportsRule, []rule_tester.ValidTestCase{
		{Code: `import foo from "foo";`},
		{Code: `import type foo from "foo";`, Options: []interface{}{map[string]interface{}{"paths": []interface{}{map[string]interface{}{"name": "foo", "allowTypeImports": true}}}}},
	}, []rule_tester.InvalidTestCase{
		{
			Code:    `import foo from "foo";`,
			Options: []interface{}{"foo"},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "path", Line: 1, Column: 17}},
		},
		{
			Code:    `import foo from "internal/private/module";`,
			Options: []interface{}{map[string]interface{}{"patterns": []interface{}{map[string]interface{}{"group": []interface{}{"internal/private/*"}}}}},
			Errors:  []rule_tester.InvalidTestCaseError{{MessageId: "patterns", Line: 1, Column: 17}},
		},
	})
}
