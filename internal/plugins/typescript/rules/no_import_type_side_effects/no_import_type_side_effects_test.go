package no_import_type_side_effects

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestNoImportTypeSideEffectsRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &NoImportTypeSideEffectsRule, []rule_tester.ValidTestCase{
		{Code: "import type { T } from 'mod';"},
		{Code: "import { type T, U } from 'mod';"},
		{Code: "import T, { type U } from 'mod';"},
		{Code: "import 'mod';"},
	}, []rule_tester.InvalidTestCase{
		{
			Code: "import { type A } from 'mod';",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "useTopLevelQualifier", Line: 1, Column: 1},
			},
		},
		{
			Code: "import { type A, type B } from 'mod';",
			Errors: []rule_tester.InvalidTestCaseError{
				{MessageId: "useTopLevelQualifier", Line: 1, Column: 1},
			},
		},
	})
}
