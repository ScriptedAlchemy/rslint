package strict_void_return

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/fixtures"
	"github.com/web-infra-dev/rslint/internal/rule_tester"
)

func TestStrictVoidReturnRule(t *testing.T) {
	rule_tester.RunRuleTester(fixtures.GetRootDir(), "tsconfig.json", t, &StrictVoidReturnRule, []rule_tester.ValidTestCase{
		{Code: `declare function takesVoid(cb: () => void): void; takesVoid(() => {});`},
		{Code: `declare function takesVoid(cb: () => void): void; takesVoid(function (): void { return; });`},
		{
			Code: `declare function takesVoid(cb: () => void): void;
const cb = () => (0 as any);
takesVoid(cb);`,
			Options: map[string]any{
				"allowReturnAny": true,
			},
		},
	}, []rule_tester.InvalidTestCase{
		{
			Code:   `declare function takesVoid(cb: () => void): void; takesVoid(() => 1);`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "nonVoidReturn"}},
		},
		{
			Code:   `declare function takesVoid(cb: () => void): void; takesVoid(async () => {});`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "asyncFunc"}},
		},
		{
			Code: `declare function takesVoid(cb: () => void): void;
const cb = () => 1;
takesVoid(cb);`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "nonVoidFunc"}},
		},
		{
			Code: `type VoidFn = () => void;
const cb: VoidFn = () => {
  return 1;
};`,
			Errors: []rule_tester.InvalidTestCaseError{{MessageId: "nonVoidReturn"}},
		},
	})
}
