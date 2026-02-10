package strict_boolean_expressions

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var StrictBooleanExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "strict-boolean-expressions",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
