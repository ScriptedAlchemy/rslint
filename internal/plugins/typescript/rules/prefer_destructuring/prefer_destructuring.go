package prefer_destructuring

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var PreferDestructuringRule = rule.CreateRule(rule.Rule{
	Name: "prefer-destructuring",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
