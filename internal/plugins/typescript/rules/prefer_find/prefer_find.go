package prefer_find

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var PreferFindRule = rule.CreateRule(rule.Rule{
	Name: "prefer-find",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
