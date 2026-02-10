package no_invalid_this

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var NoInvalidThisRule = rule.CreateRule(rule.Rule{
	Name: "no-invalid-this",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
