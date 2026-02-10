package no_restricted_imports

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var NoRestrictedImportsRule = rule.CreateRule(rule.Rule{
	Name: "no-restricted-imports",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
