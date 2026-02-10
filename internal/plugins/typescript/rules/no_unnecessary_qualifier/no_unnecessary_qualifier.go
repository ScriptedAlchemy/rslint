package no_unnecessary_qualifier

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var NoUnnecessaryQualifierRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-qualifier",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
