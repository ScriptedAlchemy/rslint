package no_empty_object_type

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var NoEmptyObjectTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-empty-object-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
