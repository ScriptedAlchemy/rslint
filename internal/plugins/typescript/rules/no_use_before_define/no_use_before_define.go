package no_use_before_define

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var NoUseBeforeDefineRule = rule.CreateRule(rule.Rule{
	Name: "no-use-before-define",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
