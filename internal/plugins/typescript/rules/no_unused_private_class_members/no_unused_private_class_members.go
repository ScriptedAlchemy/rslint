package no_unused_private_class_members

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var NoUnusedPrivateClassMembersRule = rule.CreateRule(rule.Rule{
	Name: "no-unused-private-class-members",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
