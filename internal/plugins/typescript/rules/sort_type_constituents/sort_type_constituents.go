package sort_type_constituents

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var SortTypeConstituentsRule = rule.CreateRule(rule.Rule{
	Name: "sort-type-constituents",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
