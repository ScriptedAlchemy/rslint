package prefer_regexp_exec

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var PreferRegexpExecRule = rule.CreateRule(rule.Rule{
	Name: "prefer-regexp-exec",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
