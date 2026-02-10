package method_signature_style

import "github.com/web-infra-dev/rslint/internal/rule"

// TODO: replace scaffold with full parity implementation.
var MethodSignatureStyleRule = rule.CreateRule(rule.Rule{
	Name: "method-signature-style",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
