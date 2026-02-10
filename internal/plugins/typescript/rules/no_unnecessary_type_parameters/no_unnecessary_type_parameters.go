package no_unnecessary_type_parameters

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

// TODO: replace scaffold with full parity implementation.
var NoUnnecessaryTypeParametersRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-parameters",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = ctx
		_ = options
		return rule.RuleListeners{}
	},
})
