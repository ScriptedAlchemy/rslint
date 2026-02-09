package no_invalid_this

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnexpectedThisMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpectedThis",
		Description: "Unexpected 'this'.",
	}
}

func isAllowedThisContext(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindMethodDeclaration, ast.KindConstructor, ast.KindClassDeclaration, ast.KindClassExpression:
			return true
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction:
			// plain functions are not bound by default
			return false
		}
		current = current.Parent
	}
	return false
}

var NoInvalidThisRule = rule.CreateRule(rule.Rule{
	Name: "no-invalid-this",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindThisKeyword: func(node *ast.Node) {
				if isAllowedThisContext(node) {
					return
				}
				ctx.ReportNode(node, buildUnexpectedThisMessage())
			},
		}
	},
})
