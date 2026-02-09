package no_unsafe_function_type

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildBannedFunctionTypeMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "bannedFunctionType",
		Description: "The `Function` type accepts any function-like value. Prefer explicitly defining any function parameters and return type.",
	}
}

func isFunctionIdentifier(node *ast.Node) bool {
	return node != nil && node.Kind == ast.KindIdentifier && node.AsIdentifier().Text == "Function"
}

var NoUnsafeFunctionTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-unsafe-function-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil {
					return
				}
				if isFunctionIdentifier(typeRef.TypeName) {
					ctx.ReportNode(node, buildBannedFunctionTypeMessage())
				}
			},
			ast.KindExpressionWithTypeArguments: func(node *ast.Node) {
				expr := node.AsExpressionWithTypeArguments()
				if expr == nil || expr.Expression == nil {
					return
				}
				if isFunctionIdentifier(expr.Expression) {
					ctx.ReportNode(node, buildBannedFunctionTypeMessage())
				}
			},
		}
	},
})
