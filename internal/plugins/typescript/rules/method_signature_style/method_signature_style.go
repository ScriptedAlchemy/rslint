package method_signature_style

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type methodSignatureStyle string

const (
	styleProperty methodSignatureStyle = "property"
	styleMethod   methodSignatureStyle = "method"
)

func parseStyleOption(options any) methodSignatureStyle {
	if options == nil {
		return styleProperty
	}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok && s == string(styleMethod) {
			return styleMethod
		}
	}
	if s, ok := options.(string); ok && s == string(styleMethod) {
		return styleMethod
	}
	return styleProperty
}

func unwrapTypeNode(node *ast.Node) *ast.Node {
	for node != nil && node.Kind == ast.KindParenthesizedType {
		node = node.AsParenthesizedTypeNode().Type
	}
	return node
}

func isFunctionTypePropertySignature(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindPropertySignature {
		return false
	}
	property := node.AsPropertySignature()
	if property == nil || property.Type == nil {
		return false
	}
	t := unwrapTypeNode(property.Type)
	return t != nil && t.Kind == ast.KindFunctionType
}

var MethodSignatureStyleRule = rule.CreateRule(rule.Rule{
	Name: "method-signature-style",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		style := parseStyleOption(options)

		return rule.RuleListeners{
			ast.KindMethodSignature: func(node *ast.Node) {
				if style != styleProperty {
					return
				}
				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "errorMethod",
					Description: "Shorthand method signature is forbidden. Use a function property instead.",
				})
			},
			ast.KindPropertySignature: func(node *ast.Node) {
				if style != styleMethod {
					return
				}
				if !isFunctionTypePropertySignature(node) {
					return
				}
				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "errorProperty",
					Description: "Function property signature is forbidden. Use a method signature instead.",
				})
			},
		}
	},
})
