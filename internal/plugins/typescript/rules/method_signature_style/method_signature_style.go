package method_signature_style

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type MethodSignatureStyle string

const (
	StyleProperty MethodSignatureStyle = "property"
	StyleMethod   MethodSignatureStyle = "method"
)

func parseStyle(options any) MethodSignatureStyle {
	style := StyleProperty
	if options == nil {
		return style
	}

	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok && (s == string(StyleProperty) || s == string(StyleMethod)) {
			return MethodSignatureStyle(s)
		}
	}

	if s, ok := options.(string); ok && (s == string(StyleProperty) || s == string(StyleMethod)) {
		return MethodSignatureStyle(s)
	}

	return style
}

func buildErrorMethodMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "errorMethod",
		Description: "Shorthand method signature is forbidden. Use a function property instead.",
	}
}

func buildErrorPropertyMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "errorProperty",
		Description: "Function property signature is forbidden. Use a method shorthand instead.",
	}
}

func isFunctionTypeLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionType:
		return true
	case ast.KindParenthesizedType:
		parenthesized := node.AsParenthesizedTypeNode()
		return parenthesized != nil && isFunctionTypeLike(parenthesized.Type)
	case ast.KindIntersectionType:
		intersection := node.AsIntersectionTypeNode()
		if intersection == nil || intersection.Types == nil || len(intersection.Types.Nodes) == 0 {
			return false
		}
		for _, t := range intersection.Types.Nodes {
			if !isFunctionTypeLike(t) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

var MethodSignatureStyleRule = rule.CreateRule(rule.Rule{
	Name: "method-signature-style",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		style := parseStyle(options)

		return rule.RuleListeners{
			ast.KindMethodSignature: func(node *ast.Node) {
				if style != StyleProperty {
					return
				}
				ctx.ReportNode(node, buildErrorMethodMessage())
			},
			ast.KindPropertySignature: func(node *ast.Node) {
				if style != StyleMethod {
					return
				}
				property := node.AsPropertySignatureDeclaration()
				if property == nil || property.Type == nil || !isFunctionTypeLike(property.Type) {
					return
				}
				ctx.ReportNode(node, buildErrorPropertyMessage())
			},
		}
	},
})
