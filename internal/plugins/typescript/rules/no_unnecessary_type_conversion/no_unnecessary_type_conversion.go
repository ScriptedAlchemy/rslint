package no_unnecessary_type_conversion

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryTypeConversionMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryTypeConversion",
		Description: "This type conversion is unnecessary.",
	}
}

func unwrapParens(node *ast.Node) *ast.Node {
	current := node
	for current != nil && current.Kind == ast.KindParenthesizedExpression {
		paren := current.AsParenthesizedExpression()
		if paren == nil {
			break
		}
		current = paren.Expression
	}
	return current
}

func sameTypeAssertion(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindAsExpression {
		return false
	}
	asExpr := node.AsAsExpression()
	if asExpr == nil || asExpr.Expression == nil || asExpr.Type == nil {
		return false
	}
	inner := unwrapParens(asExpr.Expression)
	if inner.Kind != ast.KindAsExpression {
		return false
	}
	innerAs := inner.AsAsExpression()
	if innerAs == nil || innerAs.Type == nil {
		return false
	}
	if asExpr.Type.Kind != innerAs.Type.Kind {
		return false
	}
	if asExpr.Type.Kind == ast.KindTypeReference && innerAs.Type.Kind == ast.KindTypeReference {
		left := asExpr.Type.AsTypeReferenceNode()
		right := innerAs.Type.AsTypeReferenceNode()
		if left != nil && right != nil && left.TypeName != nil && right.TypeName != nil && left.TypeName.Kind == ast.KindIdentifier && right.TypeName.Kind == ast.KindIdentifier {
			return left.TypeName.AsIdentifier().Text == right.TypeName.AsIdentifier().Text
		}
	}
	return true
}

var NoUnnecessaryTypeConversionRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-conversion",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindAsExpression: func(node *ast.Node) {
				if sameTypeAssertion(node) {
					ctx.ReportNode(node, buildUnnecessaryTypeConversionMessage())
				}
			},
		}
	},
})
