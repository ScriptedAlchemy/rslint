package prefer_optional_chain

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildPreferOptionalChainMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferOptionalChain",
		Description: "Prefer using an optional chain expression instead, as it's more concise and easier to read.",
	}
}

func sameLeftIdentifier(left, right *ast.Node) bool {
	if left == nil || right == nil {
		return false
	}
	if left.Kind != ast.KindIdentifier {
		return false
	}
	if right.Kind == ast.KindPropertyAccessExpression {
		pa := right.AsPropertyAccessExpression()
		return pa != nil && pa.Expression != nil && pa.Expression.Kind == ast.KindIdentifier && pa.Expression.AsIdentifier().Text == left.AsIdentifier().Text
	}
	if right.Kind == ast.KindElementAccessExpression {
		ea := right.AsElementAccessExpression()
		return ea != nil && ea.Expression != nil && ea.Expression.Kind == ast.KindIdentifier && ea.Expression.AsIdentifier().Text == left.AsIdentifier().Text
	}
	return false
}

var PreferOptionalChainRule = rule.CreateRule(rule.Rule{
	Name: "prefer-optional-chain",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindBinaryExpression: func(node *ast.Node) {
				expr := node.AsBinaryExpression()
				if expr == nil || expr.OperatorToken.Kind != ast.KindAmpersandAmpersandToken {
					return
				}
				if sameLeftIdentifier(expr.Left, expr.Right) {
					ctx.ReportNode(node, buildPreferOptionalChainMessage())
				}
			},
		}
	},
})
