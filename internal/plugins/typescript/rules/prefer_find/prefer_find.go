package prefer_find

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildPreferFindMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferFind",
		Description: "Prefer .find(...) instead of .filter(...)[0].",
	}
}

func isZeroNode(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindNumericLiteral:
		n := node.AsNumericLiteral()
		return n != nil && n.Text == "0"
	case ast.KindStringLiteral:
		s := node.AsStringLiteral()
		return s != nil && s.Text == "0"
	default:
		return false
	}
}

func getFilterReceiver(call *ast.CallExpression) *ast.Node {
	if call == nil || call.Expression == nil {
		return nil
	}
	if call.Expression.Kind != ast.KindPropertyAccessExpression {
		return nil
	}
	access := call.Expression.AsPropertyAccessExpression()
	if access == nil || access.Name() == nil || access.Name().Text() != "filter" {
		return nil
	}
	return access.Expression
}

func isArrayLike(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}
	t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
	return utils.TypeRecurser(t, func(t *checker.Type) bool {
		return checker.Checker_isArrayOrTupleType(ctx.TypeChecker, t)
	})
}

func isFilterCallOnArray(ctx rule.RuleContext, node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindCallExpression {
		return false
	}
	call := node.AsCallExpression()
	receiver := getFilterReceiver(call)
	return receiver != nil && isArrayLike(ctx, receiver)
}

var PreferFindRule = rule.CreateRule(rule.Rule{
	Name: "prefer-find",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			// arr.filter(fn)[0]
			ast.KindElementAccessExpression: func(node *ast.Node) {
				element := node.AsElementAccessExpression()
				if element == nil || element.ArgumentExpression == nil || !isZeroNode(element.ArgumentExpression) {
					return
				}
				if !isFilterCallOnArray(ctx, element.Expression) {
					return
				}
				ctx.ReportNode(node, buildPreferFindMessage())
			},

			// arr.filter(fn).at(0)
			ast.KindCallExpression: func(node *ast.Node) {
				call := node.AsCallExpression()
				if call == nil || call.Expression == nil || call.Arguments == nil || len(call.Arguments.Nodes) != 1 {
					return
				}
				if !isZeroNode(call.Arguments.Nodes[0]) {
					return
				}
				if call.Expression.Kind != ast.KindPropertyAccessExpression {
					return
				}
				access := call.Expression.AsPropertyAccessExpression()
				if access == nil || access.Name() == nil || access.Name().Text() != "at" {
					return
				}
				if !isFilterCallOnArray(ctx, access.Expression) {
					return
				}
				ctx.ReportNode(node, buildPreferFindMessage())
			},
		}
	},
})
