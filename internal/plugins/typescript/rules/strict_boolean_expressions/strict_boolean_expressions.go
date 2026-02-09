package strict_boolean_expressions

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildConditionErrorOtherMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "conditionErrorOther",
		Description: "Unexpected value in conditional. A boolean expression is required.",
	}
}

func isBooleanLikeCondition(node *ast.Node) bool {
	if node == nil {
		return true
	}
	switch node.Kind {
	case ast.KindTrueKeyword, ast.KindFalseKeyword:
		return true
	case ast.KindPrefixUnaryExpression:
		unary := node.AsPrefixUnaryExpression()
		return unary != nil && unary.Operator == ast.KindExclamationToken
	case ast.KindBinaryExpression:
		binary := node.AsBinaryExpression()
		if binary == nil {
			return false
		}
		switch binary.OperatorToken.Kind {
		case ast.KindEqualsEqualsToken, ast.KindExclamationEqualsToken, ast.KindEqualsEqualsEqualsToken, ast.KindExclamationEqualsEqualsToken, ast.KindLessThanToken, ast.KindLessThanEqualsToken, ast.KindGreaterThanToken, ast.KindGreaterThanEqualsToken, ast.KindAmpersandAmpersandToken, ast.KindBarBarToken:
			return true
		}
	}
	return false
}

func checkCondition(ctx rule.RuleContext, cond *ast.Node) {
	if isBooleanLikeCondition(cond) {
		return
	}
	ctx.ReportNode(cond, buildConditionErrorOtherMessage())
}

var StrictBooleanExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "strict-boolean-expressions",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindIfStatement: func(node *ast.Node) {
				stmt := node.AsIfStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression)
			},
			ast.KindWhileStatement: func(node *ast.Node) {
				stmt := node.AsWhileStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression)
			},
			ast.KindDoStatement: func(node *ast.Node) {
				stmt := node.AsDoStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression)
			},
			ast.KindForStatement: func(node *ast.Node) {
				stmt := node.AsForStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Condition)
			},
		}
	},
})
