package no_unused_expressions

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type noUnusedExpressionsOptions struct {
	AllowShortCircuit bool
	AllowTernary      bool
}

func parseOptions(options any) noUnusedExpressionsOptions {
	opts := noUnusedExpressionsOptions{
		AllowShortCircuit: false,
		AllowTernary:      false,
	}
	if options == nil {
		return opts
	}

	var optsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			optsMap = first
		}
	} else if direct, ok := options.(map[string]interface{}); ok {
		optsMap = direct
	}
	if optsMap == nil {
		return opts
	}

	if v, ok := optsMap["allowShortCircuit"].(bool); ok {
		opts.AllowShortCircuit = v
	}
	if v, ok := optsMap["allowTernary"].(bool); ok {
		opts.AllowTernary = v
	}
	return opts
}

func unwrapTSExpression(expr *ast.Node) *ast.Node {
	for expr != nil {
		switch expr.Kind {
		case ast.KindParenthesizedExpression:
			expr = expr.AsParenthesizedExpression().Expression
		case ast.KindAsExpression:
			expr = expr.AsAsExpression().Expression
		case ast.KindTypeAssertionExpression:
			expr = expr.AsTypeAssertion().Expression
		case ast.KindNonNullExpression:
			expr = expr.AsNonNullExpression().Expression
		default:
			return expr
		}
	}
	return nil
}

func isWriteLikeUnary(expr *ast.Node) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case ast.KindPrefixUnaryExpression:
		unary := expr.AsPrefixUnaryExpression()
		return unary != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken || unary.Operator == ast.KindDeleteKeyword)
	case ast.KindPostfixUnaryExpression:
		unary := expr.AsPostfixUnaryExpression()
		return unary != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken)
	default:
		return false
	}
}

func isDirectivePrologueStatement(stmt *ast.Node) bool {
	if stmt == nil || stmt.Kind != ast.KindExpressionStatement {
		return false
	}
	exprStmt := stmt.AsExpressionStatement()
	if exprStmt == nil || exprStmt.Expression == nil || exprStmt.Expression.Kind != ast.KindStringLiteral {
		return false
	}

	parent := stmt.Parent
	if parent == nil {
		return false
	}
	stmts := parent.Statements()
	if stmts == nil {
		return false
	}
	for _, current := range stmts {
		if current == stmt {
			return true
		}
		if current.Kind != ast.KindExpressionStatement {
			return false
		}
		currentExpr := current.AsExpressionStatement()
		if currentExpr == nil || currentExpr.Expression == nil || currentExpr.Expression.Kind != ast.KindStringLiteral {
			return false
		}
	}
	return false
}

func isPurelyUnusedExpression(expr *ast.Node, opts noUnusedExpressionsOptions) bool {
	expr = unwrapTSExpression(ast.SkipParentheses(expr))
	if expr == nil {
		return false
	}

	switch expr.Kind {
	case ast.KindCallExpression, ast.KindNewExpression, ast.KindAwaitExpression, ast.KindYieldExpression, ast.KindTaggedTemplateExpression:
		return false
	case ast.KindConditionalExpression:
		if !opts.AllowTernary {
			return true
		}
		conditional := expr.AsConditionalExpression()
		if conditional == nil {
			return true
		}
		return isPurelyUnusedExpression(conditional.WhenTrue, opts) || isPurelyUnusedExpression(conditional.WhenFalse, opts)
	case ast.KindBinaryExpression:
		bin := expr.AsBinaryExpression()
		if bin == nil {
			return true
		}
		if ast.IsAssignmentOperator(bin.OperatorToken.Kind) {
			return false
		}
		if bin.OperatorToken.Kind == ast.KindAmpersandAmpersandToken || bin.OperatorToken.Kind == ast.KindBarBarToken || bin.OperatorToken.Kind == ast.KindQuestionQuestionToken {
			if !opts.AllowShortCircuit {
				return true
			}
			return isPurelyUnusedExpression(bin.Right, opts)
		}
		return true
	default:
		return !isWriteLikeUnary(expr)
	}
}

var NoUnusedExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "no-unused-expressions",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindExpressionStatement: func(node *ast.Node) {
				if isDirectivePrologueStatement(node) {
					return
				}
				exprStmt := node.AsExpressionStatement()
				if exprStmt == nil || exprStmt.Expression == nil {
					return
				}
				if !isPurelyUnusedExpression(exprStmt.Expression, opts) {
					return
				}
				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "unusedExpression",
					Description: "Expected an assignment or function call and instead saw an expression.",
				})
			},
		}
	},
})
