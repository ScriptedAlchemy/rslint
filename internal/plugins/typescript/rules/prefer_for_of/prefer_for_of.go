package prefer_for_of

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildPreferForOfMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferForOf",
		Description: "Expected a `for-of` loop instead of a `for` loop with this simple iteration.",
	}
}

func nodeText(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return ctx.SourceFile.Text()[r.Pos():r.End()]
}

func unwrapExpression(expr *ast.Node) *ast.Node {
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

func isIdentifierWithName(node *ast.Node, name string) bool {
	return node != nil && node.Kind == ast.KindIdentifier && node.AsIdentifier().Text == name
}

func isNumericLiteralOne(node *ast.Node) bool {
	return node != nil && node.Kind == ast.KindNumericLiteral && node.AsNumericLiteral().Text == "1"
}

func isIncrementorForIndex(node *ast.Node, indexName string) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindPostfixUnaryExpression:
		expr := node.AsPostfixUnaryExpression()
		return expr != nil && expr.Operator == ast.KindPlusPlusToken && isIdentifierWithName(expr.Operand, indexName)
	case ast.KindPrefixUnaryExpression:
		expr := node.AsPrefixUnaryExpression()
		return expr != nil && expr.Operator == ast.KindPlusPlusToken && isIdentifierWithName(expr.Operand, indexName)
	case ast.KindBinaryExpression:
		expr := node.AsBinaryExpression()
		if expr == nil || !isIdentifierWithName(expr.Left, indexName) {
			return false
		}
		if expr.OperatorToken.Kind == ast.KindPlusEqualsToken {
			return isNumericLiteralOne(expr.Right)
		}
		if expr.OperatorToken.Kind != ast.KindEqualsToken {
			return false
		}
		if expr.Right == nil || expr.Right.Kind != ast.KindBinaryExpression {
			return false
		}
		right := expr.Right.AsBinaryExpression()
		if right == nil || right.OperatorToken.Kind != ast.KindPlusToken {
			return false
		}
		return (isIdentifierWithName(right.Left, indexName) && isNumericLiteralOne(right.Right)) ||
			(isNumericLiteralOne(right.Left) && isIdentifierWithName(right.Right, indexName))
	default:
		return false
	}
}

func isElementAccessWriteContext(node *ast.Node) bool {
	if node == nil {
		return false
	}
	current := node
	for current.Parent != nil {
		parent := current.Parent
		switch parent.Kind {
		case ast.KindParenthesizedExpression, ast.KindAsExpression, ast.KindTypeAssertionExpression, ast.KindNonNullExpression:
			current = parent
			continue
		case ast.KindPrefixUnaryExpression:
			unary := parent.AsPrefixUnaryExpression()
			return unary != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken || unary.Operator == ast.KindDeleteKeyword)
		case ast.KindPostfixUnaryExpression:
			unary := parent.AsPostfixUnaryExpression()
			return unary != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken)
		case ast.KindBinaryExpression:
			bin := parent.AsBinaryExpression()
			if bin == nil || !ast.IsAssignmentOperator(bin.OperatorToken.Kind) {
				return false
			}
			return current.Pos() >= bin.Left.Pos() && current.End() <= bin.Left.End()
		default:
			return false
		}
	}
	return false
}

func shouldSuggestForOf(ctx rule.RuleContext, forStmt *ast.ForStatement, indexName string, arrayExpr *ast.Node) bool {
	if forStmt == nil || forStmt.Statement == nil {
		return false
	}

	targetArrayText := nodeText(ctx, unwrapExpression(arrayExpr))
	if targetArrayText == "" {
		return false
	}

	disqualify := false
	var visit func(node *ast.Node)
	visit = func(node *ast.Node) {
		if node == nil || disqualify {
			return
		}
		switch node.Kind {
		// Ignore nested scopes for this loop analysis.
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindMethodDeclaration, ast.KindClassDeclaration, ast.KindClassExpression:
			return
		case ast.KindForStatement, ast.KindForInStatement, ast.KindForOfStatement:
			if node != forStmt.Statement {
				return
			}
		}

		if node.Kind == ast.KindIdentifier && node.AsIdentifier().Text == indexName {
			parent := node.Parent
			if parent != nil && parent.Kind == ast.KindElementAccessExpression {
				elem := parent.AsElementAccessExpression()
				if elem != nil && elem.ArgumentExpression != nil && elem.ArgumentExpression == node {
					baseText := nodeText(ctx, unwrapExpression(elem.Expression()))
					if baseText != targetArrayText {
						disqualify = true
						return
					}
					if isElementAccessWriteContext(parent) {
						disqualify = true
						return
					}
					// This is a plain read from the iterated array - acceptable.
					return
				}
			}
			disqualify = true
			return
		}

		node.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return false
		})
	}

	visit(forStmt.Statement)
	return !disqualify
}

var PreferForOfRule = rule.CreateRule(rule.Rule{
	Name: "prefer-for-of",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		return rule.RuleListeners{
			ast.KindForStatement: func(node *ast.Node) {
				forStmt := node.AsForStatement()
				if forStmt == nil || forStmt.Initializer == nil || forStmt.Condition == nil || forStmt.Incrementor == nil {
					return
				}
				if forStmt.Initializer.Kind != ast.KindVariableDeclarationList {
					return
				}
				declList := forStmt.Initializer.AsVariableDeclarationList()
				if declList == nil || declList.Declarations == nil || len(declList.Declarations.Nodes) != 1 {
					return
				}
				decl := declList.Declarations.Nodes[0].AsVariableDeclaration()
				if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier || decl.Initializer == nil {
					return
				}
				if decl.Initializer.Kind != ast.KindNumericLiteral || decl.Initializer.AsNumericLiteral().Text != "0" {
					return
				}
				indexName := decl.Name().AsIdentifier().Text

				if forStmt.Condition.Kind != ast.KindBinaryExpression {
					return
				}
				cond := forStmt.Condition.AsBinaryExpression()
				if cond == nil || cond.OperatorToken.Kind != ast.KindLessThanToken || !isIdentifierWithName(cond.Left, indexName) || cond.Right == nil {
					return
				}
				if cond.Right.Kind != ast.KindPropertyAccessExpression {
					return
				}
				lengthAccess := cond.Right.AsPropertyAccessExpression()
				if lengthAccess == nil || lengthAccess.Name() == nil || lengthAccess.Name().Kind != ast.KindIdentifier || lengthAccess.Name().AsIdentifier().Text != "length" {
					return
				}
				if strings.Contains(nodeText(ctx, cond.Right), "?.length") {
					return
				}
				arrayExpr := lengthAccess.Expression()
				if arrayExpr == nil {
					return
				}

				if !isIncrementorForIndex(forStmt.Incrementor, indexName) {
					return
				}
				if !shouldSuggestForOf(ctx, forStmt, indexName, arrayExpr) {
					return
				}

				ctx.ReportNode(node, buildPreferForOfMessage())
			},
		}
	},
})
