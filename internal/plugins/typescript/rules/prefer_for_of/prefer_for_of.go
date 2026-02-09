package prefer_for_of

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildPreferForOfMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferForOf",
		Description: "Expected a `for-of` loop instead of a `for` loop with this simple iteration.",
	}
}

func getLoopIndexName(initializer *ast.Node) string {
	if initializer == nil || initializer.Kind != ast.KindVariableDeclarationList {
		return ""
	}
	declList := initializer.AsVariableDeclarationList()
	if declList == nil || declList.Flags&ast.NodeFlagsConst != 0 || declList.Declarations == nil || len(declList.Declarations.Nodes) != 1 {
		return ""
	}
	decl := declList.Declarations.Nodes[0].AsVariableDeclaration()
	if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier || decl.Initializer == nil {
		return ""
	}
	if decl.Initializer.Kind != ast.KindNumericLiteral || decl.Initializer.AsNumericLiteral().Text != "0" {
		return ""
	}
	return decl.Name().AsIdentifier().Text
}

func getIteratedArrayExpression(test *ast.Node, indexName string) *ast.Node {
	if test == nil || test.Kind != ast.KindBinaryExpression {
		return nil
	}
	binary := test.AsBinaryExpression()
	if binary == nil || binary.OperatorToken.Kind != ast.KindLessThanToken {
		return nil
	}
	if binary.Left == nil || binary.Left.Kind != ast.KindIdentifier || binary.Left.AsIdentifier().Text != indexName {
		return nil
	}
	if binary.Right == nil || binary.Right.Kind != ast.KindPropertyAccessExpression {
		return nil
	}
	access := binary.Right.AsPropertyAccessExpression()
	if access == nil || access.Name() == nil || access.Name().Text() != "length" {
		return nil
	}
	return access.Expression
}

func isIncrement(node *ast.Node, indexName string) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindPostfixUnaryExpression:
		postfix := node.AsPostfixUnaryExpression()
		return postfix != nil && postfix.Operator == ast.KindPlusPlusToken && postfix.Operand != nil && postfix.Operand.Kind == ast.KindIdentifier && postfix.Operand.AsIdentifier().Text == indexName
	case ast.KindPrefixUnaryExpression:
		prefix := node.AsPrefixUnaryExpression()
		return prefix != nil && prefix.Operator == ast.KindPlusPlusToken && prefix.Operand != nil && prefix.Operand.Kind == ast.KindIdentifier && prefix.Operand.AsIdentifier().Text == indexName
	case ast.KindBinaryExpression:
		binary := node.AsBinaryExpression()
		if binary == nil || binary.Left == nil || binary.Left.Kind != ast.KindIdentifier || binary.Left.AsIdentifier().Text != indexName {
			return false
		}
		if binary.OperatorToken.Kind == ast.KindPlusEqualsToken {
			return binary.Right != nil && binary.Right.Kind == ast.KindNumericLiteral && binary.Right.AsNumericLiteral().Text == "1"
		}
		if binary.OperatorToken.Kind != ast.KindEqualsToken || binary.Right == nil || binary.Right.Kind != ast.KindBinaryExpression {
			return false
		}
		rhs := binary.Right.AsBinaryExpression()
		if rhs == nil || rhs.OperatorToken.Kind != ast.KindPlusToken {
			return false
		}
		leftIsIndex := rhs.Left != nil && rhs.Left.Kind == ast.KindIdentifier && rhs.Left.AsIdentifier().Text == indexName
		rightIsIndex := rhs.Right != nil && rhs.Right.Kind == ast.KindIdentifier && rhs.Right.AsIdentifier().Text == indexName
		leftIsOne := rhs.Left != nil && rhs.Left.Kind == ast.KindNumericLiteral && rhs.Left.AsNumericLiteral().Text == "1"
		rightIsOne := rhs.Right != nil && rhs.Right.Kind == ast.KindNumericLiteral && rhs.Right.AsNumericLiteral().Text == "1"
		return (leftIsIndex && rightIsOne) || (rightIsIndex && leftIsOne)
	}
	return false
}

var PreferForOfRule = rule.CreateRule(rule.Rule{
	Name: "prefer-for-of",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindForStatement: func(node *ast.Node) {
				loop := node.AsForStatement()
				if loop == nil {
					return
				}

				indexName := getLoopIndexName(loop.Initializer)
				if indexName == "" {
					return
				}

				arrayExpr := getIteratedArrayExpression(loop.Condition, indexName)
				if arrayExpr == nil {
					return
				}

				if !isIncrement(loop.Incrementor, indexName) {
					return
				}

				// Heuristic implementation: for now, report loops that match the canonical
				// numeric index progression pattern over `.length`.
				_ = arrayExpr
				ctx.ReportNode(node, buildPreferForOfMessage())
			},
		}
	},
})
