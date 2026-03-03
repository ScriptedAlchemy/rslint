package prefer_for_of

import (
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

func nodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(sourceFile, node)
	start := r.Pos()
	end := r.End()
	if start < 0 || end > len(sourceFile.Text()) || start >= end {
		return ""
	}
	return sourceFile.Text()[start:end]
}

func isAssignee(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if ast.IsAssignmentTarget(node) {
		return true
	}
	target := node
	for target.Parent != nil {
		switch target.Parent.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindNonNullExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression:
			target = target.Parent
		default:
			goto done
		}
	}
done:
	if ast.IsAssignmentTarget(target) {
		return true
	}
	return target.Parent != nil && target.Parent.Kind == ast.KindDeleteExpression && target.Parent.AsDeleteExpression().Expression == target
}

func isDeclarationIdentifier(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		decl := parent.AsVariableDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindParameter:
		decl := parent.AsParameterDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindFunctionDeclaration:
		decl := parent.AsFunctionDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindClassDeclaration:
		decl := parent.AsClassDeclaration()
		return decl != nil && decl.Name() == node
	}
	return false
}

func forDeclaresVariableName(node *ast.Node, name string) bool {
	if node == nil || node.Kind != ast.KindForStatement || name == "" {
		return false
	}
	loop := node.AsForStatement()
	if loop == nil || loop.Initializer == nil || loop.Initializer.Kind != ast.KindVariableDeclarationList {
		return false
	}
	declList := loop.Initializer.AsVariableDeclarationList()
	if declList == nil || declList.Declarations == nil {
		return false
	}
	for _, declNode := range declList.Declarations.Nodes {
		decl := declNode.AsVariableDeclaration()
		if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
			continue
		}
		if decl.Name().AsIdentifier().Text == name {
			return true
		}
	}
	return false
}

func isIndexOnlyUsedWithArray(sourceFile *ast.SourceFile, body *ast.Node, indexName string, arrayExpr *ast.Node) bool {
	if sourceFile == nil || body == nil || arrayExpr == nil {
		return false
	}
	arrayText := nodeText(sourceFile, arrayExpr)
	if arrayText == "" {
		return false
	}

	valid := true
	var visit func(current *ast.Node)
	visit = func(current *ast.Node) {
		if !valid || current == nil || current.Kind != ast.KindIdentifier || current.AsIdentifier().Text != indexName {
			if current != nil && !forDeclaresVariableName(current, indexName) {
				current.ForEachChild(func(child *ast.Node) bool {
					visit(child)
					return false
				})
			}
			return
		}
		if isDeclarationIdentifier(current) {
			return
		}

		parent := current.Parent
		if parent == nil || parent.Kind != ast.KindElementAccessExpression {
			valid = false
			return
		}
		element := parent.AsElementAccessExpression()
		if element == nil || element.ArgumentExpression != current || element.Expression == nil {
			valid = false
			return
		}
		if element.Expression.Kind == ast.KindThisKeyword {
			valid = false
			return
		}
		if isAssignee(parent) {
			valid = false
			return
		}
		if nodeText(sourceFile, element.Expression) != arrayText {
			valid = false
			return
		}
	}
	visit(body)

	return valid
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

				if !isIndexOnlyUsedWithArray(ctx.SourceFile, loop.Statement, indexName, arrayExpr) {
					return
				}

				ctx.ReportNode(node, buildPreferForOfMessage())
			},
		}
	},
})
