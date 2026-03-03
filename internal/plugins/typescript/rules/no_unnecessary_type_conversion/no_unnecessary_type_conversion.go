package no_unnecessary_type_conversion

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
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

func doesUnderlyingTypeMatchFlag(t *checker.Type, flag checker.TypeFlags) bool {
	if t == nil {
		return false
	}
	typeParts := utils.UnionTypeParts(t)
	if len(typeParts) == 0 {
		return false
	}
	for _, part := range typeParts {
		if !utils.IsTypeFlagSet(part, flag) {
			return false
		}
	}
	return true
}

func isStringType(ctx rule.RuleContext, node *ast.Node) bool {
	return doesUnderlyingTypeMatchFlag(utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node), checker.TypeFlagsStringLike)
}

func isNumberType(ctx rule.RuleContext, node *ast.Node) bool {
	return doesUnderlyingTypeMatchFlag(utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node), checker.TypeFlagsNumberLike)
}

func isBooleanType(ctx rule.RuleContext, node *ast.Node) bool {
	return doesUnderlyingTypeMatchFlag(utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node), checker.TypeFlagsBooleanLike)
}

func isBigintType(ctx rule.RuleContext, node *ast.Node) bool {
	return doesUnderlyingTypeMatchFlag(utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node), checker.TypeFlagsBigIntLike)
}

func isIdentifierShadowedInFile(ctx rule.RuleContext, identifier *ast.Node) bool {
	if ctx.TypeChecker == nil || identifier == nil || identifier.Kind != ast.KindIdentifier || ctx.SourceFile == nil {
		return false
	}
	symbol := ctx.TypeChecker.GetSymbolAtLocation(identifier)
	if symbol == nil {
		return false
	}

	if symbol.ValueDeclaration != nil && ast.GetSourceFileOfNode(symbol.ValueDeclaration) == ctx.SourceFile {
		return true
	}
	for _, decl := range symbol.Declarations {
		if decl != nil && ast.GetSourceFileOfNode(decl) == ctx.SourceFile {
			return true
		}
	}
	return false
}

func isEmptyStringLiteral(node *ast.Node) bool {
	return node != nil && node.Kind == ast.KindStringLiteral && node.AsStringLiteral().Text == ""
}

var NoUnnecessaryTypeConversionRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-conversion",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		if ctx.TypeChecker == nil {
			return rule.RuleListeners{}
		}

		return rule.RuleListeners{
			ast.KindAsExpression: func(node *ast.Node) {
				if sameTypeAssertion(node) {
					ctx.ReportNode(node, buildUnnecessaryTypeConversionMessage())
				}
			},
			ast.KindCallExpression: func(node *ast.Node) {
				call := node.AsCallExpression()
				if call == nil || call.Expression == nil {
					return
				}

				if call.Expression.Kind == ast.KindIdentifier {
					callee := call.Expression.AsIdentifier()
					if callee == nil {
						return
					}
					if isIdentifierShadowedInFile(ctx, call.Expression) {
						return
					}
					if len(call.Arguments.Nodes) == 0 {
						return
					}
					arg := call.Arguments.Nodes[0]
					switch callee.Text {
					case "String":
						if isStringType(ctx, arg) {
							ctx.ReportNode(call.Expression, buildUnnecessaryTypeConversionMessage())
						}
					case "Number":
						if isNumberType(ctx, arg) {
							ctx.ReportNode(call.Expression, buildUnnecessaryTypeConversionMessage())
						}
					case "Boolean":
						if isBooleanType(ctx, arg) {
							ctx.ReportNode(call.Expression, buildUnnecessaryTypeConversionMessage())
						}
					case "BigInt":
						if isBigintType(ctx, arg) {
							ctx.ReportNode(call.Expression, buildUnnecessaryTypeConversionMessage())
						}
					}
					return
				}

				if call.Expression.Kind == ast.KindPropertyAccessExpression {
					access := call.Expression.AsPropertyAccessExpression()
					if access == nil || access.Name() == nil || access.Name().Text() != "toString" || access.Expression == nil {
						return
					}
					if len(call.Arguments.Nodes) != 0 {
						return
					}
					if isStringType(ctx, access.Expression) {
						ctx.ReportRange(
							core.NewTextRange(access.Name().Pos(), node.End()),
							buildUnnecessaryTypeConversionMessage(),
						)
					}
				}
			},
			ast.KindBinaryExpression: func(node *ast.Node) {
				expr := node.AsBinaryExpression()
				if expr == nil || expr.Left == nil || expr.Right == nil {
					return
				}

				if expr.OperatorToken.Kind == ast.KindPlusToken {
					if isEmptyStringLiteral(expr.Left) && isStringType(ctx, expr.Right) {
						exprRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
						rightRange := utils.TrimNodeTextRange(ctx.SourceFile, expr.Right)
						ctx.ReportRange(
							core.NewTextRange(exprRange.Pos(), rightRange.Pos()),
							buildUnnecessaryTypeConversionMessage(),
						)
						return
					}
					if isEmptyStringLiteral(expr.Right) && isStringType(ctx, expr.Left) {
						ctx.ReportRange(
							core.NewTextRange(expr.Left.End(), node.End()),
							buildUnnecessaryTypeConversionMessage(),
						)
						return
					}
				}

				if expr.OperatorToken.Kind == ast.KindPlusEqualsToken &&
					isEmptyStringLiteral(expr.Right) &&
					isStringType(ctx, expr.Left) {
					ctx.ReportNode(node, buildUnnecessaryTypeConversionMessage())
				}
			},
			ast.KindPrefixUnaryExpression: func(node *ast.Node) {
				expr := node.AsPrefixUnaryExpression()
				if expr == nil || expr.Operand == nil {
					return
				}

				switch expr.Operator {
				case ast.KindPlusToken:
					if isNumberType(ctx, expr.Operand) {
						exprRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
						ctx.ReportRange(
							core.NewTextRange(exprRange.Pos(), exprRange.Pos()+1),
							buildUnnecessaryTypeConversionMessage(),
						)
					}
				case ast.KindExclamationToken:
					if node.Parent == nil || node.Parent.Kind != ast.KindPrefixUnaryExpression {
						return
					}
					parent := node.Parent.AsPrefixUnaryExpression()
					if parent == nil || parent.Operator != ast.KindExclamationToken || parent.Operand != node {
						return
					}
					if isBooleanType(ctx, expr.Operand) {
						parentRange := utils.TrimNodeTextRange(ctx.SourceFile, node.Parent)
						exprRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
						ctx.ReportRange(
							core.NewTextRange(parentRange.Pos(), exprRange.Pos()+1),
							buildUnnecessaryTypeConversionMessage(),
						)
					}
				case ast.KindTildeToken:
					if node.Parent == nil || node.Parent.Kind != ast.KindPrefixUnaryExpression {
						return
					}
					parent := node.Parent.AsPrefixUnaryExpression()
					if parent == nil || parent.Operator != ast.KindTildeToken || parent.Operand != node {
						return
					}
					if isNumberType(ctx, expr.Operand) {
						parentRange := utils.TrimNodeTextRange(ctx.SourceFile, node.Parent)
						exprRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
						ctx.ReportRange(
							core.NewTextRange(parentRange.Pos(), exprRange.Pos()+1),
							buildUnnecessaryTypeConversionMessage(),
						)
					}
				}
			},
		}
	},
})
