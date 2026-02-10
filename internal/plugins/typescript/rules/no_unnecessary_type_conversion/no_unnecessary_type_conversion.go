package no_unnecessary_type_conversion

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type primitiveKind string

const (
	primitiveString  primitiveKind = "string"
	primitiveNumber  primitiveKind = "number"
	primitiveBoolean primitiveKind = "boolean"
	primitiveBigInt  primitiveKind = "bigint"
)

func buildUnnecessaryTypeConversionMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryTypeConversion",
		Description: "This type conversion is unnecessary.",
	}
}

func isEmptyStringLiteral(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindStringLiteral:
		return node.AsStringLiteral().Text == ""
	case ast.KindNoSubstitutionTemplateLiteral:
		return node.AsNoSubstitutionTemplateLiteral().Text == ""
	default:
		return false
	}
}

func getPrimitiveKindFromGlobalIdentifier(name string) (primitiveKind, bool) {
	switch name {
	case "String":
		return primitiveString, true
	case "Number":
		return primitiveNumber, true
	case "Boolean":
		return primitiveBoolean, true
	case "BigInt":
		return primitiveBigInt, true
	default:
		return "", false
	}
}

func isTypeMatchingPrimitive(t *checker.Type, kind primitiveKind) bool {
	if t == nil {
		return false
	}
	switch kind {
	case primitiveString:
		return utils.IsTypeFlagSet(t, checker.TypeFlagsStringLike)
	case primitiveNumber:
		return utils.IsTypeFlagSet(t, checker.TypeFlagsNumberLike)
	case primitiveBoolean:
		return utils.IsTypeFlagSet(t, checker.TypeFlagsBooleanLike)
	case primitiveBigInt:
		return utils.IsTypeFlagSet(t, checker.TypeFlagsBigIntLike)
	default:
		return false
	}
}

func isExpressionMatchingPrimitive(ctx rule.RuleContext, node *ast.Node, kind primitiveKind) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}
	t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
	return isTypeMatchingPrimitive(t, kind)
}

func isGlobalBuiltinIdentifier(ctx rule.RuleContext, node *ast.Node) (primitiveKind, bool) {
	if node == nil || node.Kind != ast.KindIdentifier || ctx.TypeChecker == nil {
		return "", false
	}
	identifier := node.AsIdentifier().Text
	kind, ok := getPrimitiveKindFromGlobalIdentifier(identifier)
	if !ok {
		return "", false
	}
	symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
	if symbol == nil || !utils.IsSymbolFromDefaultLibrary(ctx.Program, symbol) {
		return "", false
	}
	return kind, true
}

var NoUnnecessaryTypeConversionRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-conversion",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options
		if ctx.TypeChecker == nil {
			return rule.RuleListeners{}
		}

		reportOperatorRange := func(node *ast.Node, width int) {
			if node == nil || width <= 0 {
				return
			}
			ctx.ReportRange(core.NewTextRange(node.Pos(), node.Pos()+width), buildUnnecessaryTypeConversionMessage())
		}

		reportStringPlusRange := func(node *ast.Node, start, end int) {
			if start >= end {
				return
			}
			ctx.ReportRange(core.NewTextRange(start, end), buildUnnecessaryTypeConversionMessage())
		}

		return rule.RuleListeners{
			ast.KindCallExpression: func(node *ast.Node) {
				callExpr := node.AsCallExpression()
				if callExpr == nil || callExpr.Expression == nil || callExpr.QuestionDotToken != nil {
					return
				}

				// String(x), Number(x), Boolean(x), BigInt(x)
				if kind, ok := isGlobalBuiltinIdentifier(ctx, callExpr.Expression); ok {
					if callExpr.Arguments != nil && len(callExpr.Arguments.Nodes) == 1 && isExpressionMatchingPrimitive(ctx, callExpr.Arguments.Nodes[0], kind) {
						ctx.ReportNode(callExpr.Expression, buildUnnecessaryTypeConversionMessage())
					}
					return
				}

				// obj.toString() where obj is already string-like.
				if callExpr.Expression.Kind != ast.KindPropertyAccessExpression {
					return
				}
				propertyAccess := callExpr.Expression.AsPropertyAccessExpression()
				if propertyAccess == nil || propertyAccess.Name() == nil || propertyAccess.Name().Kind != ast.KindIdentifier {
					return
				}
				if propertyAccess.Name().AsIdentifier().Text != "toString" {
					return
				}
				if callExpr.Arguments != nil && len(callExpr.Arguments.Nodes) > 0 {
					return
				}
				if !isExpressionMatchingPrimitive(ctx, propertyAccess.Expression, primitiveString) {
					return
				}
				ctx.ReportRange(core.NewTextRange(propertyAccess.Name().Pos(), callExpr.End()), buildUnnecessaryTypeConversionMessage())
			},
			ast.KindBinaryExpression: func(node *ast.Node) {
				binaryExpr := node.AsBinaryExpression()
				if binaryExpr == nil || binaryExpr.Left == nil || binaryExpr.Right == nil {
					return
				}

				switch binaryExpr.OperatorToken.Kind {
				case ast.KindPlusToken:
					if isEmptyStringLiteral(binaryExpr.Left) && isExpressionMatchingPrimitive(ctx, binaryExpr.Right, primitiveString) {
						reportStringPlusRange(node, node.Pos(), binaryExpr.Right.Pos())
						return
					}
					if isEmptyStringLiteral(binaryExpr.Right) && isExpressionMatchingPrimitive(ctx, binaryExpr.Left, primitiveString) {
						reportStringPlusRange(node, binaryExpr.Left.End(), node.End())
						return
					}
				case ast.KindPlusEqualsToken:
					if isEmptyStringLiteral(binaryExpr.Right) && isExpressionMatchingPrimitive(ctx, binaryExpr.Left, primitiveString) {
						ctx.ReportNode(node, buildUnnecessaryTypeConversionMessage())
						return
					}
				}
			},
			ast.KindPrefixUnaryExpression: func(node *ast.Node) {
				expr := node.AsPrefixUnaryExpression()
				if expr == nil || expr.Operand == nil {
					return
				}

				switch expr.Operator {
				case ast.KindPlusToken:
					if isExpressionMatchingPrimitive(ctx, expr.Operand, primitiveNumber) {
						reportOperatorRange(node, 1)
					}
				case ast.KindTildeToken:
					if expr.Operand.Kind != ast.KindPrefixUnaryExpression {
						return
					}
					inner := expr.Operand.AsPrefixUnaryExpression()
					if inner != nil && inner.Operator == ast.KindTildeToken && inner.Operand != nil && isExpressionMatchingPrimitive(ctx, inner.Operand, primitiveNumber) {
						reportOperatorRange(node, 2)
					}
				case ast.KindExclamationToken:
					if expr.Operand.Kind != ast.KindPrefixUnaryExpression {
						return
					}
					inner := expr.Operand.AsPrefixUnaryExpression()
					if inner != nil && inner.Operator == ast.KindExclamationToken && inner.Operand != nil && isExpressionMatchingPrimitive(ctx, inner.Operand, primitiveBoolean) {
						reportOperatorRange(node, 2)
					}
				}
			},
		}
	},
})
