package prefer_find

import (
	"math"
	"strconv"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type staticValueKind int

const (
	staticUnknown staticValueKind = iota
	staticNumber
	staticString
	staticBigInt
)

type staticValue struct {
	kind       staticValueKind
	number     float64
	text       string
	bigIntZero bool
}

func buildPreferFindMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferFind",
		Description: "Prefer `.find(...)` over `.filter(...)[0]` or `.filter(...).at(0)`.",
	}
}

func unwrapExpression(node *ast.Node) *ast.Node {
	for node != nil {
		switch node.Kind {
		case ast.KindParenthesizedExpression:
			node = node.AsParenthesizedExpression().Expression
		case ast.KindAsExpression:
			node = node.AsAsExpression().Expression
		case ast.KindTypeAssertionExpression:
			node = node.AsTypeAssertion().Expression
		case ast.KindNonNullExpression:
			node = node.AsNonNullExpression().Expression
		case ast.KindSatisfiesExpression:
			node = node.AsSatisfiesExpression().Expression
		default:
			return node
		}
	}
	return nil
}

func nodeText(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return ctx.SourceFile.Text()[r.Pos():r.End()]
}

func parseNumericText(text string) (float64, bool) {
	clean := strings.ReplaceAll(strings.TrimSpace(text), "_", "")
	if clean == "" {
		return 0, false
	}
	value, err := strconv.ParseFloat(clean, 64)
	return value, err == nil
}

func parseBigIntZero(text string) bool {
	clean := strings.ReplaceAll(strings.TrimSpace(text), "_", "")
	clean = strings.TrimSuffix(clean, "n")
	clean = strings.TrimPrefix(clean, "+")
	clean = strings.TrimPrefix(clean, "-")
	clean = strings.TrimLeft(clean, "0")
	return clean == ""
}

func evaluateStaticValue(ctx rule.RuleContext, node *ast.Node, depth int) (staticValue, bool) {
	if node == nil || depth > 8 {
		return staticValue{}, false
	}
	node = unwrapExpression(node)
	if node == nil {
		return staticValue{}, false
	}

	switch node.Kind {
	case ast.KindNumericLiteral:
		if value, ok := parseNumericText(node.AsNumericLiteral().Text); ok {
			return staticValue{kind: staticNumber, number: value}, true
		}
		return staticValue{}, false
	case ast.KindBigIntLiteral:
		return staticValue{kind: staticBigInt, text: nodeText(ctx, node), bigIntZero: parseBigIntZero(nodeText(ctx, node))}, true
	case ast.KindStringLiteral:
		return staticValue{kind: staticString, text: node.AsStringLiteral().Text}, true
	case ast.KindNoSubstitutionTemplateLiteral:
		return staticValue{kind: staticString, text: node.AsNoSubstitutionTemplateLiteral().Text}, true
	case ast.KindIdentifier:
		name := node.AsIdentifier().Text
		switch name {
		case "NaN":
			return staticValue{kind: staticNumber, number: math.NaN()}, true
		case "Infinity":
			return staticValue{kind: staticNumber, number: math.Inf(1)}, true
		}
		if ctx.TypeChecker == nil {
			return staticValue{}, false
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
		if symbol == nil || len(symbol.Declarations) == 0 {
			return staticValue{}, false
		}
		for _, decl := range symbol.Declarations {
			if decl.Kind != ast.KindVariableDeclaration {
				continue
			}
			varDecl := decl.AsVariableDeclaration()
			if varDecl == nil || varDecl.Initializer == nil {
				continue
			}
			if value, ok := evaluateStaticValue(ctx, varDecl.Initializer, depth+1); ok {
				return value, true
			}
		}
		return staticValue{}, false
	case ast.KindPrefixUnaryExpression:
		unary := node.AsPrefixUnaryExpression()
		if unary == nil || unary.Operand == nil {
			return staticValue{}, false
		}
		value, ok := evaluateStaticValue(ctx, unary.Operand, depth+1)
		if !ok {
			return staticValue{}, false
		}
		switch unary.Operator {
		case ast.KindPlusToken:
			return value, true
		case ast.KindMinusToken:
			if value.kind == staticNumber {
				return staticValue{kind: staticNumber, number: -value.number}, true
			}
			if value.kind == staticBigInt {
				return staticValue{kind: staticBigInt, text: "-" + value.text, bigIntZero: value.bigIntZero}, true
			}
			return staticValue{}, false
		default:
			return staticValue{}, false
		}
	default:
		return staticValue{}, false
	}
}

func toIntegerOrInfinity(value float64) float64 {
	if math.IsNaN(value) || value == 0 {
		return 0
	}
	if math.IsInf(value, 1) {
		return math.Inf(1)
	}
	if math.IsInf(value, -1) {
		return math.Inf(-1)
	}
	if value > 0 {
		return math.Floor(value)
	}
	return math.Ceil(value)
}

func isZeroElementAccessIndex(ctx rule.RuleContext, node *ast.Node) bool {
	value, ok := evaluateStaticValue(ctx, node, 0)
	if !ok {
		return false
	}
	switch value.kind {
	case staticNumber:
		return value.number == 0
	case staticString:
		return value.text == "0"
	case staticBigInt:
		return value.bigIntZero
	default:
		return false
	}
}

func isZeroAtIndex(ctx rule.RuleContext, node *ast.Node) bool {
	value, ok := evaluateStaticValue(ctx, node, 0)
	if !ok {
		return false
	}
	switch value.kind {
	case staticNumber:
		return toIntegerOrInfinity(value.number) == 0
	case staticString:
		if parsed, ok := parseNumericText(value.text); ok {
			return toIntegerOrInfinity(parsed) == 0
		}
		return true
	case staticBigInt:
		return value.bigIntZero
	default:
		return false
	}
}

func getAccessMethodAndReceiver(ctx rule.RuleContext, accessNode *ast.Node) (receiver *ast.Node, methodName string, isOptional bool, ok bool) {
	if accessNode == nil {
		return nil, "", false, false
	}
	switch accessNode.Kind {
	case ast.KindPropertyAccessExpression:
		propertyAccess := accessNode.AsPropertyAccessExpression()
		if propertyAccess == nil || propertyAccess.Expression == nil || propertyAccess.Name() == nil || propertyAccess.Name().Kind != ast.KindIdentifier {
			return nil, "", false, false
		}
		return propertyAccess.Expression, propertyAccess.Name().AsIdentifier().Text, propertyAccess.QuestionDotToken != nil, true
	case ast.KindElementAccessExpression:
		elementAccess := accessNode.AsElementAccessExpression()
		if elementAccess == nil || elementAccess.Expression == nil || elementAccess.ArgumentExpression == nil {
			return nil, "", false, false
		}
		value, known := evaluateStaticValue(ctx, elementAccess.ArgumentExpression, 0)
		if !known || value.kind != staticString {
			return nil, "", false, false
		}
		return elementAccess.Expression, value.text, elementAccess.QuestionDotToken != nil, true
	default:
		return nil, "", false, false
	}
}

func isDefinitelyArrayOrTupleType(typeChecker *checker.Checker, t *checker.Type) bool {
	if t == nil {
		return false
	}
	flags := checker.Type_flags(t)
	if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined) != 0 {
		return false
	}
	if flags&checker.TypeFlagsUnion != 0 {
		hasArrayLikePart := false
		for _, part := range t.Types() {
			if part == nil {
				return false
			}
			partFlags := checker.Type_flags(part)
			if partFlags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined) != 0 {
				continue
			}
			if !isDefinitelyArrayOrTupleType(typeChecker, part) {
				return false
			}
			hasArrayLikePart = true
		}
		return hasArrayLikePart
	}
	if flags&checker.TypeFlagsIntersection != 0 {
		for _, part := range t.Types() {
			if isDefinitelyArrayOrTupleType(typeChecker, part) {
				return true
			}
		}
		return false
	}
	return checker.Checker_isArrayOrTupleType(typeChecker, t)
}

func isArrayFilterCall(ctx rule.RuleContext, callExpr *ast.CallExpression) bool {
	if callExpr == nil || callExpr.Expression == nil || callExpr.QuestionDotToken != nil || ctx.TypeChecker == nil {
		return false
	}

	receiver, methodName, _, ok := getAccessMethodAndReceiver(ctx, callExpr.Expression)
	if !ok || methodName != "filter" || receiver == nil {
		return false
	}

	receiverType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, receiver)
	return isDefinitelyArrayOrTupleType(ctx.TypeChecker, receiverType)
}

func isFilterResultExpression(ctx rule.RuleContext, expression *ast.Node) bool {
	expression = unwrapExpression(expression)
	if expression == nil {
		return false
	}

	switch expression.Kind {
	case ast.KindCallExpression:
		return isArrayFilterCall(ctx, expression.AsCallExpression())
	case ast.KindConditionalExpression:
		conditional := expression.AsConditionalExpression()
		if conditional == nil {
			return false
		}
		return isFilterResultExpression(ctx, conditional.WhenTrue) && isFilterResultExpression(ctx, conditional.WhenFalse)
	case ast.KindBinaryExpression:
		binary := expression.AsBinaryExpression()
		if binary == nil {
			return false
		}
		if binary.OperatorToken.Kind == ast.KindCommaToken {
			return isFilterResultExpression(ctx, binary.Right)
		}
		return false
	default:
		return false
	}
}

var PreferFindRule = rule.CreateRule(rule.Rule{
	Name: "prefer-find",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options
		if ctx.TypeChecker == nil {
			return rule.RuleListeners{}
		}

		return rule.RuleListeners{
			ast.KindElementAccessExpression: func(node *ast.Node) {
				elementAccess := node.AsElementAccessExpression()
				if elementAccess == nil || elementAccess.Expression == nil || elementAccess.ArgumentExpression == nil {
					return
				}
				if elementAccess.QuestionDotToken != nil {
					return
				}
				if !isZeroElementAccessIndex(ctx, elementAccess.ArgumentExpression) {
					return
				}
				if !isFilterResultExpression(ctx, elementAccess.Expression) {
					return
				}
				ctx.ReportNode(node, buildPreferFindMessage())
			},
			ast.KindCallExpression: func(node *ast.Node) {
				callExpr := node.AsCallExpression()
				if callExpr == nil || callExpr.Expression == nil {
					return
				}
				if callExpr.QuestionDotToken != nil {
					return
				}

				receiver, methodName, isOptionalAccess, ok := getAccessMethodAndReceiver(ctx, callExpr.Expression)
				if !ok || methodName != "at" || receiver == nil || isOptionalAccess {
					return
				}

				if callExpr.Arguments == nil || len(callExpr.Arguments.Nodes) == 0 {
					if isFilterResultExpression(ctx, receiver) {
						ctx.ReportNode(node, buildPreferFindMessage())
					}
					return
				}
				if !isZeroAtIndex(ctx, callExpr.Arguments.Nodes[0]) {
					return
				}
				if !isFilterResultExpression(ctx, receiver) {
					return
				}
				ctx.ReportNode(node, buildPreferFindMessage())
			},
		}
	},
})
