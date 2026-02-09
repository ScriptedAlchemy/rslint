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
	case ast.KindBigIntLiteral:
		return node.AsBigIntLiteral() != nil
	case ast.KindPrefixUnaryExpression:
		expr := node.AsPrefixUnaryExpression()
		if expr == nil {
			return false
		}
		if expr.Operator == ast.KindPlusToken || expr.Operator == ast.KindMinusToken {
			return isZeroNode(expr.Operand)
		}
		return false
	default:
		return false
	}
}

func unwrapExpression(node *ast.Node) *ast.Node {
	current := node
	for current != nil {
		switch current.Kind {
		case ast.KindParenthesizedExpression:
			paren := current.AsParenthesizedExpression()
			if paren == nil {
				return current
			}
			current = paren.Expression
		case ast.KindBinaryExpression:
			bin := current.AsBinaryExpression()
			if bin == nil || bin.OperatorToken.Kind != ast.KindCommaToken {
				return current
			}
			current = bin.Right
		default:
			return current
		}
	}
	return current
}

func isStaticZeroValue(ctx rule.RuleContext, node *ast.Node, seen map[string]bool) bool {
	numberValue, ok := staticNumberValue(ctx, node, seen)
	if !ok {
		return false
	}
	if math.IsNaN(numberValue) {
		return true
	}
	return math.Trunc(numberValue) == 0
}

func parseNumberFromString(str string) float64 {
	trimmed := strings.TrimSpace(str)
	if trimmed == "" {
		return 0
	}
	if value, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return value
	}
	return math.NaN()
}

func staticNumberValue(ctx rule.RuleContext, node *ast.Node, seen map[string]bool) (float64, bool) {
	node = unwrapExpression(node)
	if node == nil {
		return 0, false
	}
	switch node.Kind {
	case ast.KindNumericLiteral:
		value, err := strconv.ParseFloat(node.AsNumericLiteral().Text, 64)
		if err != nil {
			return 0, false
		}
		return value, true
	case ast.KindStringLiteral:
		return parseNumberFromString(node.AsStringLiteral().Text), true
	case ast.KindNoSubstitutionTemplateLiteral:
		return parseNumberFromString(node.AsNoSubstitutionTemplateLiteral().Text), true
	case ast.KindBigIntLiteral:
		bigint := node.AsBigIntLiteral()
		if bigint == nil {
			return 0, false
		}
		text := strings.TrimSuffix(bigint.Text, "n")
		text = strings.ReplaceAll(text, "_", "")
		if text == "" {
			return 0, false
		}
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, false
		}
		return value, true
	case ast.KindTrueKeyword:
		return 1, true
	case ast.KindFalseKeyword, ast.KindNullKeyword:
		return 0, true
	case ast.KindPrefixUnaryExpression:
		expr := node.AsPrefixUnaryExpression()
		if expr == nil {
			return 0, false
		}
		value, ok := staticNumberValue(ctx, expr.Operand, seen)
		if !ok {
			return 0, false
		}
		switch expr.Operator {
		case ast.KindPlusToken:
			return value, true
		case ast.KindMinusToken:
			return -value, true
		default:
			return 0, false
		}
	case ast.KindIdentifier:
		ident := node.AsIdentifier()
		if ident == nil {
			return 0, false
		}
		switch ident.Text {
		case "NaN", "undefined":
			return math.NaN(), true
		case "Infinity":
			return math.Inf(1), true
		}
		if seen[ident.Text] || ctx.TypeChecker == nil {
			return 0, false
		}
		seen[ident.Text] = true
		symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
		if symbol == nil || symbol.Declarations == nil {
			return 0, false
		}
		for _, decl := range symbol.Declarations {
			if decl == nil || decl.Kind != ast.KindVariableDeclaration {
				continue
			}
			varDecl := decl.AsVariableDeclaration()
			if varDecl == nil || varDecl.Initializer == nil {
				continue
			}
			if value, ok := staticNumberValue(ctx, varDecl.Initializer, seen); ok {
				return value, true
			}
		}
	}
	return 0, false
}

func staticStringValue(ctx rule.RuleContext, node *ast.Node, seen map[string]bool) (string, bool) {
	node = unwrapExpression(node)
	if node == nil {
		return "", false
	}
	if node.Kind == ast.KindStringLiteral {
		str := node.AsStringLiteral()
		if str != nil {
			return str.Text, true
		}
	}
	if node.Kind == ast.KindNoSubstitutionTemplateLiteral {
		template := node.AsNoSubstitutionTemplateLiteral()
		if template != nil {
			return template.Text, true
		}
	}
	if node.Kind != ast.KindIdentifier || ctx.TypeChecker == nil {
		return "", false
	}
	ident := node.AsIdentifier()
	if ident == nil {
		return "", false
	}
	if seen[ident.Text] {
		return "", false
	}
	seen[ident.Text] = true
	symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
	if symbol == nil || symbol.Declarations == nil {
		return "", false
	}
	for _, decl := range symbol.Declarations {
		if decl == nil || decl.Kind != ast.KindVariableDeclaration {
			continue
		}
		varDecl := decl.AsVariableDeclaration()
		if varDecl == nil || varDecl.Initializer == nil {
			continue
		}
		if val, ok := staticStringValue(ctx, varDecl.Initializer, seen); ok {
			return val, true
		}
	}
	return "", false
}

func getFilterReceiver(call *ast.CallExpression, ctx rule.RuleContext) *ast.Node {
	if call == nil || call.Expression == nil {
		return nil
	}
	if call.QuestionDotToken != nil {
		return nil
	}
	if call.Expression.Kind == ast.KindPropertyAccessExpression {
		access := call.Expression.AsPropertyAccessExpression()
		if access == nil || access.Name() == nil || access.Name().Text() != "filter" {
			return nil
		}
		if access.QuestionDotToken != nil && !isArrayLike(ctx, access.Expression) {
			return nil
		}
		return access.Expression
	}
	if call.Expression.Kind == ast.KindElementAccessExpression {
		access := call.Expression.AsElementAccessExpression()
		if access == nil || access.Expression == nil || access.ArgumentExpression == nil {
			return nil
		}
		name, ok := staticStringValue(ctx, access.ArgumentExpression, map[string]bool{})
		if !ok || name != "filter" {
			return nil
		}
		if access.QuestionDotToken != nil && !isArrayLike(ctx, access.Expression) {
			return nil
		}
		return access.Expression
	}
	return nil
}

func isArrayLike(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}

	isArrayOrIntersection := func(t *checker.Type) bool {
		if t == nil {
			return false
		}
		if utils.IsTypeFlagSet(t, checker.TypeFlagsIntersection) {
			parts := t.Types()
			if len(parts) == 0 {
				return false
			}
			for _, part := range parts {
				if !checker.Checker_isArrayOrTupleType(ctx.TypeChecker, part) {
					return false
				}
			}
			return true
		}
		return checker.Checker_isArrayOrTupleType(ctx.TypeChecker, t)
	}

	t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
	parts := utils.UnionTypeParts(t)
	if len(parts) == 0 {
		parts = []*checker.Type{t}
	}
	hasArrayLike := false
	for _, part := range parts {
		if part == nil {
			continue
		}
		if utils.IsTypeFlagSet(part, checker.TypeFlagsNull|checker.TypeFlagsUndefined) {
			continue
		}
		if !isArrayOrIntersection(part) {
			return false
		}
		hasArrayLike = true
	}
	return hasArrayLike
}

func isFilterCallOnArray(ctx rule.RuleContext, node *ast.Node) bool {
	node = unwrapExpression(node)
	if node == nil {
		return false
	}
	if node.Kind == ast.KindConditionalExpression {
		conditional := node.AsConditionalExpression()
		if conditional == nil {
			return false
		}
		return isFilterCallOnArray(ctx, conditional.WhenTrue) && isFilterCallOnArray(ctx, conditional.WhenFalse)
	}
	if node.Kind != ast.KindCallExpression {
		return false
	}
	call := node.AsCallExpression()
	receiver := getFilterReceiver(call, ctx)
	return receiver != nil && isArrayLike(ctx, receiver)
}

func hasOptionalChainToken(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindPropertyAccessExpression, ast.KindElementAccessExpression, ast.KindCallExpression, ast.KindTaggedTemplateExpression:
		return node.QuestionDotToken() != nil
	default:
		return false
	}
}

var PreferFindRule = rule.CreateRule(rule.Rule{
	Name: "prefer-find",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			// arr.filter(fn)[0]
			ast.KindElementAccessExpression: func(node *ast.Node) {
				element := node.AsElementAccessExpression()
				if element == nil || element.ArgumentExpression == nil {
					return
				}
				if node.Parent != nil && node.Parent.Kind == ast.KindCallExpression {
					parentCall := node.Parent.AsCallExpression()
					if parentCall != nil && parentCall.Expression == node {
						return
					}
				}
				if element.QuestionDotToken != nil || hasOptionalChainToken(element.Expression) {
					return
				}
				if !isStaticZeroValue(ctx, element.ArgumentExpression, map[string]bool{}) {
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
				if call.QuestionDotToken != nil {
					return
				}
				if !isStaticZeroValue(ctx, call.Arguments.Nodes[0], map[string]bool{}) {
					return
				}
				switch call.Expression.Kind {
				case ast.KindPropertyAccessExpression:
					access := call.Expression.AsPropertyAccessExpression()
					if access == nil || access.Name() == nil || access.Name().Text() != "at" || access.QuestionDotToken != nil {
						return
					}
					if !isFilterCallOnArray(ctx, access.Expression) {
						return
					}
				case ast.KindElementAccessExpression:
					access := call.Expression.AsElementAccessExpression()
					if access == nil || access.Expression == nil || access.ArgumentExpression == nil || access.QuestionDotToken != nil {
						return
					}
					name, ok := staticStringValue(ctx, access.ArgumentExpression, map[string]bool{})
					if !ok || name != "at" {
						return
					}
					if !isFilterCallOnArray(ctx, access.Expression) {
						return
					}
				default:
					return
				}
				ctx.ReportNode(node, buildPreferFindMessage())
			},
		}
	},
})
