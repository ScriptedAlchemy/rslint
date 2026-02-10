package prefer_destructuring

import (
	"math"
	"strconv"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type destructuringTypeConfig struct {
	Array  bool
	Object bool
}

type preferDestructuringOptions struct {
	AssignmentExpression                    destructuringTypeConfig
	VariableDeclarator                      destructuringTypeConfig
	EnforceForDeclarationWithTypeAnnotation bool
	EnforceForRenamedProperties             bool
}

func defaultOptions() preferDestructuringOptions {
	return preferDestructuringOptions{
		AssignmentExpression: destructuringTypeConfig{
			Array:  true,
			Object: true,
		},
		VariableDeclarator: destructuringTypeConfig{
			Array:  true,
			Object: true,
		},
		EnforceForDeclarationWithTypeAnnotation: false,
		EnforceForRenamedProperties:             false,
	}
}

func parseTypeConfig(raw any) destructuringTypeConfig {
	cfg := destructuringTypeConfig{
		Array:  false,
		Object: false,
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return cfg
	}
	if v, ok := m["array"].(bool); ok {
		cfg.Array = v
	}
	if v, ok := m["object"].(bool); ok {
		cfg.Object = v
	}
	return cfg
}

func parseOptions(options any) preferDestructuringOptions {
	opts := defaultOptions()

	optionArray, ok := options.([]interface{})
	if !ok || len(optionArray) == 0 {
		return opts
	}

	if first, ok := optionArray[0].(map[string]interface{}); ok {
		if _, hasArray := first["array"]; hasArray {
			cfg := parseTypeConfig(first)
			opts.AssignmentExpression = cfg
			opts.VariableDeclarator = cfg
		} else if _, hasObject := first["object"]; hasObject {
			cfg := parseTypeConfig(first)
			opts.AssignmentExpression = cfg
			opts.VariableDeclarator = cfg
		} else {
			if raw, ok := first["AssignmentExpression"]; ok {
				opts.AssignmentExpression = parseTypeConfig(raw)
			}
			if raw, ok := first["VariableDeclarator"]; ok {
				opts.VariableDeclarator = parseTypeConfig(raw)
			}
		}
	}

	if len(optionArray) > 1 {
		if second, ok := optionArray[1].(map[string]interface{}); ok {
			if v, ok := second["enforceForDeclarationWithTypeAnnotation"].(bool); ok {
				opts.EnforceForDeclarationWithTypeAnnotation = v
			}
			if v, ok := second["enforceForRenamedProperties"].(bool); ok {
				opts.EnforceForRenamedProperties = v
			}
		}
	}

	return opts
}

func buildPreferDestructuringMessage(kind string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferDestructuring",
		Description: "Use " + kind + " destructuring.",
	}
}

func getIdentifierName(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindIdentifier {
		return ""
	}
	return node.AsIdentifier().Text
}

func hasDeclarationTypeAnnotation(decl *ast.VariableDeclaration) bool {
	if decl == nil {
		return false
	}
	if decl.Type != nil {
		return true
	}
	if decl.Name() != nil && decl.Name().Type() != nil {
		return true
	}
	return false
}

func getElementAccessIntegerIndex(node *ast.Node) (int64, bool) {
	if node == nil {
		return 0, false
	}
	if node.Kind == ast.KindNumericLiteral {
		lit := node.AsNumericLiteral()
		if lit == nil {
			return 0, false
		}
		f, err := strconv.ParseFloat(lit.Text, 64)
		if err != nil || math.Trunc(f) != f {
			return 0, false
		}
		return int64(f), true
	}
	if node.Kind == ast.KindPrefixUnaryExpression {
		prefix := node.AsPrefixUnaryExpression()
		if prefix == nil || prefix.Operand == nil || prefix.Operand.Kind != ast.KindNumericLiteral {
			return 0, false
		}
		lit := prefix.Operand.AsNumericLiteral()
		if lit == nil {
			return 0, false
		}
		f, err := strconv.ParseFloat(lit.Text, 64)
		if err != nil || math.Trunc(f) != f {
			return 0, false
		}
		if prefix.Operator == ast.KindMinusToken {
			f = -f
		}
		return int64(f), true
	}
	return 0, false
}

func isTypeAnyOrIterable(ctx rule.RuleContext, t *checker.Type) bool {
	if t == nil {
		return false
	}
	if utils.IsTypeAnyType(t) {
		return true
	}
	if utils.IsUnionType(t) {
		for _, part := range utils.UnionTypeParts(t) {
			if !isTypeAnyOrIterable(ctx, part) {
				return false
			}
		}
		return true
	}
	if utils.IsIntersectionType(t) {
		for _, part := range utils.IntersectionTypeParts(t) {
			if isTypeAnyOrIterable(ctx, part) {
				return true
			}
		}
		return false
	}
	if checker.Checker_isArrayOrTupleType(ctx.TypeChecker, t) {
		return true
	}
	return utils.GetWellKnownSymbolPropertyOfType(t, "iterator", ctx.TypeChecker) != nil
}

func enabledFor(cfg destructuringTypeConfig, kind string) bool {
	if kind == "array" {
		return cfg.Array
	}
	return cfg.Object
}

var PreferDestructuringRule = rule.CreateRule(rule.Rule{
	Name: "prefer-destructuring",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		report := func(node *ast.Node, kind string) {
			ctx.ReportNode(node, buildPreferDestructuringMessage(kind))
		}

		performCheck := func(leftNode *ast.Node, rightNode *ast.Node, reportNode *ast.Node, cfg destructuringTypeConfig, skipTypedDeclaration bool) {
			if leftNode == nil || rightNode == nil || reportNode == nil {
				return
			}

			if skipTypedDeclaration && !opts.EnforceForDeclarationWithTypeAnnotation {
				return
			}

			leftName := getIdentifierName(leftNode)

			if rightNode.Kind == ast.KindPropertyAccessExpression {
				access := rightNode.AsPropertyAccessExpression()
				if access == nil || access.Expression == nil || access.QuestionDotToken != nil {
					return
				}
				if access.Expression.Kind == ast.KindSuperKeyword {
					return
				}
				nameNode := access.Name()
				if nameNode == nil || nameNode.Kind != ast.KindIdentifier {
					return
				}
				propertyName := nameNode.AsIdentifier().Text
				if !opts.EnforceForRenamedProperties && leftName != "" && leftName != propertyName {
					return
				}
				if !enabledFor(cfg, "object") {
					return
				}
				report(reportNode, "object")
				return
			}

			if rightNode.Kind != ast.KindElementAccessExpression {
				return
			}
			access := rightNode.AsElementAccessExpression()
			if access == nil || access.Expression == nil || access.ArgumentExpression == nil || access.QuestionDotToken != nil {
				return
			}
			if access.Expression.Kind == ast.KindSuperKeyword {
				return
			}

			if access.ArgumentExpression.Kind == ast.KindStringLiteral {
				propertyName := access.ArgumentExpression.AsStringLiteral().Text
				if !opts.EnforceForRenamedProperties && leftName != "" && leftName != propertyName {
					return
				}
				if !enabledFor(cfg, "object") {
					return
				}
				report(reportNode, "object")
				return
			}

			if _, ok := getElementAccessIntegerIndex(access.ArgumentExpression); ok {
				t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, access.Expression)
				if !isTypeAnyOrIterable(ctx, t) {
					if opts.EnforceForRenamedProperties && enabledFor(cfg, "object") {
						report(reportNode, "object")
					}
					return
				}
				if enabledFor(cfg, "array") {
					report(reportNode, "array")
				}
				return
			}

			if !opts.EnforceForRenamedProperties || !enabledFor(cfg, "object") {
				return
			}
			report(reportNode, "object")
		}

		return rule.RuleListeners{
			ast.KindBinaryExpression: func(node *ast.Node) {
				expr := node.AsBinaryExpression()
				if expr == nil || expr.OperatorToken.Kind != ast.KindEqualsToken || expr.Left == nil || expr.Right == nil {
					return
				}
				if expr.Left.Kind != ast.KindIdentifier {
					return
				}
				performCheck(expr.Left, expr.Right, node, opts.AssignmentExpression, false)
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				decl := node.AsVariableDeclaration()
				if decl == nil || decl.Name() == nil || decl.Initializer == nil {
					return
				}
				if decl.Name().Kind != ast.KindIdentifier {
					return
				}
				performCheck(decl.Name(), decl.Initializer, node, opts.VariableDeclarator, hasDeclarationTypeAnnotation(decl))
			},
		}
	},
})
