package prefer_regexp_exec

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type regexpArgumentInfo struct {
	known  bool
	global bool
}

func buildRegExpExecOverStringMatchMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "regExpExecOverStringMatch",
		Description: "Use the `RegExp#exec()` method instead.",
	}
}

func hasGlobalFlag(flags string) bool {
	return strings.Contains(flags, "g")
}

func parseRegexpLiteralGlobal(node *ast.Node) (bool, bool) {
	if node == nil || node.Kind != ast.KindRegularExpressionLiteral {
		return false, false
	}
	regexLit := node.AsRegularExpressionLiteral()
	if regexLit == nil {
		return false, false
	}
	text := regexLit.Text
	lastSlash := strings.LastIndex(text, "/")
	if lastSlash <= 0 {
		return false, false
	}
	flags := text[lastSlash+1:]
	return true, hasGlobalFlag(flags)
}

func parseRegExpCtorCallGlobal(node *ast.Node) (bool, bool) {
	if node == nil {
		return false, false
	}
	var args []*ast.Node
	switch node.Kind {
	case ast.KindCallExpression:
		callExpr := node.AsCallExpression()
		if callExpr == nil || callExpr.Expression == nil || callExpr.Expression.Kind != ast.KindIdentifier || callExpr.Expression.AsIdentifier().Text != "RegExp" {
			return false, false
		}
		if callExpr.Arguments != nil {
			args = callExpr.Arguments.Nodes
		}
	case ast.KindNewExpression:
		newExpr := node.AsNewExpression()
		if newExpr == nil || newExpr.Expression == nil || newExpr.Expression.Kind != ast.KindIdentifier || newExpr.Expression.AsIdentifier().Text != "RegExp" {
			return false, false
		}
		if newExpr.Arguments != nil {
			args = newExpr.Arguments.Nodes
		}
	default:
		return false, false
	}

	if len(args) < 2 {
		return true, false
	}
	flagsArg := ast.SkipParentheses(args[1])
	if flagsArg == nil || flagsArg.Kind != ast.KindStringLiteral {
		return true, false
	}
	return true, hasGlobalFlag(flagsArg.AsStringLiteral().Text)
}

func resolveRegexpArgumentInfo(ctx rule.RuleContext, node *ast.Node) regexpArgumentInfo {
	if known, global := parseRegexpLiteralGlobal(node); known {
		return regexpArgumentInfo{known: true, global: global}
	}
	if known, global := parseRegExpCtorCallGlobal(node); known {
		return regexpArgumentInfo{known: true, global: global}
	}

	if node != nil && node.Kind == ast.KindIdentifier && ctx.TypeChecker != nil {
		symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
		if symbol != nil {
			for _, decl := range symbol.Declarations {
				if decl.Kind != ast.KindVariableDeclaration {
					continue
				}
				varDecl := decl.AsVariableDeclaration()
				if varDecl == nil || varDecl.Initializer == nil {
					continue
				}
				if known, global := parseRegexpLiteralGlobal(varDecl.Initializer); known {
					return regexpArgumentInfo{known: true, global: global}
				}
				if known, global := parseRegExpCtorCallGlobal(varDecl.Initializer); known {
					return regexpArgumentInfo{known: true, global: global}
				}
			}
		}
	}

	return regexpArgumentInfo{known: false, global: false}
}

func isStringLikeType(ctx rule.RuleContext, expr *ast.Node) bool {
	if expr == nil {
		return false
	}
	if expr.Kind == ast.KindStringLiteral || expr.Kind == ast.KindNoSubstitutionTemplateLiteral {
		return true
	}
	if ctx.TypeChecker == nil {
		return false
	}
	typ := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, expr)
	if typ == nil {
		return false
	}
	return utils.GetTypeName(ctx.TypeChecker, typ) == "string"
}

func isStringLikePatternArg(ctx rule.RuleContext, arg *ast.Node) bool {
	if arg == nil {
		return false
	}
	arg = ast.SkipParentheses(arg)
	if arg == nil {
		return false
	}
	if arg.Kind == ast.KindStringLiteral || arg.Kind == ast.KindNoSubstitutionTemplateLiteral {
		return true
	}
	if ctx.TypeChecker == nil {
		return false
	}
	typ := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, arg)
	if typ == nil {
		return false
	}
	return utils.GetTypeName(ctx.TypeChecker, typ) == "string"
}

var PreferRegexpExecRule = rule.CreateRule(rule.Rule{
	Name: "prefer-regexp-exec",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		return rule.RuleListeners{
			ast.KindCallExpression: func(node *ast.Node) {
				callExpr := node.AsCallExpression()
				if callExpr == nil || callExpr.Expression == nil || callExpr.Arguments == nil || len(callExpr.Arguments.Nodes) != 1 {
					return
				}
				if callExpr.Expression.Kind != ast.KindPropertyAccessExpression {
					return
				}

				access := callExpr.Expression.AsPropertyAccessExpression()
				if access == nil || access.Name() == nil || access.Name().Kind != ast.KindIdentifier || access.Name().AsIdentifier().Text != "match" {
					return
				}

				target := access.Expression
				if !isStringLikeType(ctx, target) {
					return
				}

				arg := ast.SkipParentheses(callExpr.Arguments.Nodes[0])
				regexpInfo := resolveRegexpArgumentInfo(ctx, arg)
				if regexpInfo.known {
					if regexpInfo.global {
						return
					}
					ctx.ReportNode(access.Name(), buildRegExpExecOverStringMatchMessage())
					return
				}

				if isStringLikePatternArg(ctx, arg) {
					ctx.ReportNode(access.Name(), buildRegExpExecOverStringMatchMessage())
				}
			},
		}
	},
})
