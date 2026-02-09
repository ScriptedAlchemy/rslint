package prefer_regexp_exec

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildPreferRegExpExecMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "regExpExecOverStringMatch",
		Description: "Use the `RegExp#exec()` method instead.",
	}
}

func isGlobalRegexLiteral(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindRegularExpressionLiteral {
		return false
	}
	regex := node.AsRegularExpressionLiteral()
	if regex == nil {
		return false
	}
	text := regex.Text
	lastSlash := strings.LastIndex(text, "/")
	if lastSlash < 0 || lastSlash+1 >= len(text) {
		return false
	}
	flags := text[lastSlash+1:]
	return strings.Contains(flags, "g")
}

type staticArgInfo struct {
	known  bool
	global bool
}

func regExpFlagInfo(args []*ast.Node) (known bool, global bool) {
	if len(args) < 2 || args[1] == nil || args[1].Kind != ast.KindStringLiteral {
		return true, false
	}
	return true, strings.Contains(args[1].AsStringLiteral().Text, "g")
}

func resolveStaticArgumentInfo(ctx rule.RuleContext, node *ast.Node, seen map[string]bool) staticArgInfo {
	if node == nil {
		return staticArgInfo{}
	}
	switch node.Kind {
	case ast.KindStringLiteral:
		return staticArgInfo{known: true}
	case ast.KindRegularExpressionLiteral:
		return staticArgInfo{known: true, global: isGlobalRegexLiteral(node)}
	case ast.KindCallExpression:
		call := node.AsCallExpression()
		if call != nil && call.Expression != nil && call.Expression.Kind == ast.KindIdentifier && call.Expression.AsIdentifier().Text == "RegExp" && call.Arguments != nil {
			known, global := regExpFlagInfo(call.Arguments.Nodes)
			return staticArgInfo{known: known, global: global}
		}
	case ast.KindNewExpression:
		newExpr := node.AsNewExpression()
		if newExpr != nil && newExpr.Expression != nil && newExpr.Expression.Kind == ast.KindIdentifier && newExpr.Expression.AsIdentifier().Text == "RegExp" && newExpr.Arguments != nil {
			known, global := regExpFlagInfo(newExpr.Arguments.Nodes)
			return staticArgInfo{known: known, global: global}
		}
	case ast.KindIdentifier:
		if ctx.TypeChecker == nil {
			return staticArgInfo{}
		}
		name := node.AsIdentifier().Text
		if seen[name] {
			return staticArgInfo{}
		}
		seen[name] = true
		sym := ctx.TypeChecker.GetSymbolAtLocation(node)
		if sym == nil || sym.Declarations == nil {
			return staticArgInfo{}
		}
		for _, decl := range sym.Declarations {
			if decl == nil || decl.Kind != ast.KindVariableDeclaration {
				continue
			}
			varDecl := decl.AsVariableDeclaration()
			if varDecl == nil || varDecl.Initializer == nil {
				continue
			}
			info := resolveStaticArgumentInfo(ctx, varDecl.Initializer, seen)
			if info.known {
				return info
			}
		}
	}
	return staticArgInfo{}
}

func definitelyDoesNotContainGlobalFlag(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindCallExpression:
		call := node.AsCallExpression()
		if call == nil || call.Expression == nil || call.Expression.Kind != ast.KindIdentifier || call.Expression.AsIdentifier().Text != "RegExp" || call.Arguments == nil {
			return false
		}
		known, global := regExpFlagInfo(call.Arguments.Nodes)
		return known && !global
	case ast.KindNewExpression:
		newExpr := node.AsNewExpression()
		if newExpr == nil || newExpr.Expression == nil || newExpr.Expression.Kind != ast.KindIdentifier || newExpr.Expression.AsIdentifier().Text != "RegExp" || newExpr.Arguments == nil {
			return false
		}
		known, global := regExpFlagInfo(newExpr.Arguments.Nodes)
		return known && !global
	default:
		return false
	}
}

func isStringMatchCall(node *ast.Node) (*ast.CallExpression, bool) {
	if node == nil || node.Kind != ast.KindCallExpression {
		return nil, false
	}
	call := node.AsCallExpression()
	if call == nil || call.Expression == nil {
		return nil, false
	}

	if call.Expression.Kind != ast.KindPropertyAccessExpression {
		return nil, false
	}
	access := call.Expression.AsPropertyAccessExpression()
	if access == nil || access.Name() == nil || access.Name().Text() != "match" {
		return nil, false
	}

	return call, true
}

func isStringLikeReceiver(ctx rule.RuleContext, receiver *ast.Node) bool {
	if receiver == nil || ctx.TypeChecker == nil {
		return false
	}
	receiverType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, receiver)
	return utils.GetTypeName(ctx.TypeChecker, receiverType) == "string"
}

func isRegExpOrStringArgument(ctx rule.RuleContext, argument *ast.Node) bool {
	if argument == nil {
		return false
	}
	if argument.Kind == ast.KindRegularExpressionLiteral || argument.Kind == ast.KindStringLiteral {
		return true
	}
	if ctx.TypeChecker == nil {
		return false
	}
	argType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, argument)
	typeName := utils.GetTypeName(ctx.TypeChecker, argType)
	return typeName == "RegExp" || typeName == "string"
}

var PreferRegExpExecRule = rule.CreateRule(rule.Rule{
	Name: "prefer-regexp-exec",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindCallExpression: func(node *ast.Node) {
				call, ok := isStringMatchCall(node)
				if !ok || call.Arguments == nil || len(call.Arguments.Nodes) != 1 {
					return
				}

				access := call.Expression.AsPropertyAccessExpression()
				receiver := access.Expression
				if !isStringLikeReceiver(ctx, receiver) {
					return
				}

				arg := call.Arguments.Nodes[0]
				staticInfo := resolveStaticArgumentInfo(ctx, arg, map[string]bool{})
				if staticInfo.known && staticInfo.global {
					return
				}
				if !staticInfo.known && !definitelyDoesNotContainGlobalFlag(arg) {
					return
				}
				if !isRegExpOrStringArgument(ctx, arg) {
					return
				}
				if arg.Kind == ast.KindStringLiteral {
					if _, err := regexp.Compile(arg.AsStringLiteral().Text); err != nil {
						return
					}
				}

				ctx.ReportNode(access.Name(), buildPreferRegExpExecMessage())
			},
		}
	},
})
