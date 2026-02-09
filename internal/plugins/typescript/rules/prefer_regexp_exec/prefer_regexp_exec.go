package prefer_regexp_exec

import (
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
				if isGlobalRegexLiteral(arg) {
					return
				}
				if !isRegExpOrStringArgument(ctx, arg) {
					return
				}

				ctx.ReportNode(access.Name(), buildPreferRegExpExecMessage())
			},
		}
	},
})
