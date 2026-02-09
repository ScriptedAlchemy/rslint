package prefer_destructuring

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildPreferDestructuringMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferDestructuring",
		Description: "Use object destructuring.",
	}
}

func isSimpleMemberAccess(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindPropertyAccessExpression {
		return false
	}
	access := node.AsPropertyAccessExpression()
	return access != nil && access.Expression != nil
}

var PreferDestructuringRule = rule.CreateRule(rule.Rule{
	Name: "prefer-destructuring",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindVariableDeclaration: func(node *ast.Node) {
				decl := node.AsVariableDeclaration()
				if decl == nil || decl.Name() == nil || decl.Initializer == nil {
					return
				}
				if decl.Name().Kind != ast.KindIdentifier {
					return
				}
				if !isSimpleMemberAccess(decl.Initializer) {
					return
				}
				ctx.ReportNode(decl.Name(), buildPreferDestructuringMessage())
			},
		}
	},
})
