package prefer_function_type

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildFunctionTypeOverCallableTypeMessage(kind string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "functionTypeOverCallableType",
		Description: kind + " only has a call signature, you should use a function type instead.",
	}
}

func hasInterfaceSupertypes(node *ast.InterfaceDeclaration) bool {
	if node == nil || node.HeritageClauses == nil {
		return false
	}
	for _, clause := range node.HeritageClauses.Nodes {
		h := clause.AsHeritageClause()
		if h == nil || h.Token != ast.KindExtendsKeyword || h.Types == nil {
			continue
		}
		if len(h.Types.Nodes) == 0 {
			continue
		}
		// simplified: any extends disqualifies reporting
		return true
	}
	return false
}

func isCallableSignatureMember(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == ast.KindCallSignature || node.Kind == ast.KindConstructSignature
}

var PreferFunctionTypeRule = rule.CreateRule(rule.Rule{
	Name: "prefer-function-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				iface := node.AsInterfaceDeclaration()
				if iface == nil || iface.Members == nil || len(iface.Members.Nodes) != 1 {
					return
				}
				if hasInterfaceSupertypes(iface) {
					return
				}
				if !isCallableSignatureMember(iface.Members.Nodes[0]) {
					return
				}
				ctx.ReportNode(iface.Members.Nodes[0], buildFunctionTypeOverCallableTypeMessage("Interface"))
			},
			ast.KindTypeLiteral: func(node *ast.Node) {
				literal := node.AsTypeLiteralNode()
				if literal == nil || literal.Members == nil || len(literal.Members.Nodes) != 1 {
					return
				}
				if !isCallableSignatureMember(literal.Members.Nodes[0]) {
					return
				}
				ctx.ReportNode(literal.Members.Nodes[0], buildFunctionTypeOverCallableTypeMessage("Type literal"))
			},
		}
	},
})
