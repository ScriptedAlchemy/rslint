package prefer_enum_initializers

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildDefineInitializerMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "defineInitializer",
		Description: "Explicitly define an initializer for this enum member.",
	}
}

var PreferEnumInitializersRule = rule.CreateRule(rule.Rule{
	Name: "prefer-enum-initializers",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		return rule.RuleListeners{
			ast.KindEnumDeclaration: func(node *ast.Node) {
				enumDecl := node.AsEnumDeclaration()
				if enumDecl == nil || enumDecl.Members == nil {
					return
				}

				for _, memberNode := range enumDecl.Members.Nodes {
					member := memberNode.AsEnumMember()
					if member == nil || member.Initializer != nil {
						continue
					}
					ctx.ReportNode(member.Name(), buildDefineInitializerMessage())
				}
			},
		}
	},
})
