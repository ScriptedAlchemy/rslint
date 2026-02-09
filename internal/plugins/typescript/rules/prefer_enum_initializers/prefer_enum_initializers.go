package prefer_enum_initializers

import (
	"strconv"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildDefineInitializerMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "defineInitializer",
		Description: "The value of the member '" + name + "' should be explicitly defined.",
	}
}

func buildDefineInitializerSuggestionMessage(name string, suggested string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "defineInitializerSuggestion",
		Description: "Can be fixed to " + name + " = " + suggested,
	}
}

func getEnumMemberNameText(sourceFile *ast.SourceFile, member *ast.EnumMember) string {
	if member == nil || member.Name() == nil {
		return ""
	}
	name := member.Name()
	switch name.Kind {
	case ast.KindIdentifier:
		return name.AsIdentifier().Text
	case ast.KindStringLiteral:
		return strconv.Quote(name.AsStringLiteral().Text)
	default:
		r := utils.TrimNodeTextRange(sourceFile, name)
		return sourceFile.Text()[r.Pos():r.End()]
	}
}

var PreferEnumInitializersRule = rule.CreateRule(rule.Rule{
	Name: "prefer-enum-initializers",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
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

					nameText := getEnumMemberNameText(ctx.SourceFile, member)
					if nameText == "" {
						continue
					}

					ctx.ReportNode(memberNode, buildDefineInitializerMessage(nameText))
				}
			},
		}
	},
})
