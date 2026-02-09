package no_deprecated

import (
	"regexp"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

var deprecatedDeclRe = regexp.MustCompile(`(?s)@deprecated[\s\S]*?(?:const|let|var|function|class|interface|type|enum)\s+([A-Za-z_][A-Za-z0-9_]*)`)

func buildDeprecatedMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "deprecated",
		Description: "`" + name + "` is deprecated.",
	}
}

func isDeclarationIdentifier(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	switch node.Parent.Kind {
	case ast.KindVariableDeclaration:
		parent := node.Parent.AsVariableDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindFunctionDeclaration:
		parent := node.Parent.AsFunctionDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindClassDeclaration:
		parent := node.Parent.AsClassDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindInterfaceDeclaration:
		parent := node.Parent.AsInterfaceDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindTypeAliasDeclaration:
		parent := node.Parent.AsTypeAliasDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindEnumDeclaration:
		parent := node.Parent.AsEnumDeclaration()
		return parent != nil && parent.Name() == node
	}
	return false
}

var NoDeprecatedRule = rule.CreateRule(rule.Rule{
	Name: "no-deprecated",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		deprecatedNames := map[string]bool{}
		if ctx.SourceFile != nil {
			matches := deprecatedDeclRe.FindAllStringSubmatch(ctx.SourceFile.Text(), -1)
			for _, m := range matches {
				if len(m) > 1 {
					deprecatedNames[m[1]] = true
				}
			}
		}
		return rule.RuleListeners{
			ast.KindIdentifier: func(node *ast.Node) {
				if isDeclarationIdentifier(node) {
					return
				}
				name := node.AsIdentifier().Text
				if deprecatedNames[name] {
					ctx.ReportNode(node, buildDeprecatedMessage(name))
				}
			},
		}
	},
})
