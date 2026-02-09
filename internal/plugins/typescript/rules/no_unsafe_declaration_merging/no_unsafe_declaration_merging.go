package no_unsafe_declaration_merging

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnsafeMergingMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeMerging",
		Description: "Unsafe declaration merging between class and interface '" + name + "'.",
	}
}

var NoUnsafeDeclarationMergingRule = rule.CreateRule(rule.Rule{
	Name: "no-unsafe-declaration-merging",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		classes := map[string]*ast.Node{}
		interfaces := map[string]*ast.Node{}
		return rule.RuleListeners{
			ast.KindClassDeclaration: func(node *ast.Node) {
				classDecl := node.AsClassDeclaration()
				if classDecl == nil || classDecl.Name() == nil {
					return
				}
				name := classDecl.Name().Text()
				classes[name] = node
				if interfaceNode, ok := interfaces[name]; ok {
					ctx.ReportNode(node, buildUnsafeMergingMessage(name))
					ctx.ReportNode(interfaceNode, buildUnsafeMergingMessage(name))
				}
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				iface := node.AsInterfaceDeclaration()
				if iface == nil || iface.Name() == nil {
					return
				}
				name := iface.Name().Text()
				interfaces[name] = node
				if classNode, ok := classes[name]; ok {
					ctx.ReportNode(node, buildUnsafeMergingMessage(name))
					ctx.ReportNode(classNode, buildUnsafeMergingMessage(name))
				}
			},
		}
	},
})
