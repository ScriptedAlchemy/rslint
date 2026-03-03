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
		type scopeEntries struct {
			classes    map[string]*ast.Node
			interfaces map[string]*ast.Node
		}
		scopes := map[*ast.Node]*scopeEntries{}

		isScopeKind := func(kind ast.Kind) bool {
			switch kind {
			case ast.KindSourceFile, ast.KindModuleBlock, ast.KindBlock, ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction:
				return true
			}
			return false
		}
		nearestScopeNode := func(node *ast.Node) *ast.Node {
			for current := node; current != nil; current = current.Parent {
				if isScopeKind(current.Kind) {
					return current
				}
			}
			return nil
		}
		getScope := func(node *ast.Node) *scopeEntries {
			scopeNode := nearestScopeNode(node.Parent)
			if scopeNode == nil {
				return nil
			}
			scope := scopes[scopeNode]
			if scope == nil {
				scope = &scopeEntries{
					classes:    map[string]*ast.Node{},
					interfaces: map[string]*ast.Node{},
				}
				scopes[scopeNode] = scope
			}
			return scope
		}

		return rule.RuleListeners{
			ast.KindClassDeclaration: func(node *ast.Node) {
				scope := getScope(node)
				if scope == nil {
					return
				}
				classDecl := node.AsClassDeclaration()
				if classDecl == nil || classDecl.Name() == nil {
					return
				}
				name := classDecl.Name().Text()
				scope.classes[name] = node
				if interfaceNode, ok := scope.interfaces[name]; ok {
					ctx.ReportNode(classDecl.Name(), buildUnsafeMergingMessage(name))
					if iface := interfaceNode.AsInterfaceDeclaration(); iface != nil && iface.Name() != nil {
						ctx.ReportNode(iface.Name(), buildUnsafeMergingMessage(name))
					}
				}
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				scope := getScope(node)
				if scope == nil {
					return
				}
				iface := node.AsInterfaceDeclaration()
				if iface == nil || iface.Name() == nil {
					return
				}
				name := iface.Name().Text()
				scope.interfaces[name] = node
				if classNode, ok := scope.classes[name]; ok {
					ctx.ReportNode(iface.Name(), buildUnsafeMergingMessage(name))
					if classDecl := classNode.AsClassDeclaration(); classDecl != nil && classDecl.Name() != nil {
						ctx.ReportNode(classDecl.Name(), buildUnsafeMergingMessage(name))
					}
				}
			},
		}
	},
})
