package no_redeclare

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type scope struct {
	decls map[string]*ast.Node
}

func newScope() *scope {
	return &scope{decls: map[string]*ast.Node{}}
}

func buildRedeclaredMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "redeclared",
		Description: "'" + name + "' is already defined.",
	}
}

func getDeclarationName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		decl := node.AsVariableDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name().AsIdentifier().Text
		}
	case ast.KindFunctionDeclaration:
		decl := node.AsFunctionDeclaration()
		if decl != nil && decl.Name() != nil {
			return decl.Name().Text()
		}
	case ast.KindClassDeclaration:
		decl := node.AsClassDeclaration()
		if decl != nil && decl.Name() != nil {
			return decl.Name().Text()
		}
	case ast.KindInterfaceDeclaration:
		decl := node.AsInterfaceDeclaration()
		if decl != nil && decl.Name() != nil {
			return decl.Name().Text()
		}
	case ast.KindTypeAliasDeclaration:
		decl := node.AsTypeAliasDeclaration()
		if decl != nil && decl.Name() != nil {
			return decl.Name().Text()
		}
	case ast.KindEnumDeclaration:
		decl := node.AsEnumDeclaration()
		if decl != nil && decl.Name() != nil {
			return decl.Name().Text()
		}
	}
	return ""
}

func addDeclaration(ctx rule.RuleContext, node *ast.Node, scopes []*scope) {
	if len(scopes) == 0 {
		return
	}
	name := getDeclarationName(node)
	if name == "" {
		return
	}
	current := scopes[len(scopes)-1]
	if _, exists := current.decls[name]; exists {
		ctx.ReportNode(node, buildRedeclaredMessage(name))
		return
	}
	current.decls[name] = node
}

func isScopeKind(kind ast.Kind) bool {
	switch kind {
	case ast.KindSourceFile, ast.KindBlock, ast.KindModuleBlock, ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindConstructor, ast.KindMethodDeclaration:
		return true
	}
	return false
}

func nearestScopeNode(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if isScopeKind(current.Kind) {
			return current
		}
	}
	return nil
}

var NoRedeclareRule = rule.CreateRule(rule.Rule{
	Name: "no-redeclare",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		scopesByNode := map[*ast.Node]*scope{}
		listeners := rule.RuleListeners{}

		declarationKinds := []ast.Kind{
			ast.KindVariableDeclaration,
			ast.KindFunctionDeclaration,
			ast.KindClassDeclaration,
			ast.KindInterfaceDeclaration,
			ast.KindTypeAliasDeclaration,
			ast.KindEnumDeclaration,
		}
		for _, kind := range declarationKinds {
			k := kind
			listeners[k] = func(node *ast.Node) {
				scopeNode := nearestScopeNode(node.Parent)
				if scopeNode == nil {
					return
				}
				scopeObj, ok := scopesByNode[scopeNode]
				if !ok {
					scopeObj = newScope()
					scopesByNode[scopeNode] = scopeObj
				}
				name := getDeclarationName(node)
				if name == "" {
					return
				}
				if _, exists := scopeObj.decls[name]; exists {
					ctx.ReportNode(node, buildRedeclaredMessage(name))
					return
				}
				scopeObj.decls[name] = node
			}
		}

		return listeners
	},
})
