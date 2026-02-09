package no_shadow

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

func buildNoShadowMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noShadow",
		Description: "'" + name + "' is already declared in the upper scope.",
	}
}

func declarationName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		n := node.AsVariableDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name().AsIdentifier().Text
		}
	case ast.KindParameter:
		n := node.AsParameterDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name().AsIdentifier().Text
		}
	case ast.KindFunctionDeclaration:
		n := node.AsFunctionDeclaration()
		if n != nil && n.Name() != nil {
			return n.Name().Text()
		}
	}
	return ""
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

var NoShadowRule = rule.CreateRule(rule.Rule{
	Name: "no-shadow",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		declsByScope := map[*ast.Node]*scope{}
		ensureScope := func(scopeNode *ast.Node) *scope {
			if scopeNode == nil {
				return nil
			}
			if s, ok := declsByScope[scopeNode]; ok {
				return s
			}
			s := newScope()
			declsByScope[scopeNode] = s
			return s
		}
		checkAndDeclare := func(node *ast.Node) {
			name := declarationName(node)
			scopeNode := nearestScopeNode(node.Parent)
			if name == "" || scopeNode == nil {
				return
			}
			for current := nearestScopeNode(scopeNode.Parent); current != nil; current = nearestScopeNode(current.Parent) {
				s := declsByScope[current]
				if s != nil && s.decls[name] != nil {
					ctx.ReportNode(node, buildNoShadowMessage(name))
					break
				}
			}
			ensureScope(scopeNode).decls[name] = node
		}

		listeners := rule.RuleListeners{}
		for _, kind := range []ast.Kind{ast.KindVariableDeclaration, ast.KindParameter, ast.KindFunctionDeclaration} {
			k := kind
			listeners[k] = checkAndDeclare
		}

		return listeners
	},
})
