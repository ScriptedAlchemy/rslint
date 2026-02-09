package no_use_before_define

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type declInfo struct {
	pos  int
	node *ast.Node
}

func buildNoUseBeforeDefineMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noUseBeforeDefine",
		Description: "'" + name + "' was used before it was defined.",
	}
}

func collectDecls(node *ast.Node, mapRef map[string]declInfo) {
	if node == nil {
		return
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		decl := node.AsVariableDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			name := decl.Name().AsIdentifier().Text
			if existing, ok := mapRef[name]; !ok || node.Pos() < existing.pos {
				mapRef[name] = declInfo{pos: node.Pos(), node: node}
			}
		}
	case ast.KindFunctionDeclaration:
		decl := node.AsFunctionDeclaration()
		if decl != nil && decl.Name() != nil {
			name := decl.Name().Text()
			if existing, ok := mapRef[name]; !ok || node.Pos() < existing.pos {
				mapRef[name] = declInfo{pos: node.Pos(), node: node}
			}
		}
	case ast.KindClassDeclaration:
		decl := node.AsClassDeclaration()
		if decl != nil && decl.Name() != nil {
			name := decl.Name().Text()
			if existing, ok := mapRef[name]; !ok || node.Pos() < existing.pos {
				mapRef[name] = declInfo{pos: node.Pos(), node: node}
			}
		}
	}
	node.ForEachChild(func(child *ast.Node) bool {
		collectDecls(child, mapRef)
		return false
	})
}

func isDeclarationIdentifier(node *ast.Node) bool {
	parent := node.Parent
	if parent == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		decl := parent.AsVariableDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindFunctionDeclaration:
		decl := parent.AsFunctionDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindClassDeclaration:
		decl := parent.AsClassDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindParameter:
		decl := parent.AsParameterDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindImportSpecifier, ast.KindImportClause:
		return true
	}
	return false
}

var NoUseBeforeDefineRule = rule.CreateRule(rule.Rule{
	Name: "no-use-before-define",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		decls := map[string]declInfo{}
		if ctx.SourceFile != nil {
			collectDecls(ctx.SourceFile.AsNode(), decls)
		}
		return rule.RuleListeners{
			ast.KindIdentifier: func(node *ast.Node) {
				if isDeclarationIdentifier(node) {
					return
				}
				name := node.AsIdentifier().Text
				info, ok := decls[name]
				if !ok {
					return
				}
				if node.Pos() < info.pos {
					ctx.ReportNode(node, buildNoUseBeforeDefineMessage(name))
				}
			},
		}
	},
})
