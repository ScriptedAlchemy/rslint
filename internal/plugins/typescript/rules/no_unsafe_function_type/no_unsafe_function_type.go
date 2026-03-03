package no_unsafe_function_type

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildBannedFunctionTypeMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "bannedFunctionType",
		Description: "The `Function` type accepts any function-like value. Prefer explicitly defining any function parameters and return type.",
	}
}

func isFunctionIdentifier(node *ast.Node) bool {
	return node != nil && node.Kind == ast.KindIdentifier && node.AsIdentifier().Text == "Function"
}

var NoUnsafeFunctionTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-unsafe-function-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
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
		declaredNamesByScope := map[*ast.Node]map[string]bool{}
		addDeclaredName := func(node *ast.Node, name string) {
			if name == "" {
				return
			}
			scopeNode := nearestScopeNode(node.Parent)
			if scopeNode == nil {
				return
			}
			scopeMap := declaredNamesByScope[scopeNode]
			if scopeMap == nil {
				scopeMap = map[string]bool{}
				declaredNamesByScope[scopeNode] = scopeMap
			}
			scopeMap[name] = true
		}
		isShadowedInScope := func(node *ast.Node, name string) bool {
			for scopeNode := nearestScopeNode(node.Parent); scopeNode != nil; scopeNode = nearestScopeNode(scopeNode.Parent) {
				scopeMap := declaredNamesByScope[scopeNode]
				if scopeMap != nil && scopeMap[name] {
					return true
				}
			}
			return false
		}

		listeners := rule.RuleListeners{
			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				decl := node.AsTypeAliasDeclaration()
				if decl != nil && decl.Name() != nil {
					addDeclaredName(node, decl.Name().Text())
				}
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				decl := node.AsInterfaceDeclaration()
				if decl != nil && decl.Name() != nil {
					addDeclaredName(node, decl.Name().Text())
				}
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				decl := node.AsClassDeclaration()
				if decl != nil && decl.Name() != nil {
					addDeclaredName(node, decl.Name().Text())
				}
			},
			ast.KindEnumDeclaration: func(node *ast.Node) {
				decl := node.AsEnumDeclaration()
				if decl != nil && decl.Name() != nil {
					addDeclaredName(node, decl.Name().Text())
				}
			},
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				decl := node.AsFunctionDeclaration()
				if decl != nil && decl.Name() != nil {
					addDeclaredName(node, decl.Name().Text())
				}
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				decl := node.AsVariableDeclaration()
				if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
					addDeclaredName(node, decl.Name().AsIdentifier().Text)
				}
			},
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil {
					return
				}
				if isFunctionIdentifier(typeRef.TypeName) {
					if isShadowedInScope(node, "Function") {
						return
					}
					ctx.ReportNode(node, buildBannedFunctionTypeMessage())
				}
			},
			ast.KindExpressionWithTypeArguments: func(node *ast.Node) {
				expr := node.AsExpressionWithTypeArguments()
				if expr == nil || expr.Expression == nil {
					return
				}
				if isFunctionIdentifier(expr.Expression) {
					if isShadowedInScope(node, "Function") {
						return
					}
					ctx.ReportNode(node, buildBannedFunctionTypeMessage())
				}
			},
		}
		return listeners
	},
})
