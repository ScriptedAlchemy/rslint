package no_wrapper_object_types

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

var wrapperTypePreferredNames = map[string]string{
	"BigInt":  "bigint",
	"Boolean": "boolean",
	"Number":  "number",
	"Object":  "object",
	"String":  "string",
	"Symbol":  "symbol",
}

func buildBannedClassTypeMessage(typeName string, preferred string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "bannedClassType",
		Description: "Prefer the primitive type `" + preferred + "` over wrapper type `" + typeName + "`.",
	}
}

func isBuiltinWrapperType(ctx rule.RuleContext, node *ast.Node, typeName string) bool {
	if ctx.Program == nil || ctx.TypeChecker == nil || node == nil {
		return false
	}
	symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
	if symbol == nil || symbol.Name != typeName {
		return false
	}
	for _, declaration := range symbol.Declarations {
		if ast.GetSourceFileOfNode(declaration) == ctx.SourceFile {
			return false
		}
	}
	return utils.IsSymbolFromDefaultLibrary(ctx.Program, symbol)
}

func shouldCheckExpressionWithTypeArguments(node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Kind != ast.KindHeritageClause {
		return false
	}
	clause := node.Parent.AsHeritageClause()
	if clause == nil {
		return false
	}

	switch clause.Token {
	case ast.KindImplementsKeyword:
		return true
	case ast.KindExtendsKeyword:
		if node.Parent.Parent == nil {
			return false
		}
		// `class X extends Number {}` is valid for this rule.
		return node.Parent.Parent.Kind == ast.KindInterfaceDeclaration
	default:
		return false
	}
}

func collectLocalTypeLikeDeclarations(node *ast.Node, names map[string]struct{}) {
	if node == nil {
		return
	}

	switch node.Kind {
	case ast.KindTypeAliasDeclaration, ast.KindInterfaceDeclaration, ast.KindClassDeclaration, ast.KindClassExpression:
		if name := node.Name(); name != nil && name.Kind == ast.KindIdentifier {
			names[name.AsIdentifier().Text] = struct{}{}
		}
	}

	node.ForEachChild(func(child *ast.Node) bool {
		collectLocalTypeLikeDeclarations(child, names)
		return false
	})
}

var NoWrapperObjectTypesRule = rule.CreateRule(rule.Rule{
	Name: "no-wrapper-object-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		localTypeLikeDeclarations := map[string]struct{}{}
		collectLocalTypeLikeDeclarations(ctx.SourceFile.AsNode(), localTypeLikeDeclarations)

		return rule.RuleListeners{
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil || typeRef.TypeName.Kind != ast.KindIdentifier {
					return
				}

				typeName := typeRef.TypeName.AsIdentifier().Text
				preferred, ok := wrapperTypePreferredNames[typeName]
				if !ok {
					return
				}
				if _, locallyDeclared := localTypeLikeDeclarations[typeName]; locallyDeclared {
					return
				}
				if !isBuiltinWrapperType(ctx, typeRef.TypeName, typeName) {
					return
				}

				ctx.ReportNode(node, buildBannedClassTypeMessage(typeName, preferred))
			},
			ast.KindExpressionWithTypeArguments: func(node *ast.Node) {
				if !shouldCheckExpressionWithTypeArguments(node) {
					return
				}

				exprWithTypeArgs := node.AsExpressionWithTypeArguments()
				if exprWithTypeArgs == nil || exprWithTypeArgs.Expression == nil || exprWithTypeArgs.Expression.Kind != ast.KindIdentifier {
					return
				}

				typeName := exprWithTypeArgs.Expression.AsIdentifier().Text
				preferred, ok := wrapperTypePreferredNames[typeName]
				if !ok {
					return
				}
				if _, locallyDeclared := localTypeLikeDeclarations[typeName]; locallyDeclared {
					return
				}
				if !isBuiltinWrapperType(ctx, exprWithTypeArgs.Expression, typeName) {
					return
				}

				ctx.ReportNode(exprWithTypeArgs.Expression, buildBannedClassTypeMessage(typeName, preferred))
			},
		}
	},
})
