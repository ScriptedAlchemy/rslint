package no_unnecessary_type_parameters

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildSoleMessage(name string, count int, descriptor string) rule.RuleMessage {
	uses := "never used"
	if count == 1 {
		uses = "used only once"
	}
	return rule.RuleMessage{
		Id:          "sole",
		Description: "Type parameter '" + name + "' is " + uses + " in the " + descriptor + " signature.",
	}
}

func collectTypeReferences(node *ast.Node, refs map[string]int) {
	if node == nil {
		return
	}
	if node.Kind == ast.KindIdentifier && ast.IsPartOfTypeNode(node) {
		refs[node.AsIdentifier().Text]++
	}
	if node.Kind == ast.KindTypeReference {
		typeRef := node.AsTypeReferenceNode()
		if typeRef != nil && typeRef.TypeName != nil && typeRef.TypeName.Kind == ast.KindIdentifier {
			refs[typeRef.TypeName.AsIdentifier().Text]++
		}
	}
	node.ForEachChild(func(child *ast.Node) bool {
		collectTypeReferences(child, refs)
		return false
	})
}

func implicitReturnUsesTypeParam(params []*ast.Node, body *ast.BlockOrExpression, typeParamName string) bool {
	if body == nil {
		return false
	}

	typedParams := map[string]bool{}
	for _, param := range params {
		if param == nil || param.Kind != ast.KindParameter {
			continue
		}
		decl := param.AsParameterDeclaration()
		if decl == nil || decl.Type == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
			continue
		}
		refs := map[string]int{}
		collectTypeReferences(decl.Type, refs)
		if refs[typeParamName] > 0 {
			typedParams[decl.Name().AsIdentifier().Text] = true
		}
	}
	if len(typedParams) == 0 {
		return false
	}

	if body.Kind != ast.KindBlock {
		expr := body.AsNode()
		return expr != nil && expr.Kind == ast.KindIdentifier && typedParams[expr.AsIdentifier().Text]
	}

	block := body.AsBlock()
	if block == nil || block.Statements == nil {
		return false
	}
	for _, stmt := range block.Statements.Nodes {
		if stmt == nil || stmt.Kind != ast.KindReturnStatement {
			continue
		}
		returnStmt := stmt.AsReturnStatement()
		if returnStmt == nil || returnStmt.Expression == nil || returnStmt.Expression.Kind != ast.KindIdentifier {
			continue
		}
		if typedParams[returnStmt.Expression.AsIdentifier().Text] {
			return true
		}
	}
	return false
}

func checkFunctionLike(ctx rule.RuleContext, typeParams []*ast.Node, params []*ast.Node, returnType *ast.Node, body *ast.BlockOrExpression) {
	if len(typeParams) == 0 {
		return
	}
	refs := map[string]int{}
	for _, param := range params {
		if param == nil {
			continue
		}
		p := param.AsParameterDeclaration()
		if p != nil {
			collectTypeReferences(p.Type, refs)
		}
	}
	collectTypeReferences(returnType, refs)
	if body != nil {
		collectTypeReferences(body.AsNode(), refs)
	}

	for _, tpNode := range typeParams {
		if tpNode == nil || tpNode.Kind != ast.KindTypeParameter {
			continue
		}
		tp := tpNode.AsTypeParameter()
		if tp == nil || tp.Name() == nil {
			continue
		}
		name := tp.Name().Text()
		count := refs[name]
		if count <= 1 && implicitReturnUsesTypeParam(params, body, name) {
			count++
		}
		if count <= 1 {
			ctx.ReportNode(tpNode, buildSoleMessage(name, count, "function"))
		}
	}
}

func checkClassLike(ctx rule.RuleContext, typeParams []*ast.Node, members []*ast.Node) {
	if len(typeParams) == 0 || len(members) == 0 {
		return
	}

	refs := map[string]int{}
	for _, member := range members {
		collectTypeReferences(member, refs)
	}

	for _, tpNode := range typeParams {
		if tpNode == nil || tpNode.Kind != ast.KindTypeParameter {
			continue
		}
		tp := tpNode.AsTypeParameter()
		if tp == nil || tp.Name() == nil {
			continue
		}
		name := tp.Name().Text()
		count := refs[name]
		if count <= 1 {
			ctx.ReportNode(tpNode, buildSoleMessage(name, count, "class"))
		}
	}
}

func getFunctionLikeTypeParameters(ctx rule.RuleContext, node *ast.Node) []*ast.Node {
	if node == nil {
		return nil
	}
	if params := node.TypeParameters(); len(params) > 0 {
		return params
	}
	if ctx.TypeChecker == nil {
		return nil
	}

	nodeType := ctx.TypeChecker.GetTypeAtLocation(node)
	if nodeType == nil {
		return nil
	}
	signatures := utils.GetCallSignatures(ctx.TypeChecker, nodeType)
	if len(signatures) == 0 {
		return nil
	}
	decl := checker.Signature_declaration(signatures[0])
	if decl == nil {
		return nil
	}
	return decl.TypeParameters()
}

var NoUnnecessaryTypeParametersRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-parameters",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				fn := node.AsFunctionDeclaration()
				if fn == nil {
					return
				}
				params := []*ast.Node{}
				if fn.Parameters != nil {
					params = fn.Parameters.Nodes
				}
				checkFunctionLike(ctx, getFunctionLikeTypeParameters(ctx, node), params, fn.Type, fn.Body)
			},
			ast.KindFunctionExpression: func(node *ast.Node) {
				fn := node.AsFunctionExpression()
				if fn == nil {
					return
				}
				params := []*ast.Node{}
				if fn.Parameters != nil {
					params = fn.Parameters.Nodes
				}
				checkFunctionLike(ctx, getFunctionLikeTypeParameters(ctx, node), params, fn.Type, fn.Body)
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				fn := node.AsArrowFunction()
				if fn == nil {
					return
				}
				params := []*ast.Node{}
				if fn.Parameters != nil {
					params = fn.Parameters.Nodes
				}
				checkFunctionLike(ctx, getFunctionLikeTypeParameters(ctx, node), params, fn.Type, fn.Body)
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				fn := node.AsMethodDeclaration()
				if fn == nil {
					return
				}
				params := []*ast.Node{}
				if fn.Parameters != nil {
					params = fn.Parameters.Nodes
				}
				checkFunctionLike(ctx, getFunctionLikeTypeParameters(ctx, node), params, fn.Type, fn.Body)
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				classDecl := node.AsClassDeclaration()
				if classDecl == nil || classDecl.Members == nil {
					return
				}
				checkClassLike(ctx, node.TypeParameters(), classDecl.Members.Nodes)
			},
			ast.KindClassExpression: func(node *ast.Node) {
				classExpr := node.AsClassExpression()
				if classExpr == nil || classExpr.Members == nil {
					return
				}
				checkClassLike(ctx, node.TypeParameters(), classExpr.Members.Nodes)
			},
		}
	},
})
