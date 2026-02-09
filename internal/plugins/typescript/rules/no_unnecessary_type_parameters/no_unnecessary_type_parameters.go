package no_unnecessary_type_parameters

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryTypeParameterMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryTypeParameter",
		Description: "Type parameter '" + name + "' is never used.",
	}
}

func collectTypeReferences(node *ast.Node, refs map[string]bool) {
	if node == nil {
		return
	}
	if node.Kind == ast.KindTypeReference {
		typeRef := node.AsTypeReferenceNode()
		if typeRef != nil && typeRef.TypeName != nil && typeRef.TypeName.Kind == ast.KindIdentifier {
			refs[typeRef.TypeName.AsIdentifier().Text] = true
		}
	}
	node.ForEachChild(func(child *ast.Node) bool {
		collectTypeReferences(child, refs)
		return false
	})
}

func checkFunctionLike(ctx rule.RuleContext, typeParams *ast.NodeList, params []*ast.Node, returnType *ast.Node) {
	if typeParams == nil || len(typeParams.Nodes) == 0 {
		return
	}
	refs := map[string]bool{}
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

	for _, tpNode := range typeParams.Nodes {
		if tpNode == nil || tpNode.Kind != ast.KindTypeParameter {
			continue
		}
		tp := tpNode.AsTypeParameter()
		if tp == nil || tp.Name() == nil {
			continue
		}
		name := tp.Name().Text()
		if !refs[name] {
			ctx.ReportNode(tpNode, buildUnnecessaryTypeParameterMessage(name))
		}
	}
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
				checkFunctionLike(ctx, fn.TypeParameters, params, fn.Type)
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
				checkFunctionLike(ctx, fn.TypeParameters, params, fn.Type)
			},
		}
	},
})
