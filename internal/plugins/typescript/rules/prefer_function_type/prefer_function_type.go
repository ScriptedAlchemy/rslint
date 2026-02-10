package prefer_function_type

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildFunctionTypeOverCallableTypeMessage(literalOrInterface string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "functionTypeOverCallableType",
		Description: literalOrInterface + " only has a call signature. Use a function type instead.",
	}
}

func buildUnexpectedThisOnFunctionOnlyInterfaceMessage(interfaceName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpectedThisOnFunctionOnlyInterface",
		Description: "Unexpected `this` in a function-only interface `" + interfaceName + "`.",
	}
}

func hasOnlySingleCallSignature(members []*ast.Node) *ast.Node {
	if len(members) != 1 {
		return nil
	}
	if members[0].Kind != ast.KindCallSignature {
		return nil
	}
	return members[0]
}

func hasOnlyExtendsFunction(interfaceDecl *ast.InterfaceDeclaration) bool {
	if interfaceDecl == nil || interfaceDecl.HeritageClauses == nil {
		return false
	}
	extendsClauses := 0
	for _, clauseNode := range interfaceDecl.HeritageClauses.Nodes {
		clause := clauseNode.AsHeritageClause()
		if clause == nil || clause.Token != ast.KindExtendsKeyword {
			continue
		}
		extendsClauses++
		if clause.Types == nil || len(clause.Types.Nodes) != 1 {
			return false
		}
		extendedType := clause.Types.Nodes[0]
		if extendedType == nil || extendedType.Kind != ast.KindExpressionWithTypeArguments {
			return false
		}
		expr := extendedType.AsExpressionWithTypeArguments()
		if expr == nil || expr.Expression == nil || expr.Expression.Kind != ast.KindIdentifier || expr.Expression.AsIdentifier().Text != "Function" {
			return false
		}
	}
	return extendsClauses == 1
}

func containsDirectThisType(typeNode *ast.Node) *ast.Node {
	if typeNode == nil {
		return nil
	}
	if typeNode.Kind == ast.KindThisType {
		return typeNode
	}
	switch typeNode.Kind {
	case ast.KindUnionType:
		unionType := typeNode.AsUnionTypeNode()
		if unionType == nil || unionType.Types == nil {
			return nil
		}
		for _, t := range unionType.Types.Nodes {
			if t != nil && t.Kind == ast.KindThisType {
				return t
			}
		}
	case ast.KindIntersectionType:
		intersectionType := typeNode.AsIntersectionTypeNode()
		if intersectionType == nil || intersectionType.Types == nil {
			return nil
		}
		for _, t := range intersectionType.Types.Nodes {
			if t != nil && t.Kind == ast.KindThisType {
				return t
			}
		}
	}
	return nil
}

func getThisNodeInCallSignature(callSignature *ast.Node) *ast.Node {
	if callSignature == nil {
		return nil
	}
	params := callSignature.Parameters()
	for _, p := range params {
		param := p.AsParameterDeclaration()
		if param == nil {
			continue
		}
		if thisType := containsDirectThisType(param.Type); thisType != nil {
			return thisType
		}
	}
	if returnType := callSignature.Type(); returnType != nil {
		if thisType := containsDirectThisType(returnType); thisType != nil {
			return thisType
		}
	}
	return nil
}

var PreferFunctionTypeRule = rule.CreateRule(rule.Rule{
	Name: "prefer-function-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		return rule.RuleListeners{
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				interfaceDecl := node.AsInterfaceDeclaration()
				if interfaceDecl == nil || interfaceDecl.Members == nil {
					return
				}

				callSignature := hasOnlySingleCallSignature(interfaceDecl.Members.Nodes)
				if callSignature == nil {
					return
				}

				shouldCheck := interfaceDecl.HeritageClauses == nil || hasOnlyExtendsFunction(interfaceDecl)
				if !shouldCheck {
					return
				}

				if thisNode := getThisNodeInCallSignature(callSignature); thisNode != nil {
					interfaceName := ""
					if interfaceDecl.Name() != nil && interfaceDecl.Name().Kind == ast.KindIdentifier {
						interfaceName = interfaceDecl.Name().AsIdentifier().Text
					}
					ctx.ReportNode(thisNode, buildUnexpectedThisOnFunctionOnlyInterfaceMessage(interfaceName))
					return
				}

				ctx.ReportNode(callSignature, buildFunctionTypeOverCallableTypeMessage("Interface"))
			},
			ast.KindTypeLiteral: func(node *ast.Node) {
				typeLiteral := node.AsTypeLiteralNode()
				if typeLiteral == nil || typeLiteral.Members == nil {
					return
				}
				callSignature := hasOnlySingleCallSignature(typeLiteral.Members.Nodes)
				if callSignature == nil {
					return
				}
				ctx.ReportNode(callSignature, buildFunctionTypeOverCallableTypeMessage("Type literal"))
			},
		}
	},
})
