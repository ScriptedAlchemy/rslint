package prefer_function_type

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildFunctionTypeOverCallableTypeMessage(kind string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "functionTypeOverCallableType",
		Description: kind + " only has a call signature, you should use a function type instead.",
	}
}

func buildUnexpectedThisOnFunctionOnlyInterfaceMessage(interfaceName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpectedThisOnFunctionOnlyInterface",
		Description: "`this` refers to the function type '" + interfaceName + "'.",
	}
}

func hasDisqualifyingInterfaceExtends(node *ast.InterfaceDeclaration) bool {
	if node == nil || node.HeritageClauses == nil {
		return false
	}
	extendsTypes := []*ast.Node{}
	for _, clause := range node.HeritageClauses.Nodes {
		h := clause.AsHeritageClause()
		if h == nil || h.Token != ast.KindExtendsKeyword || h.Types == nil {
			continue
		}
		extendsTypes = append(extendsTypes, h.Types.Nodes...)
	}
	if len(extendsTypes) == 0 {
		return false
	}
	if len(extendsTypes) != 1 {
		return true
	}
	extendsType := extendsTypes[0]
	if extendsType == nil {
		return true
	}
	if extendsType.Kind == ast.KindExpressionWithTypeArguments {
		exprWithTypeArgs := extendsType.AsExpressionWithTypeArguments()
		if exprWithTypeArgs == nil || exprWithTypeArgs.Expression == nil {
			return true
		}
		if exprWithTypeArgs.Expression.Kind == ast.KindIdentifier && exprWithTypeArgs.Expression.AsIdentifier().Text == "Function" {
			return false
		}
		return true
	}
	if extendsType.Kind == ast.KindIdentifier && extendsType.AsIdentifier().Text == "Function" {
		return false
	}
	return false
}

func isCallableSignatureMember(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == ast.KindCallSignature || node.Kind == ast.KindConstructSignature
}

func findFirstThisTypeOutsideNestedTypeLiterals(node *ast.Node) *ast.Node {
	var found *ast.Node
	var walk func(*ast.Node, int)
	walk = func(current *ast.Node, typeLiteralDepth int) {
		if current == nil || found != nil {
			return
		}

		nextDepth := typeLiteralDepth
		if current.Kind == ast.KindTypeLiteral {
			nextDepth++
		}
		if current.Kind == ast.KindThisType && typeLiteralDepth == 0 {
			found = current
			return
		}
		current.ForEachChild(func(child *ast.Node) bool {
			walk(child, nextDepth)
			return found != nil
		})
	}

	walk(node, 0)
	return found
}

var PreferFunctionTypeRule = rule.CreateRule(rule.Rule{
	Name: "prefer-function-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				iface := node.AsInterfaceDeclaration()
				if iface == nil || iface.Members == nil || len(iface.Members.Nodes) != 1 {
					return
				}
				if hasDisqualifyingInterfaceExtends(iface) {
					return
				}
				if !isCallableSignatureMember(iface.Members.Nodes[0]) {
					return
				}
				if thisType := findFirstThisTypeOutsideNestedTypeLiterals(iface.Members.Nodes[0]); thisType != nil {
					name := ""
					if iface.Name() != nil {
						name = iface.Name().Text()
					}
					ctx.ReportNode(thisType, buildUnexpectedThisOnFunctionOnlyInterfaceMessage(name))
					return
				}
				ctx.ReportNode(iface.Members.Nodes[0], buildFunctionTypeOverCallableTypeMessage("Interface"))
			},
			ast.KindTypeLiteral: func(node *ast.Node) {
				literal := node.AsTypeLiteralNode()
				if literal == nil || literal.Members == nil || len(literal.Members.Nodes) != 1 {
					return
				}
				if !isCallableSignatureMember(literal.Members.Nodes[0]) {
					return
				}
				ctx.ReportNode(literal.Members.Nodes[0], buildFunctionTypeOverCallableTypeMessage("Type literal"))
			},
		}
	},
})
