package no_unnecessary_parameter_property_assignment

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryAssignMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryAssign",
		Description: "Parameter property '" + name + "' is assigned to itself in the constructor.",
	}
}

func parameterPropertyNames(constructor *ast.ConstructorDeclaration) map[string]bool {
	names := map[string]bool{}
	if constructor == nil || constructor.Parameters == nil {
		return names
	}
	for _, p := range constructor.Parameters.Nodes {
		if p == nil || !ast.IsParameter(p) {
			continue
		}
		flags := ast.GetCombinedModifierFlags(p)
		if flags&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) == 0 {
			continue
		}
		param := p.AsParameterDeclaration()
		if param == nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
			continue
		}
		names[param.Name().AsIdentifier().Text] = true
	}
	return names
}

func assignmentPropertyName(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return ""
	}
	binary := node.AsBinaryExpression()
	if binary == nil || binary.Left == nil {
		return ""
	}
	left := binary.Left
	switch left.Kind {
	case ast.KindPropertyAccessExpression:
		propAccess := left.AsPropertyAccessExpression()
		if propAccess == nil || propAccess.Expression == nil || propAccess.Expression.Kind != ast.KindThisKeyword || propAccess.Name() == nil || propAccess.Name().Kind != ast.KindIdentifier {
			return ""
		}
		return propAccess.Name().AsIdentifier().Text
	case ast.KindElementAccessExpression:
		elemAccess := left.AsElementAccessExpression()
		if elemAccess == nil || elemAccess.Expression == nil || elemAccess.Expression.Kind != ast.KindThisKeyword || elemAccess.ArgumentExpression == nil {
			return ""
		}
		if elemAccess.ArgumentExpression.Kind == ast.KindStringLiteral {
			return elemAccess.ArgumentExpression.AsStringLiteral().Text
		}
	}
	return ""
}

func unwrapIdentifier(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindIdentifier:
		return node
	case ast.KindAsExpression:
		return unwrapIdentifier(node.AsAsExpression().Expression)
	case ast.KindNonNullExpression:
		return unwrapIdentifier(node.AsNonNullExpression().Expression)
	default:
		return nil
	}
}

func isUnnecessaryOperator(kind ast.Kind) bool {
	return kind == ast.KindEqualsToken ||
		kind == ast.KindBarBarEqualsToken ||
		kind == ast.KindQuestionQuestionEqualsToken ||
		kind == ast.KindAmpersandAmpersandEqualsToken
}

func isFunctionLike(kind ast.Kind) bool {
	return kind == ast.KindFunctionDeclaration ||
		kind == ast.KindFunctionExpression ||
		kind == ast.KindArrowFunction
}

func findParentFunction(node *ast.Node) *ast.Node {
	for current := node.Parent; current != nil; current = current.Parent {
		if isFunctionLike(current.Kind) {
			return current
		}
	}
	return nil
}

func findNextParentFunction(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if isFunctionLike(current.Kind) {
			return current
		}
	}
	return nil
}

func findParentPropertyDeclaration(node *ast.Node) *ast.Node {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindPropertyDeclaration {
			return current
		}
	}
	return nil
}

func findParentConstructor(node *ast.Node) *ast.Node {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindConstructor {
			return current
		}
	}
	return nil
}

func arrowIIFECall(node *ast.Node) *ast.Node {
	if node == nil || node.Kind != ast.KindArrowFunction {
		return nil
	}
	parent := node.Parent
	if parent != nil && parent.Kind == ast.KindParenthesizedExpression {
		parent = parent.Parent
	}
	if parent != nil && parent.Kind == ast.KindCallExpression {
		return parent
	}
	return nil
}

func isArrowIIFE(node *ast.Node) bool {
	return arrowIIFECall(node) != nil
}

func isInConstructor(node *ast.Node, constructorNode *ast.Node) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindConstructor {
			return current == constructorNode
		}
	}
	return false
}

func walk(node *ast.Node, visit func(*ast.Node)) {
	if node == nil {
		return
	}
	visit(node)
	node.ForEachChild(func(child *ast.Node) bool {
		walk(child, visit)
		return false
	})
}

func classMembers(classNode *ast.Node) []*ast.Node {
	if classNode == nil {
		return nil
	}
	switch classNode.Kind {
	case ast.KindClassDeclaration:
		decl := classNode.AsClassDeclaration()
		if decl != nil && decl.Members != nil {
			return decl.Members.Nodes
		}
	case ast.KindClassExpression:
		decl := classNode.AsClassExpression()
		if decl != nil && decl.Members != nil {
			return decl.Members.Nodes
		}
	}
	return nil
}

func assignmentParamName(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return ""
	}
	binary := node.AsBinaryExpression()
	if binary == nil {
		return ""
	}
	leftName := assignmentPropertyName(node)
	if leftName == "" {
		return ""
	}
	rightNode := unwrapIdentifier(binary.Right)
	if rightNode == nil || rightNode.Kind != ast.KindIdentifier {
		return ""
	}
	rightName := rightNode.AsIdentifier().Text
	if leftName != rightName {
		return ""
	}
	return rightName
}

var NoUnnecessaryParameterPropertyAssignmentRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-parameter-property-assignment",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindConstructor: func(node *ast.Node) {
				constructor := node.AsConstructorDeclaration()
				if constructor == nil || constructor.Body == nil {
					return
				}
				propertyParams := parameterPropertyNames(constructor)
				if len(propertyParams) == 0 {
					return
				}
				paramDeclNodes := map[*ast.Node]bool{}
				if ctx.TypeChecker != nil && constructor.Parameters != nil {
					for _, p := range constructor.Parameters.Nodes {
						if p == nil || !ast.IsParameter(p) {
							continue
						}
						param := p.AsParameterDeclaration()
						if param == nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
							continue
						}
						paramDeclNodes[p] = true
					}
				}

				assignedBeforeConstructor := map[string]bool{}
				for _, member := range classMembers(node.Parent) {
					if member == nil || member.Kind != ast.KindPropertyDeclaration {
						continue
					}
					property := member.AsPropertyDeclaration()
					if property == nil || property.Initializer == nil {
						continue
					}
					walk(property.Initializer, func(current *ast.Node) {
						if current == nil || current.Kind != ast.KindBinaryExpression {
							return
						}
						name := assignmentPropertyName(current)
						if name == "" {
							return
						}
						if findParentConstructor(current) != nil {
							return
						}
						parentFn := findParentFunction(current)
						if parentFn == nil {
							assignedBeforeConstructor[name] = true
							return
						}
						if isArrowIIFE(parentFn) {
							parentProperty := findParentPropertyDeclaration(current)
							if parentProperty == nil {
								return
							}
							parentPropertyDecl := parentProperty.AsPropertyDeclaration()
							if parentPropertyDecl == nil {
								return
							}
							if parentPropertyDecl.Initializer == arrowIIFECall(parentFn) {
								assignedBeforeConstructor[name] = true
							}
						}
					})
				}

				assignedBeforeUnnecessary := map[string]bool{}
				walk(constructor.Body.AsNode(), func(current *ast.Node) {
					if current == nil || current.Kind != ast.KindBinaryExpression || !isInConstructor(current, node) {
						return
					}
					name := assignmentPropertyName(current)
					if name == "" {
						return
					}
					parentFn := findParentFunction(current)
					if parentFn != nil {
						if isArrowIIFE(parentFn) {
							if findNextParentFunction(arrowIIFECall(parentFn)) != nil {
								return
							}
						} else {
							return
						}
					}

					binary := current.AsBinaryExpression()
					if binary == nil {
						return
					}
					if !isUnnecessaryOperator(binary.OperatorToken.Kind) {
						assignedBeforeUnnecessary[name] = true
						return
					}
					paramName := assignmentParamName(current)
					if paramName == "" || !propertyParams[paramName] {
						return
					}
					if ctx.TypeChecker != nil && len(paramDeclNodes) > 0 {
						rightIdent := unwrapIdentifier(binary.Right)
						if rightIdent == nil || rightIdent.Kind != ast.KindIdentifier {
							return
						}
						rightSym := ctx.TypeChecker.GetSymbolAtLocation(rightIdent)
						if rightSym != nil && len(rightSym.Declarations) > 0 {
							isFromParameter := false
							for _, decl := range rightSym.Declarations {
								if paramDeclNodes[decl] || decl.Kind == ast.KindParameter || decl.Kind == ast.KindPropertyDeclaration {
									isFromParameter = true
									break
								}
							}
							if !isFromParameter {
								return
							}
						}
					}
					if assignedBeforeUnnecessary[paramName] || assignedBeforeConstructor[paramName] {
						return
					}
					ctx.ReportNode(current, buildUnnecessaryAssignMessage(paramName))
				})
			},
		}
	},
})
