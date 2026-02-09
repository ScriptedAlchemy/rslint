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

func assignmentParamName(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return ""
	}
	binary := node.AsBinaryExpression()
	if binary == nil || binary.OperatorToken.Kind != ast.KindEqualsToken {
		return ""
	}
	if binary.Left == nil || binary.Left.Kind != ast.KindPropertyAccessExpression {
		return ""
	}
	left := binary.Left.AsPropertyAccessExpression()
	if left == nil || left.Expression == nil || left.Expression.Kind != ast.KindThisKeyword || left.Name() == nil {
		return ""
	}
	if binary.Right == nil || binary.Right.Kind != ast.KindIdentifier {
		return ""
	}
	rightName := binary.Right.AsIdentifier().Text
	leftName := left.Name().AsIdentifier().Text
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
				for _, stmt := range constructor.Body.Statements() {
					if stmt == nil || stmt.Kind != ast.KindExpressionStatement {
						continue
					}
					exprStmt := stmt.AsExpressionStatement()
					if exprStmt == nil {
						continue
					}
					name := assignmentParamName(exprStmt.Expression)
					if name == "" || !propertyParams[name] {
						continue
					}
					ctx.ReportNode(exprStmt.Expression, buildUnnecessaryAssignMessage(name))
				}
			},
		}
	},
})
