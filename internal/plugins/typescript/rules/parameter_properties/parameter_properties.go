package parameter_properties

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type parameterPropertiesOptions struct {
	prefer string
	allow  map[string]bool
}

func parseParameterPropertiesOptions(options any) parameterPropertiesOptions {
	parsed := parameterPropertiesOptions{
		prefer: "class-property",
		allow:  map[string]bool{},
	}
	if options == nil {
		return parsed
	}

	var optionMap map[string]interface{}
	switch typed := options.(type) {
	case []interface{}:
		if len(typed) > 0 {
			optionMap, _ = typed[0].(map[string]interface{})
		}
	case map[string]interface{}:
		optionMap = typed
	}
	if optionMap == nil {
		return parsed
	}

	if prefer, ok := optionMap["prefer"].(string); ok && (prefer == "class-property" || prefer == "parameter-property") {
		parsed.prefer = prefer
	}
	if allowItems, ok := optionMap["allow"].([]interface{}); ok {
		for _, item := range allowItems {
			if value, ok := item.(string); ok && value != "" {
				parsed.allow[value] = true
			}
		}
	}
	return parsed
}

func getModifierCombo(node *ast.Node) string {
	if node == nil {
		return ""
	}
	modifiers := []string{}
	if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) {
		modifiers = append(modifiers, "private")
	} else if ast.HasSyntacticModifier(node, ast.ModifierFlagsProtected) {
		modifiers = append(modifiers, "protected")
	} else if ast.HasSyntacticModifier(node, ast.ModifierFlagsPublic) {
		modifiers = append(modifiers, "public")
	}
	if ast.HasSyntacticModifier(node, ast.ModifierFlagsReadonly) {
		modifiers = append(modifiers, "readonly")
	}
	return strings.Join(modifiers, " ")
}

func isParameterProperty(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindParameter {
		return false
	}
	flags := ast.GetCombinedModifierFlags(node)
	return flags&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0
}

func buildPreferClassPropertyMessage(parameter string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferClassProperty",
		Description: "Property '" + parameter + "' should be declared as a class property instead of a parameter property.",
	}
}

func buildPreferParameterPropertyMessage(parameter string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferParameterProperty",
		Description: "Class property '" + parameter + "' should be converted to a parameter property.",
	}
}

func getTypeText(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return ctx.SourceFile.Text()[r.Pos():r.End()]
}

type constructorAssignmentInfo struct {
	propertyName  string
	parameterName string
	parameterDecl *ast.Node
}

func getSimpleConstructorAssignment(ctor *ast.ConstructorDeclaration) (constructorAssignmentInfo, bool) {
	if ctor == nil || ctor.Body == nil {
		return constructorAssignmentInfo{}, false
	}
	stmts := ctor.Body.Statements()
	if len(stmts) != 1 {
		return constructorAssignmentInfo{}, false
	}
	stmt := stmts[0]
	if stmt == nil || stmt.Kind != ast.KindExpressionStatement {
		return constructorAssignmentInfo{}, false
	}
	exprStmt := stmt.AsExpressionStatement()
	if exprStmt == nil || exprStmt.Expression == nil || exprStmt.Expression.Kind != ast.KindBinaryExpression {
		return constructorAssignmentInfo{}, false
	}
	binaryExpr := exprStmt.Expression.AsBinaryExpression()
	if binaryExpr == nil || binaryExpr.OperatorToken.Kind != ast.KindEqualsToken || binaryExpr.Left == nil || binaryExpr.Right == nil {
		return constructorAssignmentInfo{}, false
	}
	if binaryExpr.Left.Kind != ast.KindPropertyAccessExpression || binaryExpr.Right.Kind != ast.KindIdentifier {
		return constructorAssignmentInfo{}, false
	}
	leftAccess := binaryExpr.Left.AsPropertyAccessExpression()
	if leftAccess == nil || leftAccess.Expression == nil || leftAccess.Expression.Kind != ast.KindThisKeyword || leftAccess.Name() == nil || leftAccess.Name().Kind != ast.KindIdentifier {
		return constructorAssignmentInfo{}, false
	}
	propertyName := leftAccess.Name().AsIdentifier().Text
	parameterName := binaryExpr.Right.AsIdentifier().Text
	if propertyName == "" || parameterName == "" || propertyName != parameterName {
		return constructorAssignmentInfo{}, false
	}

	var parameterDecl *ast.Node
	if ctor.Parameters != nil {
		for _, parameterNode := range ctor.Parameters.Nodes {
			if parameterNode.Kind != ast.KindParameter {
				continue
			}
			parameter := parameterNode.AsParameterDeclaration()
			if parameter == nil || parameter.Name() == nil || parameter.Name().Kind != ast.KindIdentifier {
				continue
			}
			if parameter.DotDotDotToken != nil {
				continue
			}
			if isParameterProperty(parameterNode) {
				continue
			}
			if parameter.Name().AsIdentifier().Text == parameterName {
				parameterDecl = parameterNode
				break
			}
		}
	}
	if parameterDecl == nil {
		return constructorAssignmentInfo{}, false
	}

	return constructorAssignmentInfo{
		propertyName:  propertyName,
		parameterName: parameterName,
		parameterDecl: parameterDecl,
	}, true
}

func getClassMembers(node *ast.Node) []*ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindClassDeclaration:
		classDecl := node.AsClassDeclaration()
		if classDecl != nil && classDecl.Members != nil {
			return classDecl.Members.Nodes
		}
	case ast.KindClassExpression:
		classExpr := node.AsClassExpression()
		if classExpr != nil && classExpr.Members != nil {
			return classExpr.Members.Nodes
		}
	}
	return nil
}

var ParameterPropertiesRule = rule.CreateRule(rule.Rule{
	Name: "parameter-properties",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		parsedOptions := parseParameterPropertiesOptions(options)

		reportConstructorParameterProperties := func(node *ast.Node) {
			ctor := node.AsConstructorDeclaration()
			if ctor == nil || ctor.Parameters == nil {
				return
			}
			for _, parameterNode := range ctor.Parameters.Nodes {
				if !isParameterProperty(parameterNode) {
					continue
				}
				parameter := parameterNode.AsParameterDeclaration()
				if parameter == nil || parameter.Name() == nil || parameter.Name().Kind != ast.KindIdentifier {
					continue
				}
				combo := getModifierCombo(parameterNode)
				if parsedOptions.allow[combo] {
					continue
				}
				ctx.ReportNode(parameterNode, buildPreferClassPropertyMessage(parameter.Name().AsIdentifier().Text))
			}
		}

		reportClassPropertyForConstructorAssignment := func(classNode *ast.Node) {
			members := getClassMembers(classNode)
			if len(members) == 0 {
				return
			}

			var assignmentInfo constructorAssignmentInfo
			foundConstructorAssignment := false
			for _, member := range members {
				if member.Kind != ast.KindConstructor {
					continue
				}
				ctor := member.AsConstructorDeclaration()
				if ctor == nil || ctor.Body == nil {
					continue
				}
				info, ok := getSimpleConstructorAssignment(ctor)
				if !ok {
					continue
				}
				assignmentInfo = info
				foundConstructorAssignment = true
				break
			}
			if !foundConstructorAssignment {
				return
			}

			parameterDecl := assignmentInfo.parameterDecl.AsParameterDeclaration()
			parameterType := ""
			if parameterDecl != nil && parameterDecl.Type != nil {
				parameterType = getTypeText(ctx, parameterDecl.Type)
			}

			for _, member := range members {
				if member == nil || member.Kind != ast.KindPropertyDeclaration {
					continue
				}
				if ast.HasSyntacticModifier(member, ast.ModifierFlagsStatic) {
					continue
				}
				property := member.AsPropertyDeclaration()
				if property == nil || property.Name() == nil || property.Name().Kind != ast.KindIdentifier {
					continue
				}
				if property.Initializer != nil {
					continue
				}
				propertyName := property.Name().AsIdentifier().Text
				if propertyName != assignmentInfo.propertyName {
					continue
				}
				combo := getModifierCombo(member)
				if parsedOptions.allow[combo] {
					continue
				}

				propertyType := ""
				if property.Type != nil {
					propertyType = getTypeText(ctx, property.Type)
				}

				// Preserve rule behavior: only straightforward, type-compatible
				// cases should be transformed into parameter properties.
				if (propertyType == "" && parameterType != "") || (propertyType != "" && parameterType == "") {
					continue
				}
				if propertyType != "" && parameterType != "" && propertyType != parameterType {
					continue
				}

				ctx.ReportNode(member, buildPreferParameterPropertyMessage(propertyName))
			}
		}

		if parsedOptions.prefer == "parameter-property" {
			return rule.RuleListeners{
				ast.KindClassDeclaration: reportClassPropertyForConstructorAssignment,
				ast.KindClassExpression:  reportClassPropertyForConstructorAssignment,
			}
		}

		return rule.RuleListeners{
			ast.KindConstructor: reportConstructorParameterProperties,
		}
	},
})
