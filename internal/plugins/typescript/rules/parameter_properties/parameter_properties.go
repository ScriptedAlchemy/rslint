package parameter_properties

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ParameterPropertiesOptions struct {
	Allow  []string `json:"allow"`
	Prefer string   `json:"prefer"`
}

func parseOptions(options any) ParameterPropertiesOptions {
	opts := ParameterPropertiesOptions{
		Allow:  []string{},
		Prefer: "class-property",
	}
	if options == nil {
		return opts
	}
	var optsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		optsMap, _ = arr[0].(map[string]interface{})
	} else {
		optsMap, _ = options.(map[string]interface{})
	}
	if optsMap == nil {
		return opts
	}
	if v, ok := optsMap["prefer"].(string); ok {
		opts.Prefer = v
	}
	if v, ok := optsMap["allow"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				opts.Allow = append(opts.Allow, s)
			}
		}
	}
	return opts
}

func buildPreferClassPropertyMessage(parameter string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferClassProperty",
		Description: "Property " + parameter + " should be declared as a class property.",
	}
}

func buildPreferParameterPropertyMessage(parameter string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferParameterProperty",
		Description: "Property " + parameter + " should be declared as a parameter property.",
	}
}

func isInConstructor(node *ast.Node) bool {
	if node == nil {
		return false
	}
	parent := node.Parent
	for parent != nil {
		if parent.Kind == ast.KindConstructor {
			return true
		}
		if ast.IsFunctionLike(parent) {
			return false
		}
		parent = parent.Parent
	}
	return false
}

func modifierString(node *ast.Node) string {
	if node == nil {
		return ""
	}
	flags := ast.GetCombinedModifierFlags(node)
	parts := make([]string, 0, 2)
	if flags&ast.ModifierFlagsPrivate != 0 {
		parts = append(parts, "private")
	} else if flags&ast.ModifierFlagsProtected != 0 {
		parts = append(parts, "protected")
	} else if flags&ast.ModifierFlagsPublic != 0 {
		parts = append(parts, "public")
	}
	if flags&ast.ModifierFlagsReadonly != 0 {
		parts = append(parts, "readonly")
	}
	return strings.Join(parts, " ")
}

func allowMap(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		if value == "" {
			continue
		}
		out[value] = true
	}
	return out
}

func parameterName(node *ast.Node) (string, bool) {
	if node == nil || !ast.IsParameter(node) {
		return "", false
	}
	param := node.AsParameterDeclaration()
	if param == nil || param.Name() == nil || param.DotDotDotToken != nil {
		return "", false
	}
	switch param.Name().Kind {
	case ast.KindIdentifier:
		return param.Name().AsIdentifier().Text, true
	case ast.KindArrayBindingPattern, ast.KindObjectBindingPattern:
		return "", false
	default:
		return "", false
	}
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
		expr := classNode.AsClassExpression()
		if expr != nil && expr.Members != nil {
			return expr.Members.Nodes
		}
	}
	return nil
}

func typeAnnotationText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(sourceFile, node)
	start := r.Pos()
	end := r.End()
	if start < 0 || end > len(sourceFile.Text()) || start >= end {
		return ""
	}
	return sourceFile.Text()[start:end]
}

func typeAnnotationsMatch(sourceFile *ast.SourceFile, classProperty *ast.PropertyDeclaration, constructorParameter *ast.ParameterDeclaration) bool {
	if classProperty == nil || constructorParameter == nil {
		return false
	}
	if classProperty.Type == nil || constructorParameter.Type == nil {
		return classProperty.Type == constructorParameter.Type
	}
	return typeAnnotationText(sourceFile, classProperty.Type) == typeAnnotationText(sourceFile, constructorParameter.Type)
}

type propertyNodes struct {
	classProperty       *ast.Node
	constructorAssign   *ast.Node
	constructorParamRef *ast.Node
}

func collectParameterPropertyCandidates(sourceFile *ast.SourceFile, classNode *ast.Node, allow map[string]bool) map[string]*propertyNodes {
	byName := map[string]*propertyNodes{}
	get := func(name string) *propertyNodes {
		if existing, ok := byName[name]; ok {
			return existing
		}
		created := &propertyNodes{}
		byName[name] = created
		return created
	}

	for _, member := range classMembers(classNode) {
		if member == nil {
			continue
		}
		switch member.Kind {
		case ast.KindPropertyDeclaration:
			property := member.AsPropertyDeclaration()
			if property == nil || property.Name() == nil || property.Name().Kind != ast.KindIdentifier || property.Initializer != nil {
				continue
			}
			if allow[modifierString(member)] {
				continue
			}
			get(property.Name().AsIdentifier().Text).classProperty = member
		case ast.KindConstructor:
			constructor := member.AsConstructorDeclaration()
			if constructor == nil {
				continue
			}
			if constructor.Parameters != nil {
				for _, paramNode := range constructor.Parameters.Nodes {
					name, ok := parameterName(paramNode)
					if !ok {
						continue
					}
					get(name).constructorParamRef = paramNode
				}
			}
			if constructor.Body == nil {
				continue
			}
			for _, stmt := range constructor.Body.Statements() {
				if stmt == nil || stmt.Kind != ast.KindExpressionStatement {
					break
				}
				exprStmt := stmt.AsExpressionStatement()
				if exprStmt == nil || exprStmt.Expression == nil || exprStmt.Expression.Kind != ast.KindBinaryExpression {
					break
				}
				assignment := exprStmt.Expression.AsBinaryExpression()
				if assignment == nil || assignment.OperatorToken.Kind != ast.KindEqualsToken || assignment.Left == nil || assignment.Right == nil {
					break
				}
				if assignment.Left.Kind != ast.KindPropertyAccessExpression {
					break
				}
				left := assignment.Left.AsPropertyAccessExpression()
				if left == nil || left.Expression == nil || left.Expression.Kind != ast.KindThisKeyword || left.Name() == nil || left.Name().Kind != ast.KindIdentifier {
					break
				}
				if assignment.Right.Kind != ast.KindIdentifier {
					break
				}
				get(assignment.Right.AsIdentifier().Text).constructorAssign = exprStmt.Expression
			}
		}
	}

	_ = sourceFile
	return byName
}

var ParameterPropertiesRule = rule.CreateRule(rule.Rule{
	Name: "parameter-properties",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		allowed := allowMap(opts.Allow)

		checkClass := func(classNode *ast.Node) {
			nodesByName := collectParameterPropertyCandidates(ctx.SourceFile, classNode, allowed)
			for name, nodes := range nodesByName {
				if nodes.classProperty == nil || nodes.constructorAssign == nil || nodes.constructorParamRef == nil {
					continue
				}
				classProperty := nodes.classProperty.AsPropertyDeclaration()
				constructorParam := nodes.constructorParamRef.AsParameterDeclaration()
				if !typeAnnotationsMatch(ctx.SourceFile, classProperty, constructorParam) {
					continue
				}
				ctx.ReportNode(nodes.classProperty, buildPreferParameterPropertyMessage(name))
			}
		}

		return rule.RuleListeners{
			ast.KindParameter: func(node *ast.Node) {
				if opts.Prefer != "class-property" {
					return
				}
				if !isInConstructor(node) {
					return
				}
				modifiers := modifierString(node)
				if modifiers == "" || allowed[modifiers] {
					return
				}
				name, ok := parameterName(node)
				if !ok {
					return
				}
				ctx.ReportNode(node, buildPreferClassPropertyMessage(name))
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				if opts.Prefer != "parameter-property" {
					return
				}
				checkClass(node)
			},
			ast.KindClassExpression: func(node *ast.Node) {
				if opts.Prefer != "parameter-property" {
					return
				}
				checkClass(node)
			},
		}
	},
})
