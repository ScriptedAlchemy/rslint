package no_useless_default_assignment

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type noUselessDefaultAssignmentOptions struct {
	AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing *bool `json:"allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing,omitempty"`
}

func parseOptions(options any) noUselessDefaultAssignmentOptions {
	parsed := noUselessDefaultAssignmentOptions{
		AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing: utils.Ref(false),
	}
	if options == nil {
		return parsed
	}

	if raw, ok := options.([]any); ok && len(raw) > 0 {
		options = raw[0]
	}
	if raw, ok := options.(map[string]any); ok {
		if allow, ok := raw["allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing"].(bool); ok {
			parsed.AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing = utils.Ref(allow)
		}
	}

	return parsed
}

func buildNoStrictNullCheckMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noStrictNullCheck",
		Description: "This rule requires the `strictNullChecks` compiler option to be turned on to function correctly.",
	}
}

func buildPreferOptionalSyntaxMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferOptionalSyntax",
		Description: "Using `= undefined` to make a parameter optional adds unnecessary runtime logic. Use the `?` optional syntax instead.",
	}
}

func buildUselessDefaultAssignmentMessage(kind string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "uselessDefaultAssignment",
		Description: "Default value is useless because the " + kind + " is not optional.",
	}
}

func buildUselessUndefinedMessage(kind string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "uselessUndefined",
		Description: "Default value is useless because it is undefined. Optional " + kind + "s are already undefined by default.",
	}
}

func isUndefinedIdentifier(node *ast.Node) bool {
	return node != nil && node.Kind == ast.KindIdentifier && node.AsIdentifier() != nil && node.AsIdentifier().Text == "undefined"
}

func canBeUndefined(t *checker.Type) bool {
	if t == nil {
		return false
	}
	if utils.IsTypeAnyType(t) || utils.IsTypeUnknownType(t) {
		return true
	}
	for _, part := range utils.UnionTypeParts(t) {
		if utils.IsTypeFlagSet(part, checker.TypeFlagsUndefined) {
			return true
		}
	}
	return false
}

func parameterIndexInParent(param *ast.Node) int {
	if param == nil || param.Parent == nil {
		return -1
	}
	params := param.Parent.Parameters()
	for idx, current := range params {
		if current == param {
			return idx
		}
	}
	return -1
}

func parameterDeclaredType(ctx rule.RuleContext, parameterNode *ast.Node) *checker.Type {
	parameter := parameterNode.AsParameterDeclaration()
	if parameter == nil {
		return nil
	}
	if parameter.Type != nil {
		return ctx.TypeChecker.GetTypeAtLocation(parameter.Type)
	}

	index := parameterIndexInParent(parameterNode)
	parent := parameterNode.Parent
	if index >= 0 && parent != nil && (ast.IsArrowFunction(parent) || ast.IsFunctionExpression(parent)) {
		contextualType := checker.Checker_getContextualType(ctx.TypeChecker, parent, checker.ContextFlagsNone)
		if contextualType != nil {
			for _, contextualPart := range utils.UnionTypeParts(contextualType) {
				for _, signature := range utils.GetCallSignatures(ctx.TypeChecker, contextualPart) {
					parameters := checker.Signature_parameters(signature)
					if index < len(parameters) {
						paramType := ctx.TypeChecker.GetTypeOfSymbolAtLocation(parameters[index], parent)
						if paramType != nil {
							return paramType
						}
					}
				}
			}
		}
	}

	return ctx.TypeChecker.GetTypeAtLocation(parameterNode)
}

func bindingElementPropertyName(bindingElement *ast.BindingElement) string {
	if bindingElement == nil {
		return ""
	}
	if bindingElement.PropertyName != nil {
		switch bindingElement.PropertyName.Kind {
		case ast.KindIdentifier:
			identifier := bindingElement.PropertyName.AsIdentifier()
			if identifier != nil {
				return identifier.Text
			}
		case ast.KindStringLiteral:
			stringLiteral := bindingElement.PropertyName.AsStringLiteral()
			if stringLiteral != nil {
				return stringLiteral.Text
			}
		case ast.KindNumericLiteral:
			return bindingElement.PropertyName.Text()
		}
	}
	if bindingElement.Name() != nil && bindingElement.Name().Kind == ast.KindIdentifier {
		identifier := bindingElement.Name().AsIdentifier()
		if identifier != nil {
			return identifier.Text
		}
	}
	return ""
}

func objectBindingPatternSourceType(ctx rule.RuleContext, objectBindingPatternNode *ast.Node, seen map[*ast.Node]bool) *checker.Type {
	if objectBindingPatternNode == nil || objectBindingPatternNode.Kind != ast.KindObjectBindingPattern || seen[objectBindingPatternNode] {
		return nil
	}
	seen[objectBindingPatternNode] = true
	defer delete(seen, objectBindingPatternNode)

	parent := objectBindingPatternNode.Parent
	if parent == nil {
		return nil
	}

	switch parent.Kind {
	case ast.KindVariableDeclaration:
		decl := parent.AsVariableDeclaration()
		if decl == nil {
			return nil
		}
		if decl.Initializer != nil {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, decl.Initializer)
		}
		if decl.Type != nil {
			return ctx.TypeChecker.GetTypeAtLocation(decl.Type)
		}
	case ast.KindParameter:
		param := parent.AsParameterDeclaration()
		if param == nil {
			return nil
		}
		if param.Type != nil {
			return ctx.TypeChecker.GetTypeAtLocation(param.Type)
		}
		if param.Initializer != nil {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, param.Initializer)
		}
	case ast.KindBindingElement:
		bindingElementType := ctx.TypeChecker.GetTypeAtLocation(parent)
		if bindingElementType != nil {
			return bindingElementType
		}
		bindingElement := parent.AsBindingElement()
		if bindingElement == nil || parent.Parent == nil || parent.Parent.Kind != ast.KindObjectBindingPattern {
			return nil
		}
		outerObjectType := objectBindingPatternSourceType(ctx, parent.Parent, seen)
		if outerObjectType == nil {
			return nil
		}
		propertyName := bindingElementPropertyName(bindingElement)
		if propertyName == "" {
			return nil
		}
		propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, outerObjectType, propertyName)
		if propertySymbol == nil {
			return nil
		}
		return ctx.TypeChecker.GetTypeOfSymbolAtLocation(propertySymbol, parent)
	case ast.KindBinaryExpression:
		binaryExpression := parent.AsBinaryExpression()
		if binaryExpression != nil && binaryExpression.OperatorToken.Kind == ast.KindEqualsToken {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, binaryExpression.Right)
		}
	}

	return nil
}

func arrayBindingPatternSourceType(ctx rule.RuleContext, arrayBindingPatternNode *ast.Node, seen map[*ast.Node]bool) *checker.Type {
	if arrayBindingPatternNode == nil || arrayBindingPatternNode.Kind != ast.KindArrayBindingPattern || seen[arrayBindingPatternNode] {
		return nil
	}
	seen[arrayBindingPatternNode] = true
	defer delete(seen, arrayBindingPatternNode)

	parent := arrayBindingPatternNode.Parent
	if parent == nil {
		return nil
	}

	switch parent.Kind {
	case ast.KindVariableDeclaration:
		decl := parent.AsVariableDeclaration()
		if decl == nil {
			return nil
		}
		if decl.Initializer != nil {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, decl.Initializer)
		}
		if decl.Type != nil {
			return ctx.TypeChecker.GetTypeAtLocation(decl.Type)
		}
	case ast.KindParameter:
		param := parent.AsParameterDeclaration()
		if param == nil {
			return nil
		}
		if param.Type != nil {
			return ctx.TypeChecker.GetTypeAtLocation(param.Type)
		}
		if param.Initializer != nil {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, param.Initializer)
		}
	case ast.KindBindingElement:
		bindingElementType := ctx.TypeChecker.GetTypeAtLocation(parent)
		if bindingElementType != nil {
			return bindingElementType
		}
		bindingElement := parent.AsBindingElement()
		if bindingElement == nil || parent.Parent == nil || parent.Parent.Kind != ast.KindArrayBindingPattern {
			return nil
		}
		outerType := arrayBindingPatternSourceType(ctx, parent.Parent, seen)
		if outerType == nil {
			return nil
		}
		elementIndex := -1
		for idx, element := range parent.Parent.AsBindingPattern().Elements.Nodes {
			if element == parent {
				elementIndex = idx
				break
			}
		}
		if elementIndex < 0 {
			return nil
		}
		if checker.IsTupleType(outerType) {
			typeArguments := checker.Checker_getTypeArguments(ctx.TypeChecker, outerType)
			if elementIndex < len(typeArguments) {
				return typeArguments[elementIndex]
			}
		}
		return checker.Checker_getIndexTypeOfType(ctx.TypeChecker, outerType, checker.Checker_numberType(ctx.TypeChecker))
	case ast.KindBinaryExpression:
		binaryExpression := parent.AsBinaryExpression()
		if binaryExpression != nil && binaryExpression.OperatorToken.Kind == ast.KindEqualsToken {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, binaryExpression.Right)
		}
	}

	return nil
}

func bindingElementSourceType(ctx rule.RuleContext, bindingElementNode *ast.Node) *checker.Type {
	if bindingElementNode == nil || bindingElementNode.Kind != ast.KindBindingElement {
		return nil
	}
	parent := bindingElementNode.Parent
	if parent == nil {
		return ctx.TypeChecker.GetTypeAtLocation(bindingElementNode)
	}

	if parent.Kind == ast.KindObjectBindingPattern {
		sourceType := objectBindingPatternSourceType(ctx, parent, map[*ast.Node]bool{})
		if sourceType == nil {
			return nil
		}
		propertyName := bindingElementPropertyName(bindingElementNode.AsBindingElement())
		if propertyName == "" {
			return nil
		}
		propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, sourceType, propertyName)
		if propertySymbol == nil {
			return nil
		}
		return ctx.TypeChecker.GetTypeOfSymbolAtLocation(propertySymbol, bindingElementNode)
	}

	if parent.Kind == ast.KindArrayBindingPattern {
		sourceType := arrayBindingPatternSourceType(ctx, parent, map[*ast.Node]bool{})
		if sourceType == nil {
			return nil
		}

		elementIndex := -1
		for idx, element := range parent.AsBindingPattern().Elements.Nodes {
			if element == bindingElementNode {
				elementIndex = idx
				break
			}
		}
		if elementIndex < 0 {
			return nil
		}

		if checker.IsTupleType(sourceType) {
			typeArguments := checker.Checker_getTypeArguments(ctx.TypeChecker, sourceType)
			if elementIndex < len(typeArguments) {
				return typeArguments[elementIndex]
			}
			return nil
		}

		return checker.Checker_getIndexTypeOfType(ctx.TypeChecker, sourceType, checker.Checker_numberType(ctx.TypeChecker))
	}

	return ctx.TypeChecker.GetTypeAtLocation(bindingElementNode)
}

var NoUselessDefaultAssignmentRule = rule.CreateRule(rule.Rule{
	Name: "no-useless-default-assignment",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		if ctx.Program != nil && !*opts.AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing {
			compilerOptions := ctx.Program.Options()
			if !utils.IsStrictCompilerOptionEnabled(compilerOptions, compilerOptions.StrictNullChecks) {
				ctx.ReportNode(&ast.Node{}, buildNoStrictNullCheckMessage())
			}
		}

		checkParameter := func(node *ast.Node) {
			parameter := node.AsParameterDeclaration()
			if parameter == nil || parameter.Initializer == nil {
				return
			}

			declaredType := parameterDeclaredType(ctx, node)
			if declaredType == nil {
				return
			}

			if isUndefinedIdentifier(parameter.Initializer) {
				if canBeUndefined(declaredType) {
					ctx.ReportNode(parameter.Initializer, buildPreferOptionalSyntaxMessage())
				} else {
					ctx.ReportNode(parameter.Initializer, buildUselessUndefinedMessage("parameter"))
				}
				return
			}

			if !canBeUndefined(declaredType) {
				ctx.ReportNode(parameter.Initializer, buildUselessDefaultAssignmentMessage("parameter"))
			}
		}

		checkBindingElement := func(node *ast.Node) {
			bindingElement := node.AsBindingElement()
			if bindingElement == nil || bindingElement.Initializer == nil || bindingElement.DotDotDotToken != nil {
				return
			}

			if isUndefinedIdentifier(bindingElement.Initializer) {
				ctx.ReportNode(bindingElement.Initializer, buildUselessUndefinedMessage("property"))
				return
			}

			declaredType := bindingElementSourceType(ctx, node)
			if declaredType == nil {
				return
			}

			if !canBeUndefined(declaredType) {
				ctx.ReportNode(bindingElement.Initializer, buildUselessDefaultAssignmentMessage("property"))
			}
		}

		return rule.RuleListeners{
			ast.KindParameter:      checkParameter,
			ast.KindBindingElement: checkBindingElement,
		}
	},
})
