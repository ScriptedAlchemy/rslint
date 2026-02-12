package explicit_function_return_type

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type explicitFunctionReturnTypeOptions struct {
	AllowExpressions                                     bool
	AllowTypedFunctionExpressions                        bool
	AllowHigherOrderFunctions                            bool
	AllowIIFEs                                           bool
	AllowDirectConstAssertionInArrowFunctions            bool
	AllowConciseArrowFunctionExpressionsStartingWithVoid bool
	AllowFunctionsWithoutTypeParameters                  bool
	AllowedNames                                         []string
}

func parseOptions(options any) explicitFunctionReturnTypeOptions {
	opts := explicitFunctionReturnTypeOptions{
		AllowExpressions:                                     false,
		AllowTypedFunctionExpressions:                        true,
		AllowHigherOrderFunctions:                            true,
		AllowIIFEs:                                           false,
		AllowDirectConstAssertionInArrowFunctions:            true,
		AllowConciseArrowFunctionExpressionsStartingWithVoid: false,
		AllowFunctionsWithoutTypeParameters:                  false,
		AllowedNames:                                         []string{},
	}
	if options == nil {
		return opts
	}

	var optionsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		optionsMap, _ = arr[0].(map[string]interface{})
	} else {
		optionsMap, _ = options.(map[string]interface{})
	}
	if optionsMap == nil {
		return opts
	}

	if value, ok := optionsMap["allowExpressions"].(bool); ok {
		opts.AllowExpressions = value
	}
	if value, ok := optionsMap["allowTypedFunctionExpressions"].(bool); ok {
		opts.AllowTypedFunctionExpressions = value
	}
	if value, ok := optionsMap["allowHigherOrderFunctions"].(bool); ok {
		opts.AllowHigherOrderFunctions = value
	}
	if value, ok := optionsMap["allowIIFEs"].(bool); ok {
		opts.AllowIIFEs = value
	}
	if value, ok := optionsMap["allowDirectConstAssertionInArrowFunctions"].(bool); ok {
		opts.AllowDirectConstAssertionInArrowFunctions = value
	}
	if value, ok := optionsMap["allowConciseArrowFunctionExpressionsStartingWithVoid"].(bool); ok {
		opts.AllowConciseArrowFunctionExpressionsStartingWithVoid = value
	}
	if value, ok := optionsMap["allowFunctionsWithoutTypeParameters"].(bool); ok {
		opts.AllowFunctionsWithoutTypeParameters = value
	}
	if values, ok := optionsMap["allowedNames"].([]interface{}); ok {
		for _, value := range values {
			if name, ok := value.(string); ok {
				opts.AllowedNames = append(opts.AllowedNames, name)
			}
		}
	}

	return opts
}

func buildMissingReturnTypeMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingReturnType",
		Description: "Missing return type on function.",
	}
}

func hasAllowedName(name string, allowed []string) bool {
	if name == "" {
		return false
	}
	for _, allowedName := range allowed {
		if allowedName == name {
			return true
		}
	}
	return false
}

func functionName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration != nil && functionDeclaration.Name() != nil {
			return functionDeclaration.Name().Text()
		}
	case ast.KindFunctionExpression:
		functionExpression := node.AsFunctionExpression()
		if functionExpression != nil && functionExpression.Name() != nil {
			return functionExpression.Name().Text()
		}
		if parentName := functionNameFromParent(node); parentName != "" {
			return parentName
		}
	case ast.KindArrowFunction:
		if parentName := functionNameFromParent(node); parentName != "" {
			return parentName
		}
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		if methodDeclaration != nil && methodDeclaration.Name() != nil {
			return staticNameText(methodDeclaration.Name())
		}
	case ast.KindGetAccessor:
		getAccessor := node.AsGetAccessorDeclaration()
		if getAccessor != nil && getAccessor.Name() != nil {
			return staticNameText(getAccessor.Name())
		}
	}
	return ""
}

func staticNameText(nameNode *ast.Node) string {
	if nameNode == nil {
		return ""
	}
	switch nameNode.Kind {
	case ast.KindIdentifier:
		return nameNode.AsIdentifier().Text
	case ast.KindPrivateIdentifier:
		return nameNode.AsPrivateIdentifier().Text
	case ast.KindStringLiteral:
		return nameNode.AsStringLiteral().Text
	case ast.KindNumericLiteral:
		return nameNode.AsNumericLiteral().Text
	}
	return ""
}

func functionNameFromParent(node *ast.Node) string {
	if node == nil || node.Parent == nil {
		return ""
	}
	switch node.Parent.Kind {
	case ast.KindVariableDeclaration:
		variableDeclaration := node.Parent.AsVariableDeclaration()
		if variableDeclaration != nil && variableDeclaration.Name() != nil && variableDeclaration.Name().Kind == ast.KindIdentifier {
			return variableDeclaration.Name().AsIdentifier().Text
		}
	case ast.KindPropertyAssignment:
		propertyAssignment := node.Parent.AsPropertyAssignment()
		if propertyAssignment == nil || propertyAssignment.Name() == nil {
			return ""
		}
		switch propertyAssignment.Name().Kind {
		case ast.KindIdentifier:
			return propertyAssignment.Name().AsIdentifier().Text
		case ast.KindStringLiteral:
			return propertyAssignment.Name().AsStringLiteral().Text
		}
	case ast.KindPropertyDeclaration:
		propertyDeclaration := node.Parent.AsPropertyDeclaration()
		if propertyDeclaration == nil || propertyDeclaration.Name() == nil {
			return ""
		}
		switch propertyDeclaration.Name().Kind {
		case ast.KindIdentifier:
			return propertyDeclaration.Name().AsIdentifier().Text
		case ast.KindStringLiteral:
			return propertyDeclaration.Name().AsStringLiteral().Text
		}
	}
	return ""
}

func hasExplicitReturnType(node *ast.Node) bool {
	if node == nil {
		return true
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		return functionDeclaration == nil || functionDeclaration.Type != nil
	case ast.KindFunctionExpression:
		functionExpression := node.AsFunctionExpression()
		return functionExpression == nil || functionExpression.Type != nil
	case ast.KindArrowFunction:
		arrowFunction := node.AsArrowFunction()
		return arrowFunction == nil || arrowFunction.Type != nil
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		return methodDeclaration == nil || methodDeclaration.Type != nil
	case ast.KindGetAccessor:
		getAccessor := node.AsGetAccessorDeclaration()
		return getAccessor == nil || getAccessor.Type != nil
	}
	return true
}

func isExpressionFunction(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	for parent != nil {
		switch parent.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindPrefixUnaryExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			parent = parent.Parent
			continue
		}
		break
	}
	if parent == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindExpressionStatement,
		ast.KindCallExpression,
		ast.KindNewExpression,
		ast.KindPropertyAssignment,
		ast.KindArrayLiteralExpression,
		ast.KindReturnStatement,
		ast.KindBinaryExpression,
		ast.KindJsxExpression:
		return true
	}
	return false
}

func isTypedFunctionExpressionContext(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent

	for parent != nil {
		switch parent.Kind {
		case ast.KindParenthesizedExpression, ast.KindNonNullExpression:
			parent = parent.Parent
			continue
		case ast.KindAsExpression, ast.KindTypeAssertionExpression, ast.KindSatisfiesExpression:
			return true
		}
		break
	}

	for parent != nil {
		switch parent.Kind {
		case ast.KindParenthesizedExpression, ast.KindNonNullExpression,
			ast.KindAsExpression, ast.KindTypeAssertionExpression, ast.KindSatisfiesExpression:
			parent = parent.Parent
			continue
		}
		break
	}
	if parent == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		variableDeclaration := parent.AsVariableDeclaration()
		return variableDeclaration != nil && variableDeclaration.Type != nil
	case ast.KindCallExpression:
		callExpression := parent.AsCallExpression()
		if callExpression == nil || callExpression.Arguments == nil {
			return false
		}
		for _, argument := range callExpression.Arguments.Nodes {
			if argument == node {
				return true
			}
		}
		return false
	case ast.KindNewExpression:
		newExpression := parent.AsNewExpression()
		if newExpression == nil || newExpression.Arguments == nil {
			return false
		}
		for _, argument := range newExpression.Arguments.Nodes {
			if argument == node {
				return true
			}
		}
		return false
	case ast.KindPropertyDeclaration:
		propertyDeclaration := parent.AsPropertyDeclaration()
		return propertyDeclaration != nil && propertyDeclaration.Type != nil
	case ast.KindPropertyAssignment:
		propertyAssignment := parent.AsPropertyAssignment()
		if propertyAssignment == nil || propertyAssignment.Name() == nil {
			return false
		}
		if propertyAssignment.Parent == nil || propertyAssignment.Parent.Kind != ast.KindObjectLiteralExpression {
			return false
		}
		return hasTypedObjectLiteralAncestor(propertyAssignment.Parent)
	case ast.KindParameter:
		parameter := parent.AsParameterDeclaration()
		return parameter != nil && parameter.Type != nil
	case ast.KindJsxExpression:
		return true
	case ast.KindJsxAttribute:
		return true
	}
	return false
}

func returnsFunctionLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	var body *ast.BlockOrExpression
	switch node.Kind {
	case ast.KindArrowFunction:
		arrowFunction := node.AsArrowFunction()
		if arrowFunction == nil {
			return false
		}
		body = arrowFunction.Body
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration == nil || functionDeclaration.Body == nil {
			return false
		}
		body = functionDeclaration.Body
	case ast.KindFunctionExpression:
		functionExpression := node.AsFunctionExpression()
		if functionExpression == nil || functionExpression.Body == nil {
			return false
		}
		body = functionExpression.Body
	}
	if body == nil {
		return false
	}
	unwrapExpression := func(expressionNode *ast.Node) *ast.Node {
		current := expressionNode
		for current != nil {
			switch current.Kind {
			case ast.KindParenthesizedExpression:
				parenthesizedExpression := current.AsParenthesizedExpression()
				if parenthesizedExpression == nil || parenthesizedExpression.Expression == nil {
					return current
				}
				current = parenthesizedExpression.Expression
			case ast.KindAsExpression:
				asExpression := current.AsAsExpression()
				if asExpression == nil || asExpression.Expression == nil {
					return current
				}
				current = asExpression.Expression
			case ast.KindTypeAssertionExpression:
				typeAssertionExpression := current.AsTypeAssertion()
				if typeAssertionExpression == nil || typeAssertionExpression.Expression == nil {
					return current
				}
				current = typeAssertionExpression.Expression
			case ast.KindSatisfiesExpression:
				satisfiesExpression := current.AsSatisfiesExpression()
				if satisfiesExpression == nil || satisfiesExpression.Expression == nil {
					return current
				}
				current = satisfiesExpression.Expression
			case ast.KindNonNullExpression:
				nonNullExpression := current.AsNonNullExpression()
				if nonNullExpression == nil || nonNullExpression.Expression == nil {
					return current
				}
				current = nonNullExpression.Expression
			default:
				return current
			}
		}
		return nil
	}

	if body.Kind != ast.KindBlock {
		expression := unwrapExpression(body.AsNode())
		return expression != nil && (expression.Kind == ast.KindArrowFunction || expression.Kind == ast.KindFunctionExpression)
	}
	block := body.AsBlock()
	if block == nil || block.Statements == nil || len(block.Statements.Nodes) == 0 {
		return false
	}
	foundReturn := false
	allReturnsAreFunctionLike := true

	var visit func(current *ast.Node)
	visit = func(current *ast.Node) {
		if current == nil || !allReturnsAreFunctionLike {
			return
		}
		switch current.Kind {
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return
		}
		if current.Kind == ast.KindReturnStatement {
			returnStatement := current.AsReturnStatement()
			if returnStatement == nil || returnStatement.Expression == nil {
				allReturnsAreFunctionLike = false
				return
			}
			foundReturn = true
			expression := unwrapExpression(returnStatement.Expression)
			if expression == nil || (expression.Kind != ast.KindArrowFunction && expression.Kind != ast.KindFunctionExpression) {
				allReturnsAreFunctionLike = false
			}
			return
		}
		current.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return !allReturnsAreFunctionLike
		})
	}

	for _, statement := range block.Statements.Nodes {
		visit(statement)
		if !allReturnsAreFunctionLike {
			break
		}
	}
	return foundReturn && allReturnsAreFunctionLike
}

func hasDirectConstAssertionInArrow(sourceFile *ast.SourceFile, node *ast.Node) bool {
	if sourceFile == nil || node == nil || node.Kind != ast.KindArrowFunction {
		return false
	}
	arrowFunction := node.AsArrowFunction()
	if arrowFunction == nil || arrowFunction.Body == nil || arrowFunction.Body.Kind == ast.KindBlock {
		return false
	}
	bodyRange := utils.TrimNodeTextRange(sourceFile, arrowFunction.Body.AsNode())
	text := sourceFile.Text()
	if bodyRange.Pos() < 0 || bodyRange.End() > len(text) || bodyRange.Pos() >= bodyRange.End() {
		return false
	}
	return strings.Contains(text[bodyRange.Pos():bodyRange.End()], " as const")
}

func isConciseArrowFunctionWithVoidBody(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindArrowFunction {
		return false
	}
	arrowFunction := node.AsArrowFunction()
	if arrowFunction == nil || arrowFunction.Body == nil || arrowFunction.Body.Kind == ast.KindBlock {
		return false
	}
	return arrowFunction.Body.Kind == ast.KindVoidExpression
}

func hasNoTypeParameters(node *ast.Node) bool {
	if node == nil {
		return true
	}
	return len(node.TypeParameters()) == 0
}

func isDirectlyReturnedFunction(node *ast.Node) bool {
	if node == nil {
		return false
	}
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindParenthesizedExpression {
			continue
		}
		if current.Kind == ast.KindReturnStatement {
			return true
		}
		if current.Kind == ast.KindArrowFunction {
			arrowFunction := current.AsArrowFunction()
			return arrowFunction != nil && arrowFunction.Body != nil && arrowFunction.Body.AsNode() == node
		}
		return false
	}
	return false
}

func arrowOperatorRange(sourceFile *ast.SourceFile, arrow *ast.ArrowFunction) core.TextRange {
	if sourceFile == nil || arrow == nil || arrow.Body == nil {
		return core.NewTextRange(0, 0)
	}
	start := arrow.Pos()
	if arrow.Type != nil {
		start = arrow.Type.End()
	} else if arrow.Parameters != nil && len(arrow.Parameters.Nodes) > 0 {
		lastParam := arrow.Parameters.Nodes[len(arrow.Parameters.Nodes)-1]
		if lastParam != nil {
			start = lastParam.End()
		}
	}
	end := arrow.Body.Pos()
	text := sourceFile.Text()
	if start >= 0 && end > start && end <= len(text) {
		segment := text[start:end]
		if index := strings.Index(segment, "=>"); index >= 0 {
			operatorStart := start + index
			operatorEnd := end
			if operatorEnd <= operatorStart {
				operatorEnd = operatorStart + 2
			}
			return core.NewTextRange(operatorStart, operatorEnd)
		}
	}
	return core.NewTextRange(start, start+2)
}

func functionKeywordRange(sourceFile *ast.SourceFile, node *ast.Node) core.TextRange {
	if sourceFile == nil || node == nil {
		return core.NewTextRange(0, 0)
	}
	nodeRange := utils.TrimNodeTextRange(sourceFile, node)
	text := sourceFile.Text()
	if nodeRange.Pos() < 0 || nodeRange.End() > len(text) || nodeRange.Pos() >= nodeRange.End() {
		return core.NewTextRange(nodeRange.Pos(), nodeRange.Pos())
	}
	segment := text[nodeRange.Pos():nodeRange.End()]
	if index := strings.Index(segment, "function"); index >= 0 {
		start := nodeRange.Pos() + index
		end := start + len("function")
		for end < nodeRange.End() {
			ch := text[end]
			if ch != ' ' && ch != '\t' {
				break
			}
			end++
		}
		return core.NewTextRange(start, end)
	}
	return core.NewTextRange(nodeRange.Pos(), nodeRange.Pos())
}

func functionDeclarationSignatureRange(sourceFile *ast.SourceFile, functionDeclaration *ast.FunctionDeclaration) core.TextRange {
	if sourceFile == nil || functionDeclaration == nil {
		return core.NewTextRange(0, 0)
	}
	node := functionDeclaration.AsNode()
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	start := trimmed.Pos()
	if functionDeclaration.Name() != nil {
		return core.NewTextRange(start, functionDeclaration.Name().End())
	}
	return functionKeywordRange(sourceFile, node)
}

func shouldIgnore(node *ast.Node, ctx rule.RuleContext, opts explicitFunctionReturnTypeOptions) bool {
	if node == nil {
		return true
	}
	if hasAllowedName(functionName(node), opts.AllowedNames) {
		return true
	}
	if opts.AllowExpressions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression) && isExpressionFunction(node) {
		return true
	}
	if opts.AllowTypedFunctionExpressions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression) && isTypedFunctionExpressionContext(node) {
		return true
	}
	if opts.AllowTypedFunctionExpressions && hasContextualFunctionType(ctx, node) {
		return true
	}
	if opts.AllowHigherOrderFunctions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression || node.Kind == ast.KindFunctionDeclaration) && returnsFunctionLike(node) {
		return true
	}
	if opts.AllowIIFEs && isIIFE(node) {
		return true
	}
	if opts.AllowConciseArrowFunctionExpressionsStartingWithVoid && isConciseArrowFunctionWithVoidBody(node) {
		return true
	}
	if opts.AllowFunctionsWithoutTypeParameters && hasNoTypeParameters(node) {
		return true
	}
	if opts.AllowDirectConstAssertionInArrowFunctions && hasDirectConstAssertionInArrow(ctx.SourceFile, node) {
		return true
	}
	return false
}

func hasContextualFunctionType(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}

	checkType := func(t *checker.Type) bool {
		return t != nil && len(utils.GetCallSignatures(ctx.TypeChecker, t)) > 0
	}

	contextualType := checker.Checker_getContextualType(ctx.TypeChecker, node, checker.ContextFlagsNone)
	if checkType(contextualType) {
		return true
	}

	if node.Kind == ast.KindMethodDeclaration {
		methodDeclaration := node.AsMethodDeclaration()
		if methodDeclaration != nil && methodDeclaration.Name() != nil {
			if checkType(checker.Checker_getContextualType(ctx.TypeChecker, methodDeclaration.Name(), checker.ContextFlagsNone)) {
				return true
			}
			if node.Parent != nil && node.Parent.Kind == ast.KindObjectLiteralExpression {
				objectType := checker.Checker_getContextualType(ctx.TypeChecker, node.Parent, checker.ContextFlagsNone)
				if objectType != nil {
					propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, objectType, methodDeclaration.Name().Text())
					if propertySymbol != nil {
						contextualMethodType := ctx.TypeChecker.GetTypeOfSymbolAtLocation(propertySymbol, methodDeclaration.Name())
						if checkType(contextualMethodType) {
							return true
						}
					}
				}
			}
		}
	}

	if node.Parent != nil && node.Parent.Kind == ast.KindPropertyAssignment {
		propertyAssignment := node.Parent.AsPropertyAssignment()
		if propertyAssignment != nil && propertyAssignment.Initializer != nil {
			if checkType(checker.Checker_getContextualType(ctx.TypeChecker, propertyAssignment.Initializer, checker.ContextFlagsNone)) {
				return true
			}
		}
	}

	for current := node.Parent; current != nil; current = current.Parent {
		var arguments *ast.NodeList
		isOptionalChainCall := false
		switch current.Kind {
		case ast.KindCallExpression:
			callExpression := current.AsCallExpression()
			if callExpression == nil {
				continue
			}
			arguments = callExpression.Arguments
			isOptionalChainCall = ast.IsOptionalChain(current)
		case ast.KindNewExpression:
			newExpression := current.AsNewExpression()
			if newExpression == nil {
				continue
			}
			arguments = newExpression.Arguments
		default:
			continue
		}
		if arguments == nil {
			continue
		}

		for index, argument := range arguments.Nodes {
			if argument == nil {
				continue
			}
			if argument != node && !isDescendantOf(node, argument) {
				continue
			}
			if isOptionalChainCall {
				return true
			}
			if checkType(checker.Checker_getContextualTypeForArgumentAtIndex(ctx.TypeChecker, current, index)) {
				return true
			}
			signature := checker.Checker_getResolvedSignature(ctx.TypeChecker, current, nil, checker.CheckModeNormal)
			if signature != nil {
				parameters := checker.Signature_parameters(signature)
				if index < len(parameters) && parameters[index] != nil {
					parameterType := ctx.TypeChecker.GetTypeOfSymbolAtLocation(parameters[index], current)
					if checkType(parameterType) {
						return true
					}
				}
			}
		}
	}

	return false
}

func isDescendantOf(node *ast.Node, ancestor *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		if current == ancestor {
			return true
		}
	}
	return false
}

func isIIFE(node *ast.Node) bool {
	if node == nil {
		return false
	}
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			current = current.Parent
			continue
		}
		break
	}
	if current == nil || current.Kind != ast.KindCallExpression {
		return false
	}
	callExpression := current.AsCallExpression()
	if callExpression == nil || callExpression.Expression == nil {
		return false
	}
	callee := callExpression.Expression.AsNode()
	return callee == node || isDescendantOf(node, callee)
}

func reportMissingReturnType(ctx rule.RuleContext, node *ast.Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case ast.KindArrowFunction:
		arrow := node.AsArrowFunction()
		if arrow != nil {
			if node.Parent != nil && node.Parent.Kind == ast.KindPropertyAssignment {
				propertyAssignment := node.Parent.AsPropertyAssignment()
				if propertyAssignment != nil && propertyAssignment.Name() != nil && propertyAssignment.Initializer != nil {
					if reportRange, ok := propertyAssignmentInitializerBoundaryRange(ctx.SourceFile, propertyAssignment); ok {
						ctx.ReportRange(reportRange, buildMissingReturnTypeMessage())
					} else {
						ctx.ReportNode(propertyAssignment.Name(), buildMissingReturnTypeMessage())
					}
					return
				}
			}
			if node.Parent != nil && node.Parent.Kind == ast.KindPropertyDeclaration {
				propertyDeclaration := node.Parent.AsPropertyDeclaration()
				if propertyDeclaration != nil && propertyDeclaration.Name() != nil {
					if reportRange, ok := propertyInitializerBoundaryRange(ctx.SourceFile, node.Parent, propertyDeclaration.Name(), node); ok {
						ctx.ReportRange(reportRange, buildMissingReturnTypeMessage())
						return
					}
				}
			}
			ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
			return
		}
	case ast.KindFunctionExpression:
		if node.Parent != nil && node.Parent.Kind == ast.KindPropertyAssignment {
			propertyAssignment := node.Parent.AsPropertyAssignment()
			if propertyAssignment != nil && propertyAssignment.Name() != nil {
				keywordRange := functionKeywordRange(ctx.SourceFile, node)
				start := utils.TrimNodeTextRange(ctx.SourceFile, propertyAssignment.Name()).Pos()
				if keywordRange.End() > start {
					ctx.ReportRange(core.NewTextRange(start, keywordRange.End()), buildMissingReturnTypeMessage())
					return
				}
			}
		}
		if node.Parent != nil && node.Parent.Kind == ast.KindPropertyDeclaration {
			propertyDeclaration := node.Parent.AsPropertyDeclaration()
			functionExpression := node.AsFunctionExpression()
			if propertyDeclaration != nil && functionExpression != nil {
				ctx.ReportRange(functionExpressionPropertyBoundaryRange(ctx.SourceFile, propertyDeclaration, functionExpression), buildMissingReturnTypeMessage())
				return
			}
		}
		ctx.ReportRange(functionKeywordRange(ctx.SourceFile, node), buildMissingReturnTypeMessage())
		return
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration != nil {
			ctx.ReportRange(functionDeclarationSignatureRange(ctx.SourceFile, functionDeclaration), buildMissingReturnTypeMessage())
			return
		}
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		if methodDeclaration != nil && methodDeclaration.Name() != nil {
			if reportRange, ok := methodLikeReportRange(ctx.SourceFile, node, methodDeclaration.Name()); ok {
				ctx.ReportRange(reportRange, buildMissingReturnTypeMessage())
			} else {
				ctx.ReportNode(methodDeclaration.Name(), buildMissingReturnTypeMessage())
			}
			return
		}
	case ast.KindGetAccessor:
		getAccessor := node.AsGetAccessorDeclaration()
		if getAccessor != nil && getAccessor.Name() != nil {
			if reportRange, ok := accessorKeywordReportRange(ctx.SourceFile, node, getAccessor.Name(), "get"); ok {
				ctx.ReportRange(reportRange, buildMissingReturnTypeMessage())
			} else {
				ctx.ReportNode(getAccessor.Name(), buildMissingReturnTypeMessage())
			}
			return
		}
	}
	ctx.ReportNode(node, buildMissingReturnTypeMessage())
}

func methodLikeReportRange(sourceFile *ast.SourceFile, node *ast.Node, nameNode *ast.Node) (core.TextRange, bool) {
	if sourceFile == nil || node == nil || nameNode == nil {
		return core.NewTextRange(0, 0), false
	}
	nameRange := utils.TrimNodeTextRange(sourceFile, nameNode)
	start := nameRange.Pos()
	if node.Modifiers() != nil {
		for _, modifier := range node.Modifiers().Nodes {
			if modifier == nil || modifier.Kind == ast.KindDecorator {
				continue
			}
			modifierRange := utils.TrimNodeTextRange(sourceFile, modifier)
			start = modifierRange.Pos()
			break
		}
	}
	if nameRange.End() <= start {
		return core.NewTextRange(0, 0), false
	}
	return core.NewTextRange(start, nameRange.End()), true
}

func accessorKeywordReportRange(sourceFile *ast.SourceFile, node *ast.Node, nameNode *ast.Node, keyword string) (core.TextRange, bool) {
	if sourceFile == nil || node == nil || nameNode == nil || keyword == "" {
		return core.NewTextRange(0, 0), false
	}
	nameRange := utils.TrimNodeTextRange(sourceFile, nameNode)
	text := sourceFile.Text()
	nodeRange := utils.TrimNodeTextRange(sourceFile, node)
	if nodeRange.Pos() < 0 || nameRange.Pos() > len(text) || nodeRange.Pos() >= nameRange.Pos() {
		return core.NewTextRange(0, 0), false
	}
	segment := text[nodeRange.Pos():nameRange.Pos()]
	index := strings.Index(segment, keyword)
	if index < 0 {
		return core.NewTextRange(0, 0), false
	}
	start := nodeRange.Pos() + index
	if nameRange.End() <= start {
		return core.NewTextRange(0, 0), false
	}
	return core.NewTextRange(start, nameRange.End()), true
}

func propertyInitializerBoundaryRange(sourceFile *ast.SourceFile, node *ast.Node, nameNode *ast.Node, initializerNode *ast.Node) (core.TextRange, bool) {
	if sourceFile == nil || node == nil || nameNode == nil || initializerNode == nil {
		return core.NewTextRange(0, 0), false
	}
	start := leadingTokenOnLineBeforePos(sourceFile, initializerNode.Pos())
	end := initializerNode.Pos() + 1
	if end <= start {
		return core.NewTextRange(0, 0), false
	}
	return core.NewTextRange(start, end), true
}

func propertyAssignmentInitializerBoundaryRange(sourceFile *ast.SourceFile, propertyAssignment *ast.PropertyAssignment) (core.TextRange, bool) {
	if sourceFile == nil || propertyAssignment == nil || propertyAssignment.Name() == nil || propertyAssignment.Initializer == nil {
		return core.NewTextRange(0, 0), false
	}
	start := utils.TrimNodeTextRange(sourceFile, propertyAssignment.Name()).Pos()
	end := propertyAssignment.Initializer.Pos() + 1
	if end <= start {
		return core.NewTextRange(0, 0), false
	}
	return core.NewTextRange(start, end), true
}

func hasTypedObjectLiteralAncestor(node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		parent := current.Parent
		if parent == nil {
			return false
		}
		switch parent.Kind {
		case ast.KindAsExpression, ast.KindTypeAssertionExpression, ast.KindSatisfiesExpression:
			return true
		case ast.KindJsxExpression, ast.KindJsxAttribute, ast.KindJsxSpreadAttribute:
			return true
		case ast.KindVariableDeclaration:
			variableDeclaration := parent.AsVariableDeclaration()
			if variableDeclaration != nil && variableDeclaration.Type != nil {
				return true
			}
		case ast.KindPropertyDeclaration:
			propertyDeclaration := parent.AsPropertyDeclaration()
			if propertyDeclaration != nil && propertyDeclaration.Type != nil {
				return true
			}
		case ast.KindParameter:
			parameter := parent.AsParameterDeclaration()
			if parameter != nil && parameter.Type != nil {
				return true
			}
		}
	}
	return false
}

func functionExpressionPropertyBoundaryRange(sourceFile *ast.SourceFile, prop *ast.PropertyDeclaration, fnExpr *ast.FunctionExpression) core.TextRange {
	if sourceFile == nil || prop == nil || fnExpr == nil {
		return core.NewTextRange(0, 0)
	}
	start := leadingTokenOnLineBeforePos(sourceFile, fnExpr.Pos())
	end := fnExpr.End()
	if fnExpr.Body != nil {
		end = fnExpr.Body.Pos() - 2
	}
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func leadingTokenOnLineBeforePos(sourceFile *ast.SourceFile, pos int) int {
	if sourceFile == nil {
		return pos
	}
	text := sourceFile.Text()
	if pos > len(text) {
		pos = len(text)
	}
	if pos < 0 {
		pos = 0
	}

	lineStart := pos
	for lineStart > 0 {
		if text[lineStart-1] == '\n' {
			break
		}
		lineStart--
	}

	for lineStart < len(text) {
		ch := text[lineStart]
		if ch == ' ' || ch == '\t' {
			lineStart++
			continue
		}
		break
	}

	return lineStart
}

var ExplicitFunctionReturnTypeRule = rule.CreateRule(rule.Rule{
	Name: "explicit-function-return-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		checkNode := func(node *ast.Node) {
			if node == nil {
				return
			}
			if hasExplicitReturnType(node) || shouldIgnore(node, ctx, opts) {
				return
			}
			reportMissingReturnType(ctx, node)
		}

		return rule.RuleListeners{
			ast.KindFunctionDeclaration: checkNode,
			ast.KindFunctionExpression:  checkNode,
			ast.KindArrowFunction:       checkNode,
			ast.KindMethodDeclaration:   checkNode,
			ast.KindGetAccessor:         checkNode,
		}
	},
})
