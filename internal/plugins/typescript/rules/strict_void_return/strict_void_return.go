package strict_void_return

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type strictVoidReturnOptions struct {
	AllowReturnAny *bool `json:"allowReturnAny,omitempty"`
}

func parseOptions(options any) strictVoidReturnOptions {
	parsed := strictVoidReturnOptions{
		AllowReturnAny: utils.Ref(false),
	}
	if options == nil {
		return parsed
	}

	if raw, ok := options.([]any); ok && len(raw) > 0 {
		options = raw[0]
	}
	if raw, ok := options.(map[string]any); ok {
		if allow, ok := raw["allowReturnAny"].(bool); ok {
			parsed.AllowReturnAny = utils.Ref(allow)
		}
	}

	return parsed
}

func buildAsyncFuncMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "asyncFunc",
		Description: "Async function used in a context where a void function is expected.",
	}
}

func buildNonVoidFuncMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "nonVoidFunc",
		Description: "Value-returning function used in a context where a void function is expected.",
	}
}

func buildNonVoidReturnMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "nonVoidReturn",
		Description: "Value returned in a context where a void return is expected.",
	}
}

func isVoidReturningFunctionType(typeChecker *checker.Checker, t *checker.Type) bool {
	if t == nil {
		return false
	}

	returnTypesCount := 0
	for _, typePart := range utils.UnionTypeParts(t) {
		for _, signature := range utils.GetCallSignatures(typeChecker, typePart) {
			returnType := checker.Checker_getReturnTypeOfSignature(typeChecker, signature)
			for _, returnTypePart := range utils.UnionTypeParts(returnType) {
				returnTypesCount++
				if !utils.IsTypeFlagSet(returnTypePart, checker.TypeFlagsVoid) {
					return false
				}
			}
		}
	}

	return returnTypesCount > 0
}

func typeIsAllowed(typeToCheck *checker.Type, allowedFlags checker.TypeFlags) bool {
	if typeToCheck == nil {
		return false
	}
	for _, typePart := range utils.UnionTypeParts(typeToCheck) {
		if checker.Type_flags(typePart)&allowedFlags == 0 {
			return false
		}
	}
	return true
}

func functionReturnsOnlyAllowed(
	typeChecker *checker.Checker,
	functionType *checker.Type,
	allowedFlags checker.TypeFlags,
) bool {
	if functionType == nil {
		return false
	}

	signatures := utils.GetCallSignatures(typeChecker, functionType)
	if len(signatures) == 0 {
		return false
	}

	for _, signature := range signatures {
		returnType := checker.Checker_getReturnTypeOfSignature(typeChecker, signature)
		if !typeIsAllowed(returnType, allowedFlags) {
			return false
		}
	}

	return true
}

func reportInvalidReturnsInBody(
	ctx rule.RuleContext,
	functionNode *ast.Node,
	allowedFlags checker.TypeFlags,
) {
	if functionNode == nil {
		return
	}
	body := functionNode.Body()
	if body == nil || !ast.IsBlock(body) {
		return
	}

	var visit func(node *ast.Node)
	visit = func(node *ast.Node) {
		if node == nil {
			return
		}
		if node != functionNode && ast.IsFunctionLike(node) {
			return
		}
		if node.Kind == ast.KindReturnStatement {
			returnStatement := node.AsReturnStatement()
			if returnStatement != nil && returnStatement.Expression != nil {
				returnType := ctx.TypeChecker.GetTypeAtLocation(returnStatement.Expression)
				if !typeIsAllowed(returnType, allowedFlags) {
					ctx.ReportNode(node, buildNonVoidReturnMessage())
				}
			}
		}
		node.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return false
		})
	}

	visit(body)
}

var StrictVoidReturnRule = rule.CreateRule(rule.Rule{
	Name: "strict-void-return",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		allowedReturnFlags := checker.TypeFlagsVoid | checker.TypeFlagsNever | checker.TypeFlagsUndefined
		if *opts.AllowReturnAny {
			allowedReturnFlags |= checker.TypeFlagsAny
		}

		reportIfNonVoidFunction := func(functionNode *ast.Node) {
			if functionNode == nil {
				return
			}

			actualType := checker.Checker_getApparentType(ctx.TypeChecker, ctx.TypeChecker.GetTypeAtLocation(functionNode))
			if functionReturnsOnlyAllowed(ctx.TypeChecker, actualType, allowedReturnFlags) {
				return
			}

			if !ast.IsArrowFunction(functionNode) && !ast.IsFunctionExpression(functionNode) {
				ctx.ReportNode(functionNode, buildNonVoidFuncMessage())
				return
			}

			if ast.HasSyntacticModifier(functionNode, ast.ModifierFlagsAsync) {
				ctx.ReportNode(functionNode, buildAsyncFuncMessage())
				return
			}

			if ast.IsFunctionExpression(functionNode) {
				functionExpression := functionNode.AsFunctionExpression()
				if functionExpression != nil && functionExpression.AsteriskToken != nil {
					ctx.ReportNode(functionNode, buildNonVoidFuncMessage())
					return
				}
			}

			body := functionNode.Body()
			if body != nil && !ast.IsBlock(body) {
				ctx.ReportNode(body, buildNonVoidReturnMessage())
				return
			}

			if functionNode.Type() != nil && functionNode.Type().Kind != ast.KindVoidKeyword {
				ctx.ReportNode(functionNode.Type(), buildNonVoidFuncMessage())
				return
			}

			reportInvalidReturnsInBody(ctx, functionNode, allowedReturnFlags)
		}

		checkExpressionNode := func(node *ast.Node) bool {
			if node == nil {
				return false
			}
			expectedType := utils.GetContextualType(ctx.TypeChecker, node)
			if expectedType != nil && isVoidReturningFunctionType(ctx.TypeChecker, expectedType) {
				reportIfNonVoidFunction(node)
				return true
			}
			return false
		}

		checkFunctionCallNode := func(callNode *ast.Expression) {
			if callNode == nil || callNode.Arguments() == nil {
				return
			}

			callTargetType := ctx.TypeChecker.GetTypeAtLocation(callNode.Expression())

			for argumentIndex, argumentNode := range callNode.Arguments() {
				if argumentNode == nil || argumentNode.Kind == ast.KindSpreadElement {
					continue
				}
				contextualType := checker.Checker_getContextualTypeForArgumentAtIndex(ctx.TypeChecker, callNode, argumentIndex)
				if contextualType != nil && isVoidReturningFunctionType(ctx.TypeChecker, contextualType) {
					reportIfNonVoidFunction(argumentNode)
					continue
				}
				if checkExpressionNode(argumentNode) {
					continue
				}

				var signatures []*checker.Signature
				for _, callTypePart := range utils.UnionTypeParts(callTargetType) {
					if callNode.Kind == ast.KindCallExpression {
						signatures = append(signatures, utils.GetCallSignatures(ctx.TypeChecker, callTypePart)...)
					} else {
						signatures = append(signatures, utils.GetConstructSignatures(ctx.TypeChecker, callTypePart)...)
					}
				}

				if len(signatures) == 0 {
					continue
				}

				argExpectedReturnTypes := make([]*checker.Type, 0, 2)
				for _, signature := range signatures {
					parameters := checker.Signature_parameters(signature)
					if argumentIndex >= len(parameters) {
						continue
					}

					paramType := ctx.TypeChecker.GetTypeOfSymbolAtLocation(parameters[argumentIndex], callNode.Expression())
					for _, paramTypePart := range utils.UnionTypeParts(paramType) {
						for _, paramSignature := range utils.GetCallSignatures(ctx.TypeChecker, paramTypePart) {
							argExpectedReturnTypes = append(argExpectedReturnTypes, checker.Checker_getReturnTypeOfSignature(ctx.TypeChecker, paramSignature))
						}
					}
				}

				if len(argExpectedReturnTypes) == 0 {
					continue
				}

				hasVoid := false
				allExpectedAreVoidLike := true
				allowedExpectedReturnFlags := checker.TypeFlagsVoid | checker.TypeFlagsUndefined | checker.TypeFlagsNull | checker.TypeFlagsAny | checker.TypeFlagsNever
				for _, expectedReturnType := range argExpectedReturnTypes {
					for _, expectedReturnTypePart := range utils.UnionTypeParts(expectedReturnType) {
						typeFlags := checker.Type_flags(expectedReturnTypePart)
						if typeFlags&checker.TypeFlagsVoid != 0 {
							hasVoid = true
						}
						if typeFlags&allowedExpectedReturnFlags == 0 {
							allExpectedAreVoidLike = false
						}
					}
				}

				if hasVoid && allExpectedAreVoidLike {
					reportIfNonVoidFunction(argumentNode)
				}
			}
		}

		checkObjectProperty := func(propertyNode *ast.Node) {
			if propertyNode == nil {
				return
			}
			switch propertyNode.Kind {
			case ast.KindPropertyAssignment:
				propertyAssignment := propertyNode.AsPropertyAssignment()
				if propertyAssignment != nil {
					checkExpressionNode(propertyAssignment.Initializer)
				}
			case ast.KindShorthandPropertyAssignment:
				checkExpressionNode(propertyNode.Name())
			case ast.KindMethodDeclaration:
				checkExpressionNode(propertyNode)
			}
		}

		return rule.RuleListeners{
			ast.KindArrayLiteralExpression: func(node *ast.Node) {
				arrayLiteral := node.AsArrayLiteralExpression()
				if arrayLiteral == nil {
					return
				}
				for _, elementNode := range arrayLiteral.Elements.Nodes {
					if elementNode != nil && elementNode.Kind != ast.KindSpreadElement {
						checkExpressionNode(elementNode)
					}
				}
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				body := node.Body()
				if body != nil && !ast.IsBlock(body) {
					checkExpressionNode(body)
				}
			},
			ast.KindBinaryExpression: func(node *ast.Node) {
				if !ast.IsAssignmentExpression(node, false) {
					return
				}
				checkExpressionNode(node.AsBinaryExpression().Right)
			},
			ast.KindCallExpression: checkFunctionCallNode,
			ast.KindNewExpression:  checkFunctionCallNode,
			ast.KindJsxAttribute: func(node *ast.Node) {
				jsxAttribute := node.AsJsxAttribute()
				if jsxAttribute == nil || jsxAttribute.Initializer == nil || jsxAttribute.Initializer.Kind != ast.KindJsxExpression {
					return
				}
				expressionContainer := jsxAttribute.Initializer.AsJsxExpression()
				if expressionContainer != nil && expressionContainer.Expression != nil {
					checkExpressionNode(expressionContainer.Expression)
				}
			},
			ast.KindObjectLiteralExpression: func(node *ast.Node) {
				objectLiteral := node.AsObjectLiteralExpression()
				if objectLiteral == nil {
					return
				}
				for _, propertyNode := range objectLiteral.Properties.Nodes {
					if propertyNode != nil && propertyNode.Kind != ast.KindSpreadAssignment {
						checkObjectProperty(propertyNode)
					}
				}
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				propertyDeclaration := node.AsPropertyDeclaration()
				if propertyDeclaration != nil && propertyDeclaration.Initializer != nil {
					checkExpressionNode(propertyDeclaration.Initializer)
				}
			},
			ast.KindReturnStatement: func(node *ast.Node) {
				returnStatement := node.AsReturnStatement()
				if returnStatement != nil && returnStatement.Expression != nil {
					checkExpressionNode(returnStatement.Expression)
				}
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				variableDeclaration := node.AsVariableDeclaration()
				if variableDeclaration != nil && variableDeclaration.Initializer != nil {
					checkExpressionNode(variableDeclaration.Initializer)
				}
			},
		}
	},
})
