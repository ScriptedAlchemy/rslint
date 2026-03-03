package consistent_return

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ConsistentReturnOptions struct {
	TreatUndefinedAsUnspecified bool `json:"treatUndefinedAsUnspecified"`
}

// ConsistentReturnRule enforces consistent return statements
var ConsistentReturnRule = rule.CreateRule(rule.Rule{
	Name: "consistent-return",
	Run:  run,
})

// functionInfo tracks information about a function's return statements
type functionInfo struct {
	node                   *ast.Node
	ignoreBareReturns      bool
	expectedReturnHasValue *bool
}

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := ConsistentReturnOptions{
		TreatUndefinedAsUnspecified: false,
	}

	// Parse options
	if options != nil {
		if optArray, isArray := options.([]interface{}); isArray && len(optArray) > 0 {
			if optsMap, ok := optArray[0].(map[string]interface{}); ok {
				if v, exists := optsMap["treatUndefinedAsUnspecified"].(bool); exists {
					opts.TreatUndefinedAsUnspecified = v
				}
			}
		} else if optsMap, ok := options.(map[string]interface{}); ok {
			if v, exists := optsMap["treatUndefinedAsUnspecified"].(bool); exists {
				opts.TreatUndefinedAsUnspecified = v
			}
		}
	}

	// Helper to check if type is Promise<void>
	isVoidLikeAwaitedType := func(t *checker.Type) bool {
		if t == nil {
			return false
		}
		if utils.IsTypeFlagSet(t, checker.TypeFlagsVoid) {
			return true
		}
		if !utils.IsTypeFlagSet(t, checker.TypeFlagsUnion) {
			return false
		}
		unionParts := utils.UnionTypeParts(t)
		for _, part := range unionParts {
			if part != nil && utils.IsTypeFlagSet(part, checker.TypeFlagsVoid) {
				return true
			}
		}
		return false
	}

	var isPromiseVoid func(typeChecker *checker.Checker, node *ast.Node, typeToCheck *checker.Type) bool
	isPromiseVoid = func(typeChecker *checker.Checker, node *ast.Node, typeToCheck *checker.Type) bool {
		if typeToCheck == nil {
			return false
		}

		// Check if it's a thenable type
		if !utils.IsThenableType(typeChecker, node, typeToCheck) {
			return false
		}

		// Check if it's an object type (Promise<T>)
		if utils.IsObjectType(typeToCheck) {
			typeArgs := checker.Checker_getTypeArguments(typeChecker, typeToCheck)
			if len(typeArgs) > 0 {
				awaitedType := typeArgs[0]
				if isVoidLikeAwaitedType(awaitedType) {
					return true
				}
				// Recursively check for nested Promise<void>
				return isPromiseVoid(typeChecker, node, awaitedType)
			}
		}

		return false
	}

	// Helper to check if a function returns void, undefined, or Promise<void>
	isReturnVoidOrThenableVoid := func(node *ast.Node) bool {
		if ctx.TypeChecker == nil {
			return false
		}

		// Get the type of the function
		funcType := ctx.TypeChecker.GetTypeAtLocation(node)
		if funcType == nil {
			return false
		}

		// Get call signatures
		callSignatures := utils.GetCallSignatures(ctx.TypeChecker, funcType)
		if len(callSignatures) == 0 {
			return false
		}

		for _, sig := range callSignatures {
			returnType := checker.Checker_getReturnTypeOfSignature(ctx.TypeChecker, sig)
			if returnType == nil {
				continue
			}

			isAsync := ast.HasSyntacticModifier(node, ast.ModifierFlagsAsync)
			if isAsync {
				if isPromiseVoid(ctx.TypeChecker, node, returnType) {
					return true
				}
				continue
			}

			if utils.IsTypeFlagSet(returnType, checker.TypeFlagsVoid) {
				return true
			}

			if utils.IsTypeFlagSet(returnType, checker.TypeFlagsUnion) {
				for _, unionPart := range utils.UnionTypeParts(returnType) {
					if unionPart != nil && utils.IsTypeFlagSet(unionPart, checker.TypeFlagsVoid) {
						return true
					}
				}
			}
		}

		return false
	}

	// Helper to check if return type is undefined
	isUndefinedType := func(node *ast.Node) bool {
		if ctx.TypeChecker == nil || node == nil {
			return false
		}

		typeAtLocation := ctx.TypeChecker.GetTypeAtLocation(node)
		if typeAtLocation == nil {
			return false
		}

		return utils.IsTypeFlagSet(typeAtLocation, checker.TypeFlagsUndefined) &&
			!utils.IsTypeFlagSet(typeAtLocation, checker.TypeFlagsUnion)
	}

	// Stack to track nested functions
	functionStack := make([]*functionInfo, 0)

	// Helper to get current function
	getCurrentFunction := func() *functionInfo {
		if len(functionStack) > 0 {
			return functionStack[len(functionStack)-1]
		}
		return nil
	}

	enterFunction := func(node *ast.Node) {
		info := &functionInfo{
			node:                   node,
			ignoreBareReturns:      isReturnVoidOrThenableVoid(node),
			expectedReturnHasValue: nil,
		}
		functionStack = append(functionStack, info)
	}

	exitFunction := func(_ *ast.Node) {
		if len(functionStack) == 0 {
			return
		}

		functionStack = functionStack[:len(functionStack)-1]
	}

	return rule.RuleListeners{
		ast.KindFunctionDeclaration:                      enterFunction,
		rule.ListenerOnExit(ast.KindFunctionDeclaration): exitFunction,

		ast.KindFunctionExpression:                      enterFunction,
		rule.ListenerOnExit(ast.KindFunctionExpression): exitFunction,

		ast.KindArrowFunction:                      enterFunction,
		rule.ListenerOnExit(ast.KindArrowFunction): exitFunction,

		ast.KindMethodDeclaration:                      enterFunction,
		rule.ListenerOnExit(ast.KindMethodDeclaration): exitFunction,

		ast.KindGetAccessor:                      enterFunction,
		rule.ListenerOnExit(ast.KindGetAccessor): exitFunction,

		ast.KindReturnStatement: func(node *ast.Node) {
			funcInfo := getCurrentFunction()
			if funcInfo == nil {
				return
			}

			returnExpr := node.Expression()

			// If no return value and function is configured to ignore bare returns, it's ok.
			if returnExpr == nil && funcInfo.ignoreBareReturns {
				return
			}

			hasValue := returnExpr != nil
			if hasValue && opts.TreatUndefinedAsUnspecified && isUndefinedType(returnExpr) {
				hasValue = false
			}

			if funcInfo.expectedReturnHasValue == nil {
				expected := hasValue
				funcInfo.expectedReturnHasValue = &expected
				return
			}

			expected := *funcInfo.expectedReturnHasValue
			if expected == hasValue {
				return
			}

			if expected {
				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "missingReturnValue",
					Description: "Function has inconsistent return statements. Either all return statements should return a value, or none should.",
				})
				return
			}

			ctx.ReportNode(node, rule.RuleMessage{
				Id:          "unexpectedReturnValue",
				Description: "Function has inconsistent return statements. Either all return statements should return a value, or none should.",
			})
		},
	}
}
