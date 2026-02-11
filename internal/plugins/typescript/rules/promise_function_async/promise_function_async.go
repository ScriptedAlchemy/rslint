package promise_function_async

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildMissingAsyncMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingAsync",
		Description: "Functions that return promises must be async.",
	}
}

func buildMissingAsyncHybridReturnMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingAsyncHybridReturn",
		Description: "Functions that return promises and non-promises must be async.",
	}
}

type PromiseFunctionAsyncOptions struct {
	AllowAny *bool
	// TODO(port): TypeOrValueSpecifier
	AllowedPromiseNames       []string
	CheckArrowFunctions       *bool
	CheckFunctionDeclarations *bool
	CheckFunctionExpressions  *bool
	CheckMethodDeclarations   *bool
}

func parseOptions(options any) PromiseFunctionAsyncOptions {
	opts := PromiseFunctionAsyncOptions{}

	applyMap := func(raw map[string]interface{}) {
		if raw == nil {
			return
		}
		if v, ok := raw["allowAny"].(bool); ok {
			opts.AllowAny = utils.Ref(v)
		}
		if names, ok := raw["allowedPromiseNames"].([]interface{}); ok {
			opts.AllowedPromiseNames = make([]string, 0, len(names))
			for _, name := range names {
				if text, ok := name.(string); ok {
					opts.AllowedPromiseNames = append(opts.AllowedPromiseNames, text)
				}
			}
		}
		if v, ok := raw["checkArrowFunctions"].(bool); ok {
			opts.CheckArrowFunctions = utils.Ref(v)
		}
		if v, ok := raw["checkFunctionDeclarations"].(bool); ok {
			opts.CheckFunctionDeclarations = utils.Ref(v)
		}
		if v, ok := raw["checkFunctionExpressions"].(bool); ok {
			opts.CheckFunctionExpressions = utils.Ref(v)
		}
		if v, ok := raw["checkMethodDeclarations"].(bool); ok {
			opts.CheckMethodDeclarations = utils.Ref(v)
		}
	}

	switch raw := options.(type) {
	case PromiseFunctionAsyncOptions:
		opts = raw
	case *PromiseFunctionAsyncOptions:
		if raw != nil {
			opts = *raw
		}
	case map[string]interface{}:
		applyMap(raw)
	case []interface{}:
		if len(raw) > 0 {
			if firstMap, ok := raw[0].(map[string]interface{}); ok {
				applyMap(firstMap)
			}
		}
	}

	if opts.AllowAny == nil {
		opts.AllowAny = utils.Ref(true)
	}
	if opts.AllowedPromiseNames == nil {
		opts.AllowedPromiseNames = []string{}
	}
	if opts.CheckArrowFunctions == nil {
		opts.CheckArrowFunctions = utils.Ref(true)
	}
	if opts.CheckFunctionDeclarations == nil {
		opts.CheckFunctionDeclarations = utils.Ref(true)
	}
	if opts.CheckFunctionExpressions == nil {
		opts.CheckFunctionExpressions = utils.Ref(true)
	}
	if opts.CheckMethodDeclarations == nil {
		opts.CheckMethodDeclarations = utils.Ref(true)
	}

	return opts
}

var PromiseFunctionAsyncRule = rule.CreateRule(rule.Rule{
	Name: "promise-function-async",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		allAllowedPromiseNames := utils.NewSetWithSizeHint[string](len(opts.AllowedPromiseNames))
		allAllowedPromiseNames.Add("Promise")
		for _, name := range opts.AllowedPromiseNames {
			allAllowedPromiseNames.Add(name)
		}

		var containsAllTypesByName func(t *checker.Type, matchAnyInstead bool) bool
		containsAllTypesByName = func(t *checker.Type, matchAnyInstead bool) bool {
			if utils.IsTypeFlagSet(t, checker.TypeFlagsAnyOrUnknown) {
				return false
			}

			if utils.IsTypeFlagSet(t, checker.TypeFlagsObject) && checker.Type_objectFlags(t)&checker.ObjectFlagsReference != 0 {
				t = t.Target()
			}

			symbol := checker.Type_symbol(t)
			if symbol != nil && allAllowedPromiseNames.Has(symbol.Name) {
				return true
			}

			predicate := func(t *checker.Type) bool {
				return containsAllTypesByName(t, matchAnyInstead)
			}

			if utils.IsUnionType(t) || utils.IsIntersectionType(t) {
				if matchAnyInstead {
					return utils.Every(t.Types(), predicate)
				}
				return utils.Some(t.Types(), predicate)
			}

			if checker.Type_objectFlags(t)&checker.ObjectFlagsClassOrInterface == 0 {
				return false
			}

			bases := checker.Checker_getBaseTypes(ctx.TypeChecker, t)
			if matchAnyInstead {
				return utils.Some(bases, predicate)
			}
			return len(bases) > 0 && utils.Every(bases, predicate)
		}

		listeners := make(rule.RuleListeners, 3)

		validateNode := func(node *ast.Node) {
			if utils.IncludesModifier(node, ast.KindAsyncKeyword) || node.Body() == nil {
				return
			}

			t := ctx.TypeChecker.GetTypeAtLocation(node)
			signatures := utils.GetCallSignatures(ctx.TypeChecker, t)
			if len(signatures) == 0 {
				return
			}

			everySignatureReturnsPromise := true
			hasHybridReturn := false
			hasExplicitReturnType := node.Type() != nil
			for _, signature := range signatures {
				returnType := checker.Checker_getReturnTypeOfSignature(ctx.TypeChecker, signature)
				if !*opts.AllowAny && utils.IsTypeFlagSet(returnType, checker.TypeFlagsAnyOrUnknown) {
					// Report without auto fixer because the return type is unknown
					// TODO(port): getFunctionHeadLoc
					ctx.ReportNode(node, buildMissingAsyncMessage())
					return
				}

				hasPromiseReturn := containsAllTypesByName(returnType, false)
				allPromiseReturn := containsAllTypesByName(returnType, true)
				signatureQualifies := hasPromiseReturn
				if hasExplicitReturnType {
					signatureQualifies = allPromiseReturn
				}
				everySignatureReturnsPromise = everySignatureReturnsPromise && signatureQualifies
				if !hasExplicitReturnType && hasPromiseReturn && !allPromiseReturn {
					hasHybridReturn = true
				}
			}

			if !everySignatureReturnsPromise {
				return
			}

			insertAsyncBeforeNode := node
			reportMethodWithRange := false
			reportStart := node.Pos()
			if ast.IsMethodDeclaration(node) {
				insertAsyncBeforeNode = node.Name()
				hasDecorator := false
				if modifiers := node.Modifiers(); modifiers != nil {
					for _, modifier := range modifiers.Nodes {
						if modifier == nil {
							continue
						}
						if modifier.Kind == ast.KindDecorator {
							hasDecorator = true
						}
					}
				}
				if hasDecorator && node.Name() != nil {
					reportMethodWithRange = true
					reportStart = node.Name().Pos()
					sourceText := ctx.SourceFile.Text()
					for reportStart > 0 && sourceText[reportStart-1] != '\n' && sourceText[reportStart-1] != '\r' {
						reportStart--
					}
					for reportStart < len(sourceText) && (sourceText[reportStart] == ' ' || sourceText[reportStart] == '\t') {
						reportStart++
					}
				}
			}

			fix := rule.RuleFixInsertBefore(ctx.SourceFile, insertAsyncBeforeNode, " async ")
			message := buildMissingAsyncMessage()
			if hasHybridReturn {
				message = buildMissingAsyncHybridReturnMessage()
			}
			if reportMethodWithRange {
				ctx.ReportRangeWithFixes(core.NewTextRange(reportStart, node.End()), message, fix)
				return
			}
			ctx.ReportNodeWithFixes(node, message, fix)
		}

		if *opts.CheckArrowFunctions {
			listeners[ast.KindArrowFunction] = validateNode
		}

		if *opts.CheckFunctionDeclarations {
			listeners[ast.KindFunctionDeclaration] = validateNode
		}

		if *opts.CheckFunctionExpressions {
			listeners[ast.KindFunctionExpression] = validateNode
		}

		if *opts.CheckMethodDeclarations {
			listeners[ast.KindMethodDeclaration] = func(node *ast.Node) {
				if utils.IncludesModifier(node, ast.KindAbstractKeyword) {
					// Abstract method can't be async
					return
				}
				validateNode(node)
			}
		}

		return listeners
	},
})
