package no_unnecessary_type_assertion

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildContextuallyUnnecessaryMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "contextuallyUnnecessary",
		Description: "This assertion is unnecessary since the receiver accepts the original type of the expression.",
	}
}
func buildUnnecessaryAssertionMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryAssertion",
		Description: "This assertion is unnecessary since it does not change the type of the expression.",
	}
}

type NoUnnecessaryTypeAssertionOptions struct {
	// TODO(port): maybe typeOrValueSpecifier?
	TypesToIgnore []string `json:"typesToIgnore"`
	// Whether to check const assertions on literal values
	// When true, reports cases like `const foo = 'bar' as const` where the assertion is unnecessary
	CheckLiteralConstAssertions bool `json:"checkLiteralConstAssertions"`
}

func parseOptions(options any) NoUnnecessaryTypeAssertionOptions {
	opts := NoUnnecessaryTypeAssertionOptions{
		TypesToIgnore: []string{},
	}

	applyJSON := func(raw any) {
		if raw == nil {
			return
		}
		payload, err := json.Marshal(raw)
		if err != nil {
			return
		}
		_ = json.Unmarshal(payload, &opts)
	}

	switch raw := options.(type) {
	case NoUnnecessaryTypeAssertionOptions:
		opts = raw
	case *NoUnnecessaryTypeAssertionOptions:
		if raw != nil {
			opts = *raw
		}
	case map[string]interface{}:
		applyJSON(raw)
	case []interface{}:
		if len(raw) > 0 {
			applyJSON(raw[0])
		}
	default:
		if raw != nil {
			applyJSON(raw)
		}
	}

	if opts.TypesToIgnore == nil {
		opts.TypesToIgnore = []string{}
	}
	return opts
}

var NoUnnecessaryTypeAssertionRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-assertion",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		compilerOptions := ctx.Program.Options()
		isStrictNullChecks := utils.IsStrictCompilerOptionEnabled(
			compilerOptions,
			compilerOptions.StrictNullChecks,
		)

		/**
		 * Returns true if there's a chance the variable has been used before a value has been assigned to it
		 */
		isPossiblyUsedBeforeAssigned := func(node *ast.Node) bool {
			declaration := utils.GetDeclaration(ctx.TypeChecker, node)
			if declaration == nil {
				// don't know what the declaration is for some reason, so just assume the worst
				return true
			}
			// non-strict mode doesn't care about used before assigned errors
			if !isStrictNullChecks {
				return false
			}
			// ignore class properties as they are compile time guarded
			// also ignore function arguments as they can't be used before defined
			if !ast.IsVariableDeclaration(declaration) {
				return false
			}

			decl := declaration.AsVariableDeclaration()

			// For var declarations, we need to check whether the node
			// is actually in a descendant of its declaration or not. If not,
			// it may be used before defined.

			// eg
			// if (Math.random() < 0.5) {
			//     var x: number  = 2;
			// } else {
			//     x!.toFixed();
			// }
			if ast.IsVariableDeclarationList(declaration.Parent) &&
				// var
				declaration.Parent.Flags == ast.NodeFlagsNone {
				// If they are not in the same file it will not exist.
				// This situation must not occur using before defined.
				declaratorScope := ast.GetEnclosingBlockScopeContainer(declaration)
				scope := ast.GetEnclosingBlockScopeContainer(node)

				parentScope := declaratorScope
				for {
					parentScope = ast.GetEnclosingBlockScopeContainer(parentScope)
					if parentScope == nil {
						break
					}
					if parentScope == scope {
						return true
					}
				}
			}

			if
			// is it `const x: number`
			decl.Initializer == nil &&
				decl.ExclamationToken == nil &&
				decl.Type != nil {
				// check if the defined variable type has changed since assignment
				declarationType := checker.Checker_getTypeFromTypeNode(ctx.TypeChecker, declaration.Type())
				t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
				if declarationType == t &&
					// `declare`s are never narrowed, so never skip them
					(!ast.IsVariableDeclarationList(declaration.Parent) || !ast.IsVariableStatement(declaration.Parent.Parent) || !utils.IncludesModifier(declaration.Parent.Parent.AsVariableStatement(), ast.KindDeclareKeyword)) {
					// possibly used before assigned, so just skip it
					// better to false negative and skip it, than false positive and fix to compile erroring code
					//
					// no better way to figure this out right now
					// https://github.com/Microsoft/TypeScript/issues/31124
					return true
				}
			}

			return false
		}
		isConstAssertion := func(node *ast.Node) bool {
			if !ast.IsTypeReferenceNode(node) {
				return false
			}
			typeName := node.AsTypeReferenceNode().TypeName
			return ast.IsIdentifier(typeName) && typeName.Text() == "const"
		}

		isImplicitlyNarrowedLiteralDeclaration := func(node *ast.Node) bool {
			expression := node.Expression()
			/**
			 * Even on `const` variable declarations, template literals with expressions can sometimes be widened without a type assertion.
			 * @see https://github.com/typescript-eslint/typescript-eslint/issues/8737
			 */
			if ast.IsTemplateExpression(expression) {
				return false
			}

			return (ast.IsVariableDeclaration(node.Parent) && ast.IsVariableDeclarationList(node.Parent.Parent) && node.Parent.Parent.Flags&ast.NodeFlagsConst != 0) ||
				(ast.IsPropertyDeclaration(node.Parent) && node.Parent.ModifierFlags()&ast.ModifierFlagsReadonly != 0)

		}

		isTypeUnchanged := func(uncast, cast *checker.Type) bool {
			if uncast == cast {
				return true
			}

			if compilerOptions.ExactOptionalPropertyTypes.IsFalseOrUnknown() {
				return false
			}

			// if !utils.IsTypeFlagSet(uncast, checker.TypeFlagsUndefined) || !utils.IsTypeFlagSet(cast, checker.TypeFlagsUndefined) || !compilerOptions.ExactOptionalPropertyTypes.IsTrue() {
			// 	return false
			// }

			uncastParts := utils.Set[*checker.Type]{}
			uncastHasUndefined := false
			for _, part := range utils.UnionTypeParts(uncast) {
				if utils.IsTypeFlagSet(part, checker.TypeFlagsUndefined) {
					uncastHasUndefined = true
				} else {
					uncastParts.Add(part)
				}
			}

			if !uncastHasUndefined {
				return false
			}

			uncastPartsCount := uncastParts.Len()

			castPartsCount := 0
			castHasUndefined := false
			for _, part := range utils.UnionTypeParts(cast) {
				if utils.IsTypeFlagSet(part, checker.TypeFlagsUndefined) {
					castHasUndefined = true
				} else {
					if !uncastParts.Has(part) {
						return false
					}
					castPartsCount++
					if castPartsCount > uncastPartsCount {
						return false
					}
				}
			}

			return castHasUndefined && uncastPartsCount == castPartsCount
		}

		nullWordPattern := regexp.MustCompile(`\bnull\b`)
		typeNodeContainsNull := func(typeNode *ast.Node) bool {
			if typeNode == nil {
				return false
			}
			sourceText := ctx.SourceFile.Text()
			if typeNode.Pos() < 0 || typeNode.End() > len(sourceText) || typeNode.Pos() >= typeNode.End() {
				return false
			}
			return nullWordPattern.MatchString(sourceText[typeNode.Pos():typeNode.End()])
		}
		expressionDeclarationContainsNull := func(expression *ast.Node) bool {
			if expression == nil {
				return false
			}

			checkSymbolDeclarations := func(symbol *ast.Symbol) bool {
				if symbol == nil {
					return false
				}
				for _, declaration := range symbol.Declarations {
					if declaration == nil {
						continue
					}
					if typeNodeContainsNull(declaration.Type()) {
						return true
					}
				}
				return false
			}

			expression = ast.SkipParentheses(expression)
			if expression == nil {
				return false
			}

			if ast.IsPropertyAccessExpression(expression) {
				propertyAccess := expression.AsPropertyAccessExpression()
				if propertyAccess != nil && propertyAccess.Name() != nil {
					if checkSymbolDeclarations(ctx.TypeChecker.GetSymbolAtLocation(propertyAccess.Name())) {
						return true
					}
					if propertyAccess.Expression != nil {
						objectType := ctx.TypeChecker.GetTypeAtLocation(propertyAccess.Expression)
						if objectType != nil {
							propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, objectType, propertyAccess.Name().Text())
							if propertySymbol != nil {
								propertyType := ctx.TypeChecker.GetTypeOfSymbolAtLocation(propertySymbol, propertyAccess.Expression)
								for _, part := range utils.UnionTypeParts(propertyType) {
									if checker.Type_flags(part)&checker.TypeFlagsNull != 0 {
										return true
									}
								}
							}
						}
					}
				}
			}

			return checkSymbolDeclarations(ctx.TypeChecker.GetSymbolAtLocation(expression))
		}
		jsxPropertyMayIncludeNullFromParameterAnnotation := func(expression *ast.Node) bool {
			if expression == nil || !ast.IsPropertyAccessExpression(expression) {
				return false
			}
			propertyAccess := expression.AsPropertyAccessExpression()
			if propertyAccess == nil || propertyAccess.Expression == nil || propertyAccess.Name() == nil {
				return false
			}
			objectIdentifier := propertyAccess.Expression.AsIdentifier()
			if objectIdentifier == nil {
				return false
			}
			attribute := nodeAncestor(expression, ast.KindJsxAttribute)
			if attribute == nil || attribute.Parent == nil || attribute.Parent.Kind != ast.KindJsxAttributes {
				return false
			}

			propName := propertyAccess.Name().Text()
			sourceText := ctx.SourceFile.Text()
			for current := expression.Parent; current != nil; current = current.Parent {
				switch current.Kind {
				case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindMethodDeclaration:
					var params []*ast.Node
					switch current.Kind {
					case ast.KindFunctionDeclaration:
						params = current.AsFunctionDeclaration().Parameters.Nodes
					case ast.KindFunctionExpression:
						params = current.AsFunctionExpression().Parameters.Nodes
					case ast.KindArrowFunction:
						params = current.AsArrowFunction().Parameters.Nodes
					case ast.KindMethodDeclaration:
						params = current.AsMethodDeclaration().Parameters.Nodes
					}
					for _, paramNode := range params {
						if paramNode == nil || !ast.IsParameter(paramNode) {
							continue
						}
						param := paramNode.AsParameterDeclaration()
						if param == nil || param.Name() == nil || param.Type == nil {
							continue
						}
						if !ast.IsIdentifier(param.Name()) || param.Name().AsIdentifier().Text != objectIdentifier.Text {
							continue
						}
						if param.Type.Pos() < 0 || param.Type.End() > len(sourceText) || param.Type.Pos() >= param.Type.End() {
							continue
						}
						paramTypeText := sourceText[param.Type.Pos():param.Type.End()]
						pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(propName) + `\b\s*\??\s*:\s*[^;\n}]*\bnull\b`)
						if pattern.MatchString(paramTypeText) {
							return true
						}
					}
				}
			}
			return false
		}

		checkTypeAssertion := func(node *ast.Node) {
			typeNode := node.Type()
			if slices.Contains(opts.TypesToIgnore, strings.TrimSpace(ctx.SourceFile.Text()[typeNode.Pos():typeNode.End()])) {
				return
			}

			castType := ctx.TypeChecker.GetTypeAtLocation(node)

			if !utils.IsTypeFlagSet(castType, checker.TypeFlagsStringLiteral|checker.TypeFlagsNumberLiteral|checker.TypeFlagsBigIntLiteral) {
				// Skip const assertions unless checkLiteralConstAssertions is enabled
				if isConstAssertion(typeNode) && !opts.CheckLiteralConstAssertions {
					return
				}
			} else {
				// For literal types with const assertions, skip unless checkLiteralConstAssertions is enabled
				if isConstAssertion(typeNode) && !opts.CheckLiteralConstAssertions {
					return
				}
				// For literal types, only check if it's an implicitly narrowed declaration
				// (e.g., const variable or readonly property)
				// OR if checkLiteralConstAssertions is enabled for explicit const assertions
				if !isImplicitlyNarrowedLiteralDeclaration(node) {
					if !opts.CheckLiteralConstAssertions || !isConstAssertion(typeNode) {
						return
					}
				}
			}

			expression := node.Expression()
			uncastType := ctx.TypeChecker.GetTypeAtLocation(expression)
			if !isTypeUnchanged(uncastType, castType) {
				return
			}

			msg := buildUnnecessaryAssertionMessage()

			if node.Kind == ast.KindAsExpression {
				s := scanner.GetScannerForSourceFile(ctx.SourceFile, expression.End())
				asKeywordRange := s.TokenRange()

				sourceText := ctx.SourceFile.Text()
				startPos := asKeywordRange.Pos()

				if startPos > expression.End() && sourceText[startPos-1] == ' ' {
					if startPos-1 == expression.End() || (startPos-2 >= 0 && sourceText[startPos-2] != ' ') {
						startPos--
					}
				}

				fixRange := asKeywordRange.WithPos(startPos).WithEnd(typeNode.End())
				ctx.ReportNodeWithFixes(node, msg, rule.RuleFixRemoveRange(fixRange))
			} else {
				s := scanner.GetScannerForSourceFile(ctx.SourceFile, node.Pos())
				openingAngleBracket := s.TokenRange()

				fixRange := openingAngleBracket.WithEnd(expression.Pos())
				ctx.ReportNodeWithFixes(node, msg, rule.RuleFixRemoveRange(fixRange))
			}
			// TODO - add contextually unnecessary check for this
		}

		return rule.RuleListeners{
			ast.KindAsExpression:            checkTypeAssertion,
			ast.KindTypeAssertionExpression: checkTypeAssertion,

			ast.KindNonNullExpression: func(node *ast.Node) {
				expression := node.Expression()

				buildRemoveExclamationFix := func() rule.RuleFix {
					s := scanner.GetScannerForSourceFile(ctx.SourceFile, expression.End())
					return rule.RuleFixRemoveRange(s.TokenRange())
				}

				if ast.IsAssignmentExpression(node.Parent, true) {
					if node.Parent.AsBinaryExpression().Left == node {
						ctx.ReportNodeWithFixes(node, buildContextuallyUnnecessaryMessage(), buildRemoveExclamationFix())
					}
					// for all other = assignments we ignore non-null checks
					// this is because non-null assertions can change the type-flow of the code
					// so whilst they might be unnecessary for the assignment - they are necessary
					// for following code
					return
				}

				t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, expression)

				var tFlags checker.TypeFlags
				for _, part := range utils.UnionTypeParts(t) {
					tFlags |= checker.Type_flags(part)
				}

				if tFlags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown|
					checker.TypeFlagsNull|
					checker.TypeFlagsUndefined|
					checker.TypeFlagsVoid) == 0 {
					if ast.IsIdentifier(expression) && isPossiblyUsedBeforeAssigned(expression) {
						return
					}
					ctx.ReportNodeWithFixes(node, buildUnnecessaryAssertionMessage(), buildRemoveExclamationFix())
				} else {
					// we know it's a nullable type
					// so figure out if the variable is used in a place that accepts nullable types
					contextualType := utils.GetContextualType(ctx.TypeChecker, node)
					if contextualType != nil {
						var contextualFlags checker.TypeFlags
						for _, part := range utils.UnionTypeParts(contextualType) {
							contextualFlags |= checker.Type_flags(part)
						}

						if tFlags&checker.TypeFlagsUnknown != 0 && contextualFlags&checker.TypeFlagsUnknown == 0 {
							return
						}

						// in strict mode you can't assign null to undefined, so we have to make sure that
						// the two types share a nullable type
						typeIncludesUndefined := tFlags&checker.TypeFlagsUndefined != 0
						typeIncludesNull := tFlags&checker.TypeFlagsNull != 0
						typeIncludesVoid := tFlags&checker.TypeFlagsVoid != 0

						if !typeIncludesNull && expressionDeclarationContainsNull(expression) {
							typeIncludesNull = true
						}

						contextualTypeIncludesUndefined := contextualFlags&checker.TypeFlagsUndefined != 0
						contextualTypeIncludesNull := contextualFlags&checker.TypeFlagsNull != 0
						contextualTypeIncludesVoid := contextualFlags&checker.TypeFlagsVoid != 0

						// make sure that the parent accepts the same types
						// i.e. assigning `string | null | undefined` to `string | undefined` is invalid
						isValidUndefined := !typeIncludesUndefined || contextualTypeIncludesUndefined
						isValidNull := !typeIncludesNull || contextualTypeIncludesNull
						isValidVoid := !typeIncludesVoid || contextualTypeIncludesVoid

						if isValidUndefined && isValidNull && isValidVoid {
							if jsxPropertyMayIncludeNullFromParameterAnnotation(expression) {
								return
							}
							ctx.ReportNodeWithFixes(node, buildContextuallyUnnecessaryMessage(), buildRemoveExclamationFix())
						}
					}
				}
			},
		}
	},
})

func nodeAncestor(node *ast.Node, kind ast.Kind) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if current.Kind == kind {
			return current
		}
	}
	return nil
}
