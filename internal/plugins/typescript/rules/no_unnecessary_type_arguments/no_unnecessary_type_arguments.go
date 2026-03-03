package no_unnecessary_type_arguments

import (
	"slices"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildUnnecessaryTypeParameterMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryTypeParameter",
		Description: "This is the default value for this type parameter, so it can be omitted.",
	}
}

func isTypeContextDeclaration(decl *ast.Node) bool {
	return ast.IsTypeAliasDeclaration(decl) || ast.IsInterfaceDeclaration(decl)
}

func isInTypeContext(node *ast.Node) bool {
	return ast.IsTypeReferenceNode(node) || ast.IsInterfaceDeclaration(node.Parent) || ast.IsTypeReferenceNode(node.Parent) || (ast.IsHeritageClause(node.Parent) && node.Parent.AsHeritageClause().Token == ast.KindImplementsKeyword)
}

func normalizedNodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if node == nil {
		return ""
	}
	currentSourceFile := sourceFile
	if currentSourceFile == nil || ast.GetSourceFileOfNode(node) != currentSourceFile {
		currentSourceFile = ast.GetSourceFileOfNode(node)
	}
	if currentSourceFile != nil {
		trimmed := utils.TrimNodeTextRange(currentSourceFile, node)
		text := currentSourceFile.Text()
		if trimmed.Pos() >= 0 && trimmed.End() <= len(text) && trimmed.Pos() < trimmed.End() {
			raw := text[trimmed.Pos():trimmed.End()]
			return strings.Join(strings.Fields(raw), "")
		}
	}
	return ""
}

func isNonAliasExternalTypeIdentifier(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || ctx.SourceFile == nil || node == nil || node.Kind != ast.KindTypeReference {
		return false
	}
	typeRef := node.AsTypeReferenceNode()
	if typeRef == nil || typeRef.TypeName == nil || typeRef.TypeName.Kind != ast.KindIdentifier {
		return false
	}
	symbol := ctx.TypeChecker.GetSymbolAtLocation(typeRef.TypeName)
	if symbol == nil {
		return false
	}
	if symbol.Flags&ast.SymbolFlagsAlias != 0 {
		var found bool
		symbol, found = ctx.TypeChecker.ResolveAlias(symbol)
		if !found || symbol == nil {
			return false
		}
	}
	if len(symbol.Declarations) == 0 {
		return false
	}
	hasTypeAliasDeclaration := false
	allExternal := true
	for _, decl := range symbol.Declarations {
		if decl == nil {
			continue
		}
		if decl.Kind == ast.KindTypeAliasDeclaration {
			hasTypeAliasDeclaration = true
		}
		if ast.GetSourceFileOfNode(decl) == ctx.SourceFile {
			allExternal = false
		}
	}
	return allExternal && !hasTypeAliasDeclaration
}

var NoUnnecessaryTypeArgumentsRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-arguments",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		getTypeParametersFromType := func(node *ast.Node, nodeName *ast.Node) []*ast.Node {
			symbol := ctx.TypeChecker.GetSymbolAtLocation(nodeName)
			if symbol == nil {
				return nil
			}

			if symbol.Flags&ast.SymbolFlagsAlias != 0 {
				var found bool
				symbol, found = ctx.TypeChecker.ResolveAlias(symbol)
				if !found {
					return nil
				}
			}

			if symbol.Declarations == nil {
				return nil
			}

			declarations := slices.Clone(symbol.Declarations)

			nodeInTypeContext := isInTypeContext(node)
			slices.SortFunc(declarations, func(a *ast.Node, b *ast.Node) int {
				if !nodeInTypeContext {
					a, b = b, a
				}
				res := 0

				if isTypeContextDeclaration(a) {
					res -= 1
				}
				if isTypeContextDeclaration(b) {
					res += 1
				}

				return res
			})

			for _, decl := range declarations {
				if ast.IsTypeAliasDeclaration(decl) || ast.IsInterfaceDeclaration(decl) || ast.IsClassLike(decl) {
					return decl.TypeParameters()
				}

				if ast.IsVariableDeclaration(decl) {
					t := checker.Checker_getTypeOfSymbol(ctx.TypeChecker, symbol)
					signatures := utils.GetConstructSignatures(ctx.TypeChecker, t)
					if len(signatures) == 0 {
						continue
					}
					decl := checker.Signature_declaration(signatures[0])
					if decl != nil {
						return decl.TypeParameters()
					}
				}
			}

			return nil
		}

		getTypeParametersFromCall := func(node *ast.Node) []*ast.Node {
			signature := checker.Checker_getResolvedSignature(ctx.TypeChecker, node, nil, checker.CheckModeNormal)
			if signature != nil {
				if declaration := checker.Signature_declaration(signature); declaration != nil {
					return declaration.TypeParameters()
				}
			}
			if ast.IsNewExpression(node) {
				return getTypeParametersFromType(node, node.AsNewExpression().Expression)
			}
			return nil
		}

		checkArgsAndParameters := func(arguments *ast.NodeList, parameters []*ast.Node) {
			if arguments == nil || parameters == nil || len(arguments.Nodes) == 0 || len(parameters) == 0 {
				return
			}

			// Just check the last one. Must specify previous type parameters if the last one is specified.
			i := len(arguments.Nodes) - 1
			arg := arguments.Nodes[i]
			param := parameters[i]

			defaultType := param.AsTypeParameter().DefaultType
			if defaultType == nil {
				return
			}

			defaultTypeText := normalizedNodeText(ctx.SourceFile, defaultType)
			argText := normalizedNodeText(ctx.SourceFile, arg)
			if defaultTypeText == "" || argText == "" {
				return
			}

			isSameText := defaultTypeText == argText
			if !isSameText &&
				isNonAliasExternalTypeIdentifier(ctx, defaultType) &&
				isNonAliasExternalTypeIdentifier(ctx, arg) {
				return
			}

			paramType := ctx.TypeChecker.GetTypeAtLocation(defaultType)
			argType := ctx.TypeChecker.GetTypeAtLocation(arg)

			paramTypeIsError := utils.IsIntrinsicErrorType(paramType)
			argTypeIsError := utils.IsIntrinsicErrorType(argType)
			if paramTypeIsError || argTypeIsError {
				if !isSameText {
					return
				}
			} else {
				if argType != paramType &&
					(utils.IsTypeAnyType(argType) || utils.IsTypeAnyType(paramType) || (!checker.Checker_isTypeStrictSubtypeOf(ctx.TypeChecker, argType, paramType) || !checker.Checker_isTypeStrictSubtypeOf(ctx.TypeChecker, paramType, argType))) {
					return
				}
			}

			var removeRange core.TextRange
			if i == 0 {
				removeRange = scanner.GetRangeOfTokenAtPosition(ctx.SourceFile, arguments.End()).WithPos(arguments.Pos() - 1)
			} else {
				removeRange = arg.Loc.WithPos(arguments.Nodes[i-1].End())
			}
			ctx.ReportNodeWithFixes(arg, buildUnnecessaryTypeParameterMessage(), rule.RuleFixRemoveRange(removeRange))

		}

		return rule.RuleListeners{
			ast.KindExpressionWithTypeArguments: func(node *ast.Node) {
				expr := node.AsExpressionWithTypeArguments()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromType(node, expr.Expression))
			},
			ast.KindTypeReference: func(node *ast.Node) {
				expr := node.AsTypeReference()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromType(node, expr.TypeName))
			},

			ast.KindCallExpression: func(node *ast.Node) {
				expr := node.AsCallExpression()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromCall(node))
			},
			ast.KindNewExpression: func(node *ast.Node) {
				expr := node.AsNewExpression()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromCall(node))
			},
			ast.KindTaggedTemplateExpression: func(node *ast.Node) {
				expr := node.AsTaggedTemplateExpression()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromCall(node))
			},
			ast.KindJsxOpeningElement: func(node *ast.Node) {
				expr := node.AsJsxOpeningElement()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromCall(node))
			},
			ast.KindJsxSelfClosingElement: func(node *ast.Node) {
				expr := node.AsJsxSelfClosingElement()
				checkArgsAndParameters(expr.TypeArguments, getTypeParametersFromCall(node))
			},
		}
	},
})
