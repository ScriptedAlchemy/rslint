package no_base_to_string

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func certaintyToString(certainty usefulness) string {
	switch certainty {
	case usefulnessAlways:
		return "always"
	case usefulnessNever:
		return "will"
	case usefulnessSometimes:
		return "may"
	default:
		panic("unknown certainty")
	}
}

func buildBaseArrayJoinMessage(name string, certainty usefulness) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "baseArrayJoin",
		Description: fmt.Sprintf("Using `join()` for %v %v use Object's default stringification format ('[object Object]') when stringified.", name, certaintyToString(certainty)),
	}
}
func buildBaseToStringMessage(name string, certainty usefulness) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "baseToString",
		Description: fmt.Sprintf("'%v' %v use Object's default stringification format ('[object Object]') when stringified.", name, certaintyToString(certainty)),
	}
}

type NoBaseToStringOptions struct {
	IgnoredTypeNames []string `json:"ignoredTypeNames"`
	CheckUnknown     *bool    `json:"checkUnknown"`
}

func parseOptions(options any) NoBaseToStringOptions {
	opts := NoBaseToStringOptions{
		IgnoredTypeNames: []string{"Error", "RegExp", "URL", "URLSearchParams"},
	}

	applyJSON := func(raw any) {
		if raw == nil {
			return
		}
		rawJSON, err := json.Marshal(raw)
		if err != nil {
			return
		}
		_ = json.Unmarshal(rawJSON, &opts)
	}

	switch raw := options.(type) {
	case NoBaseToStringOptions:
		opts = raw
	case *NoBaseToStringOptions:
		if raw != nil {
			opts = *raw
		}
	case map[string]interface{}:
		applyJSON(raw)
	case []interface{}:
		if len(raw) > 0 {
			applyJSON(raw[0])
		}
	}

	if opts.IgnoredTypeNames == nil {
		opts.IgnoredTypeNames = []string{"Error", "RegExp", "URL", "URLSearchParams"}
	}
	if opts.CheckUnknown == nil {
		opts.CheckUnknown = utils.Ref(false)
	}

	return opts
}

type usefulness uint32

const (
	usefulnessAlways usefulness = iota
	usefulnessNever
	usefulnessSometimes
)

var NoBaseToStringRule = rule.CreateRule(rule.Rule{
	Name: "no-base-to-string",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		sourceShadowsString := false

		containsStringIdentifier := func(node *ast.Node) bool {
			var walk func(current *ast.Node) bool
			walk = func(current *ast.Node) bool {
				if current == nil {
					return false
				}
				if ast.IsIdentifier(current) {
					return current.AsIdentifier().Text == "String"
				}
				found := false
				current.ForEachChild(func(child *ast.Node) bool {
					if walk(child) {
						found = true
						return true
					}
					return false
				})
				return found
			}
			return walk(node)
		}

		for _, statement := range ctx.SourceFile.Statements.Nodes {
			if statement == nil {
				continue
			}
			switch statement.Kind {
			case ast.KindFunctionDeclaration:
				decl := statement.AsFunctionDeclaration()
				if decl != nil && decl.Name() != nil && ast.IsIdentifier(decl.Name()) && decl.Name().AsIdentifier().Text == "String" {
					sourceShadowsString = true
				}
			case ast.KindClassDeclaration:
				decl := statement.AsClassDeclaration()
				if decl != nil && decl.Name() != nil && ast.IsIdentifier(decl.Name()) && decl.Name().AsIdentifier().Text == "String" {
					sourceShadowsString = true
				}
			case ast.KindVariableStatement:
				declList := statement.AsVariableStatement().DeclarationList
				if declList == nil {
					continue
				}
				for _, declaration := range declList.AsVariableDeclarationList().Declarations.Nodes {
					if declaration != nil && declaration.Name() != nil && containsStringIdentifier(declaration.Name()) {
						sourceShadowsString = true
						break
					}
				}
			case ast.KindImportDeclaration:
				importDecl := statement.AsImportDeclaration()
				if importDecl == nil || importDecl.ImportClause == nil {
					continue
				}
				importClause := importDecl.ImportClause.AsImportClause()
				if importClause == nil {
					continue
				}
				if importClause.Name() != nil && ast.IsIdentifier(importClause.Name()) && importClause.Name().AsIdentifier().Text == "String" {
					sourceShadowsString = true
				}
				if importClause.NamedBindings == nil {
					continue
				}
				switch importClause.NamedBindings.Kind {
				case ast.KindNamespaceImport:
					nsImport := importClause.NamedBindings.AsNamespaceImport()
					if nsImport != nil && nsImport.Name() != nil && ast.IsIdentifier(nsImport.Name()) && nsImport.Name().AsIdentifier().Text == "String" {
						sourceShadowsString = true
					}
				case ast.KindNamedImports:
					namedImports := importClause.NamedBindings.AsNamedImports()
					if namedImports == nil {
						continue
					}
					for _, element := range namedImports.Elements.Nodes {
						if element != nil && element.Name() != nil && ast.IsIdentifier(element.Name()) && element.Name().AsIdentifier().Text == "String" {
							sourceShadowsString = true
							break
						}
					}
				}
			}
			if sourceShadowsString {
				break
			}
		}
		if !sourceShadowsString {
			sourceText := ctx.SourceFile.Text()
			sourceShadowsString = strings.Contains(sourceText, "function String(") ||
				strings.Contains(sourceText, "function String <") ||
				strings.Contains(sourceText, "class String") ||
				strings.Contains(sourceText, "const String") ||
				strings.Contains(sourceText, "let String") ||
				strings.Contains(sourceText, "var String") ||
				strings.Contains(sourceText, "import { String")
		}

		var collectToStringCertainty func(
			t *checker.Type,
			visited []*checker.Type,
		) usefulness
		var collectJoinCertainty func(
			t *checker.Type,
			visited []*checker.Type,
		) usefulness

		checkExpression := func(node *ast.Expression, t *checker.Type) {
			// TODO(port): boolean, null, etc?
			if ast.IsLiteralExpression(node) {
				return
			}

			if t == nil {
				t = ctx.TypeChecker.GetTypeAtLocation(node)
			}

			certainty := collectToStringCertainty(
				t,
				[]*checker.Type{},
			)
			if certainty == usefulnessAlways {
				return
			}

			ctx.ReportNode(node, buildBaseToStringMessage(ctx.SourceFile.Text()[node.Pos():node.End()], certainty))
		}

		checkExpressionForArrayJoin := func(
			node *ast.Node,
			t *checker.Type,
		) {
			certainty := collectJoinCertainty(t, []*checker.Type{})

			if certainty == usefulnessAlways {
				return
			}

			ctx.ReportNode(node, buildBaseArrayJoinMessage(ctx.SourceFile.Text()[node.Pos():node.End()], certainty))
		}

		collectUnionTypeCertainty := func(
			t *checker.Type,
			collectSubTypeCertainty func(t *checker.Type) usefulness,
		) usefulness {
			certainties := utils.Map(utils.UnionTypeParts(t), collectSubTypeCertainty)

			if utils.Every(certainties, func(c usefulness) bool { return c == usefulnessNever }) {
				return usefulnessNever
			}

			if utils.Every(certainties, func(c usefulness) bool { return c == usefulnessAlways }) {
				return usefulnessAlways
			}

			return usefulnessSometimes
		}

		collectIntersectionTypeCertainty := func(
			t *checker.Type,
			collectSubTypeCertainty func(t *checker.Type) usefulness,
		) usefulness {
			if utils.Some(utils.IntersectionTypeParts(t), func(t *checker.Type) bool { return collectSubTypeCertainty(t) == usefulnessAlways }) {
				return usefulnessAlways
			}

			return usefulnessNever
		}

		collectTupleCertainty := func(
			t *checker.Type,
			visited []*checker.Type,
		) usefulness {
			typeArgs := checker.Checker_getTypeArguments(ctx.TypeChecker, t)
			certainties := utils.Map(typeArgs, func(t *checker.Type) usefulness {
				return collectToStringCertainty(t, visited)
			})

			if utils.Some(certainties, func(c usefulness) bool { return c == usefulnessNever }) {
				return usefulnessNever
			}

			if utils.Some(certainties, func(c usefulness) bool { return c == usefulnessSometimes }) {
				return usefulnessSometimes
			}

			return usefulnessAlways
		}

		collectArrayCertainty := func(
			t *checker.Type,
			visited []*checker.Type,
		) usefulness {
			elemType := utils.GetNumberIndexType(ctx.TypeChecker, t)
			if elemType == nil {
				panic("array should have number index type")
			}
			return collectToStringCertainty(elemType, visited)
		}

		collectJoinCertainty = func(
			t *checker.Type,
			visited []*checker.Type,
		) usefulness {
			if utils.IsUnionType(t) {
				return collectUnionTypeCertainty(t, func(t *checker.Type) usefulness {
					return collectJoinCertainty(t, visited)
				})
			}

			if utils.IsIntersectionType(t) {
				return collectIntersectionTypeCertainty(t, func(t *checker.Type) usefulness {
					return collectJoinCertainty(t, visited)
				})
			}

			if checker.IsTupleType(t) {
				return collectTupleCertainty(t, visited)
			}

			if checker.Checker_isArrayType(ctx.TypeChecker, t) {
				return collectArrayCertainty(t, visited)
			}

			return usefulnessAlways
		}

		collectToStringCertainty = func(
			t *checker.Type,
			visited []*checker.Type,
		) usefulness {
			if slices.Contains(visited, t) {
				// don't report if this is a self referencing array or tuple type
				return usefulnessAlways
			}

			if utils.IsTypeParameter(t) {
				constraint := checker.Checker_getBaseConstraintOfType(ctx.TypeChecker, t)
				if constraint != nil {
					return collectToStringCertainty(constraint, visited)
				}
				// unconstrained generic means `unknown`
				if *opts.CheckUnknown {
					return usefulnessSometimes
				}
				return usefulnessAlways
			}

			// the Boolean type definition missing toString()
			if utils.IsTypeFlagSet(t, checker.TypeFlagsBooleanLike) {
				return usefulnessAlways
			}

			if slices.Contains(opts.IgnoredTypeNames, utils.GetTypeName(ctx.TypeChecker, t)) {
				return usefulnessAlways
			}

			if utils.IsIntersectionType(t) {
				return collectIntersectionTypeCertainty(t, func(t *checker.Type) usefulness {
					return collectToStringCertainty(t, visited)
				})
			}

			if utils.IsUnionType(t) {
				return collectUnionTypeCertainty(t, func(t *checker.Type) usefulness {
					return collectToStringCertainty(t, visited)
				})
			}

			if checker.IsTupleType(t) {
				return collectTupleCertainty(t, append(visited, t))
			}

			if checker.Checker_isArrayType(ctx.TypeChecker, t) {
				return collectArrayCertainty(t, append(visited, t))
			}

			toString := checker.Checker_getPropertyOfType(ctx.TypeChecker, t, "toString")
			if toString == nil {
				toString = checker.Checker_getPropertyOfType(ctx.TypeChecker, t, "toLocaleString")
			}
			if toString == nil {
				if *opts.CheckUnknown && utils.IsTypeFlagSet(t, checker.TypeFlagsUnknown) {
					return usefulnessSometimes
				}
				// e.g. any/unknown
				return usefulnessAlways
			}

			declarations := toString.Declarations

			if declarations == nil || len(declarations) != 1 {
				// If there are multiple declarations, at least one of them must not be
				// the default object toString.
				//
				// This may only matter for older versions of TS
				// see https://github.com/typescript-eslint/typescript-eslint/issues/8585
				return usefulnessAlways
			}

			declaration := declarations[0]
			isBaseToString := ast.IsInterfaceDeclaration(declaration.Parent) && declaration.Parent.AsInterfaceDeclaration().Name().Text() == "Object"

			if isBaseToString {
				return usefulnessNever
			}

			return usefulnessAlways
		}

		isBuiltInStringCall := func(node *ast.CallExpression) bool {
			if sourceShadowsString {
				return false
			}
			if ast.IsIdentifier(node.Expression) && node.Expression.AsIdentifier().Text == "String" && len(node.Arguments.Nodes) > 0 {
				symbol := ctx.TypeChecker.GetSymbolAtLocation(node.Expression)
				if symbol == nil || symbol.Name != "String" {
					return false
				}
				hasNonDefaultLibraryDecl := utils.Some(symbol.Declarations, func(declaration *ast.Node) bool {
					sourceFile := ast.GetSourceFileOfNode(declaration)
					return sourceFile != nil && !utils.IsSourceFileDefaultLibrary(ctx.Program, sourceFile)
				})
				if hasNonDefaultLibraryDecl {
					return false
				}
				return utils.IsSymbolFromDefaultLibrary(ctx.Program, symbol)
				// TODO(port-scopemanager)
				// const scope = context.sourceCode.getScope(node);
				// // eslint-disable-next-line @typescript-eslint/internal/prefer-ast-types-enum
				// const variable = scope.set.get('String');
				// return !variable?.defs.length;
			}
			return false
		}

		return rule.RuleListeners{
			ast.KindBinaryExpression: func(node *ast.Node) {
				expr := node.AsBinaryExpression()
				if expr.OperatorToken.Kind != ast.KindPlusToken && expr.OperatorToken.Kind != ast.KindPlusEqualsToken {
					return
				}
				leftType := ctx.TypeChecker.GetTypeAtLocation(expr.Left)
				rightType := ctx.TypeChecker.GetTypeAtLocation(expr.Right)

				if utils.GetTypeName(ctx.TypeChecker, leftType) == "string" {
					checkExpression(expr.Right, rightType)
				} else if utils.GetTypeName(ctx.TypeChecker, rightType) == "string" && expr.Left.Kind != ast.KindPrivateIdentifier {
					checkExpression(expr.Left, leftType)
				}
			},
			ast.KindCallExpression: func(node *ast.Node) {

				callExpr := node.AsCallExpression()
				if isBuiltInStringCall(callExpr) && callExpr.Arguments.Nodes[0].Kind != ast.KindSpreadElement {
					checkExpression(callExpr.Arguments.Nodes[0], nil)
					return
				}

				if ast.IsPropertyAccessExpression(callExpr.Expression) {
					memberExpr := callExpr.Expression.AsPropertyAccessExpression()
					propertyName := memberExpr.Name().Text()
					switch propertyName {
					case "join":
						t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, memberExpr.Expression)
						checkExpressionForArrayJoin(memberExpr.Expression, t)
						return
					case "toLocaleString", "toString":
						checkExpression(memberExpr.Expression, nil)
						return
					}
				}
			},
			ast.KindTemplateExpression: func(node *ast.Node) {

				if ast.IsTaggedTemplateExpression(node.Parent) {
					return
				}
				for _, span := range node.AsTemplateExpression().TemplateSpans.Nodes {
					checkExpression(span.Expression(), nil)
				}
			},
		}
	},
})
