package no_unnecessary_type_parameters

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildSoleMessage(name string, count int, descriptor string) rule.RuleMessage {
	uses := "never used"
	if count == 1 {
		uses = "used only once"
	}
	return rule.RuleMessage{
		Id:          "sole",
		Description: "Type parameter '" + name + "' is " + uses + " in the " + descriptor + " signature.",
	}
}

var genericArrowSingleTypeParamPattern = regexp.MustCompile(`^\s*<\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,?\s*>\s*\(`)

func nodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	text := sourceFile.Text()
	start := node.Pos()
	end := node.End()
	if start < 0 || end > len(text) || start >= end {
		return ""
	}
	return text[start:end]
}

func collectTypeReferences(node *ast.Node, refs map[string]int) {
	if node == nil {
		return
	}
	if node.Kind == ast.KindIdentifier && ast.IsPartOfTypeNode(node) {
		refs[node.AsIdentifier().Text]++
	}
	if node.Kind == ast.KindTypeReference {
		typeRef := node.AsTypeReferenceNode()
		if typeRef != nil && typeRef.TypeName != nil && typeRef.TypeName.Kind == ast.KindIdentifier {
			refs[typeRef.TypeName.AsIdentifier().Text]++
		}
	}
	node.ForEachChild(func(child *ast.Node) bool {
		collectTypeReferences(child, refs)
		return false
	})
}

func countTypeParameterIdentifierReferences(node *ast.Node, typeParamName string) int {
	if node == nil {
		return 0
	}
	count := 0
	if node.Kind == ast.KindIdentifier && ast.IsPartOfTypeNode(node) {
		identifier := node.AsIdentifier()
		if identifier != nil && identifier.Text == typeParamName {
			count++
		}
	}
	node.ForEachChild(func(child *ast.Node) bool {
		count += countTypeParameterIdentifierReferences(child, typeParamName)
		return false
	})
	return count
}

func implicitReturnUsesTypeParam(params []*ast.Node, body *ast.BlockOrExpression, typeParamName string) bool {
	if body == nil {
		return false
	}

	typedParams := map[string]bool{}
	for _, param := range params {
		if param == nil || param.Kind != ast.KindParameter {
			continue
		}
		decl := param.AsParameterDeclaration()
		if decl == nil || decl.Type == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
			continue
		}
		refs := map[string]int{}
		collectTypeReferences(decl.Type, refs)
		if refs[typeParamName] > 0 {
			typedParams[decl.Name().AsIdentifier().Text] = true
		}
	}
	if len(typedParams) == 0 {
		return false
	}

	if body.Kind != ast.KindBlock {
		expr := body.AsNode()
		return expr != nil && expr.Kind == ast.KindIdentifier && typedParams[expr.AsIdentifier().Text]
	}

	block := body.AsBlock()
	if block == nil || block.Statements == nil {
		return false
	}
	for _, stmt := range block.Statements.Nodes {
		if stmt == nil || stmt.Kind != ast.KindReturnStatement {
			continue
		}
		returnStmt := stmt.AsReturnStatement()
		if returnStmt == nil || returnStmt.Expression == nil || returnStmt.Expression.Kind != ast.KindIdentifier {
			continue
		}
		if typedParams[returnStmt.Expression.AsIdentifier().Text] {
			return true
		}
	}
	return false
}

func checkFunctionLike(ctx rule.RuleContext, typeParams []*ast.Node, params []*ast.Node, returnType *ast.Node, body *ast.BlockOrExpression) {
	if len(typeParams) == 0 {
		return
	}

	for _, tpNode := range typeParams {
		if tpNode == nil || tpNode.Kind != ast.KindTypeParameter {
			continue
		}
		tp := tpNode.AsTypeParameter()
		if tp == nil || tp.Name() == nil {
			continue
		}
		name := tp.Name().Text()
		count := countTypeParameterReferencesInParameters(params, name) + countTypeParameterReferencesInTypeNode(returnType, name)
		count += countTypeParameterReferencesInConstraints(typeParams, name)
		if typeQueryUsesTypedParam(returnType, params, name) {
			count++
		}
		if returnType == nil {
			count += countTypeParameterReferencesInReturnExpressions(body, name)
			count += countTypedParameterMentionsInReturnExpressions(params, body, name)
		}
		if count <= 1 && implicitReturnUsesTypeParam(params, body, name) {
			count++
		}
		if count <= 1 {
			ctx.ReportNode(tpNode, buildSoleMessage(name, count, "function"))
		}
	}
}

func checkClassLike(ctx rule.RuleContext, typeParams []*ast.Node, members []*ast.Node) {
	if len(typeParams) == 0 {
		return
	}

	for _, tpNode := range typeParams {
		if tpNode == nil || tpNode.Kind != ast.KindTypeParameter {
			continue
		}
		tp := tpNode.AsTypeParameter()
		if tp == nil || tp.Name() == nil {
			continue
		}
		name := tp.Name().Text()
		score := classTypeParameterUsageScore(members, name)
		if score <= 1 {
			ctx.ReportNode(tpNode, buildSoleMessage(name, score, "class"))
		}
	}
}

func getFunctionLikeTypeParameters(ctx rule.RuleContext, node *ast.Node) []*ast.Node {
	if node == nil {
		return nil
	}
	if params := node.TypeParameters(); len(params) > 0 {
		return params
	}
	if ctx.TypeChecker == nil {
		return nil
	}

	nodeType := ctx.TypeChecker.GetTypeAtLocation(node)
	if nodeType == nil {
		return nil
	}
	signatures := utils.GetCallSignatures(ctx.TypeChecker, nodeType)
	if len(signatures) == 0 {
		return nil
	}
	decl := checker.Signature_declaration(signatures[0])
	if decl == nil {
		return nil
	}
	return decl.TypeParameters()
}

func countTypeParameterReferencesInParameters(params []*ast.Node, typeParamName string) int {
	total := 0
	for _, param := range params {
		if param == nil || param.Kind != ast.KindParameter {
			continue
		}
		decl := param.AsParameterDeclaration()
		if decl == nil || decl.Type == nil {
			continue
		}
		total += countTypeParameterIdentifierReferences(decl.Type, typeParamName)
	}
	return total
}

func countTypeParameterReferencesInTypeNode(typeNode *ast.Node, typeParamName string) int {
	return countTypeParameterIdentifierReferences(typeNode, typeParamName)
}

func countTypeParameterReferencesInConstraints(typeParams []*ast.Node, typeParamName string) int {
	total := 0
	for _, tpNode := range typeParams {
		if tpNode == nil || tpNode.Kind != ast.KindTypeParameter {
			continue
		}
		tp := tpNode.AsTypeParameter()
		if tp == nil {
			continue
		}
		total += countTypeParameterIdentifierReferences(tp.Constraint, typeParamName)
		total += countTypeParameterIdentifierReferences(tp.DefaultType, typeParamName)
	}
	return total
}

func classTypeParameterUsageScore(nodes []*ast.Node, typeParamName string) int {
	isBareReferenceParent := func(node *ast.Node) bool {
		if node == nil {
			return false
		}
		switch node.Kind {
		case ast.KindParameter,
			ast.KindPropertyDeclaration,
			ast.KindPropertySignature,
			ast.KindMethodDeclaration,
			ast.KindMethodSignature,
			ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindTypeAliasDeclaration,
			ast.KindVariableDeclaration,
			ast.KindCallSignature,
			ast.KindConstructSignature,
			ast.KindFunctionType,
			ast.KindConstructorType,
			ast.KindTypePredicate,
			ast.KindIndexSignature,
			ast.KindTypeParameter:
			return true
		default:
			return false
		}
	}

	score := 0
	var walk func(node *ast.Node, parent *ast.Node, grandParent *ast.Node)
	walk = func(node *ast.Node, parent *ast.Node, grandParent *ast.Node) {
		if node == nil {
			return
		}

		if node.Kind == ast.KindIdentifier && ast.IsPartOfTypeNode(node) {
			identifier := node.AsIdentifier()
			if identifier != nil && identifier.Text == typeParamName {
				score++

				isBare := false
				if parent != nil && parent.Kind == ast.KindTypeReference {
					typeRef := parent.AsTypeReferenceNode()
					if typeRef != nil && typeRef.TypeName == node && isBareReferenceParent(grandParent) {
						isBare = true
					}
				}

				if !isBare {
					score++
				}
			}
		}

		node.ForEachChild(func(child *ast.Node) bool {
			walk(child, node, parent)
			return false
		})
	}

	for _, node := range nodes {
		walk(node, nil, nil)
	}
	return score
}

func typeQueryUsesTypedParam(returnType *ast.Node, params []*ast.Node, typeParamName string) bool {
	if returnType == nil {
		return false
	}

	typedParams := map[string]bool{}
	for _, param := range params {
		if param == nil || param.Kind != ast.KindParameter {
			continue
		}
		decl := param.AsParameterDeclaration()
		if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
			continue
		}
		if countTypeParameterReferencesInTypeNode(decl.Type, typeParamName) > 0 {
			typedParams[decl.Name().AsIdentifier().Text] = true
		}
	}
	if len(typedParams) == 0 {
		return false
	}

	found := false
	var walk func(node *ast.Node)
	walk = func(node *ast.Node) {
		if node == nil || found {
			return
		}
		if node.Kind == ast.KindTypeQuery {
			typeQuery := node.AsTypeQueryNode()
			if typeQuery != nil && typeQuery.ExprName != nil && typeQuery.ExprName.Kind == ast.KindIdentifier {
				queriedName := typeQuery.ExprName.AsIdentifier().Text
				if typedParams[queriedName] {
					found = true
					return
				}
			}
		}
		node.ForEachChild(func(child *ast.Node) bool {
			walk(child)
			return found
		})
	}
	walk(returnType)
	return found
}

func countTypeParameterReferencesInReturnExpressions(body *ast.BlockOrExpression, typeParamName string) int {
	if body == nil {
		return 0
	}
	if body.Kind != ast.KindBlock {
		return countTypeParameterIdentifierReferences(body.AsNode(), typeParamName)
	}

	block := body.AsBlock()
	if block == nil || block.Statements == nil {
		return 0
	}

	total := 0
	for _, stmt := range block.Statements.Nodes {
		if stmt == nil || stmt.Kind != ast.KindReturnStatement {
			continue
		}
		returnStmt := stmt.AsReturnStatement()
		if returnStmt == nil || returnStmt.Expression == nil {
			continue
		}
		total += countTypeParameterIdentifierReferences(returnStmt.Expression, typeParamName)
	}
	return total
}

func countTypedParameterMentionsInReturnExpressions(params []*ast.Node, body *ast.BlockOrExpression, typeParamName string) int {
	if body == nil {
		return 0
	}

	typedParams := map[string]bool{}
	for _, param := range params {
		if param == nil || param.Kind != ast.KindParameter {
			continue
		}
		decl := param.AsParameterDeclaration()
		if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
			continue
		}
		if countTypeParameterIdentifierReferences(decl.Type, typeParamName) > 0 {
			typedParams[decl.Name().AsIdentifier().Text] = true
		}
	}
	if len(typedParams) == 0 {
		return 0
	}

	countIdentifiers := func(expr *ast.Node) int {
		if expr == nil {
			return 0
		}
		count := 0
		var walk func(node *ast.Node)
		walk = func(node *ast.Node) {
			if node == nil {
				return
			}
			if node.Kind == ast.KindIdentifier {
				identifier := node.AsIdentifier()
				if identifier != nil && typedParams[identifier.Text] {
					count++
				}
			}
			node.ForEachChild(func(child *ast.Node) bool {
				walk(child)
				return false
			})
		}
		walk(expr)
		return count
	}

	if body.Kind != ast.KindBlock {
		return countIdentifiers(body.AsNode())
	}

	block := body.AsBlock()
	if block == nil || block.Statements == nil {
		return 0
	}

	total := 0
	for _, stmt := range block.Statements.Nodes {
		if stmt == nil || stmt.Kind != ast.KindReturnStatement {
			continue
		}
		returnStmt := stmt.AsReturnStatement()
		if returnStmt == nil || returnStmt.Expression == nil {
			continue
		}
		total += countIdentifiers(returnStmt.Expression)
	}
	return total
}

func reportGenericArrowTypeParameterFallback(
	ctx rule.RuleContext,
	arrowNode *ast.Node,
	params []*ast.Node,
	returnType *ast.Node,
	body *ast.BlockOrExpression,
) bool {
	text := nodeText(ctx.SourceFile, arrowNode)
	if text == "" {
		return false
	}

	matches := genericArrowSingleTypeParamPattern.FindStringSubmatch(text)
	if len(matches) != 2 {
		return false
	}
	typeParamName := matches[1]
	parameterRefCount := countTypeParameterReferencesInParameters(params, typeParamName)
	returnTypeRefCount := countTypeParameterReferencesInTypeNode(returnType, typeParamName)
	count := parameterRefCount + returnTypeRefCount
	if count <= 1 && implicitReturnUsesTypeParam(params, body, typeParamName) {
		count++
	}
	if count != 1 {
		return false
	}

	start := arrowNode.Pos() + strings.Index(text, typeParamName)
	end := start + len(typeParamName)
	if start < arrowNode.Pos() || end > arrowNode.End() {
		return false
	}
	ctx.ReportRange(core.NewTextRange(start, end), buildSoleMessage(typeParamName, count, "function"))
	return true
}

var NoUnnecessaryTypeParametersRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-parameters",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		checkFunctionLikeNode := func(node *ast.Node, body *ast.BlockOrExpression) {
			if node == nil {
				return
			}
			params := node.Parameters()
			checkFunctionLike(ctx, getFunctionLikeTypeParameters(ctx, node), params, node.Type(), body)
		}

		return rule.RuleListeners{
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				fn := node.AsFunctionDeclaration()
				if fn != nil {
					checkFunctionLikeNode(node, fn.Body)
				}
			},
			ast.KindFunctionExpression: func(node *ast.Node) {
				fn := node.AsFunctionExpression()
				if fn != nil {
					checkFunctionLikeNode(node, fn.Body)
				}
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				fn := node.AsArrowFunction()
				if fn != nil {
					checkFunctionLikeNode(node, fn.Body)
				}
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				fn := node.AsMethodDeclaration()
				if fn != nil {
					checkFunctionLikeNode(node, fn.Body)
				}
			},
			ast.KindMethodSignature: func(node *ast.Node) {
				checkFunctionLikeNode(node, nil)
			},
			ast.KindCallSignature: func(node *ast.Node) {
				checkFunctionLikeNode(node, nil)
			},
			ast.KindConstructSignature: func(node *ast.Node) {
				checkFunctionLikeNode(node, nil)
			},
			ast.KindFunctionType: func(node *ast.Node) {
				checkFunctionLikeNode(node, nil)
			},
			ast.KindConstructorType: func(node *ast.Node) {
				checkFunctionLikeNode(node, nil)
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				classDecl := node.AsClassDeclaration()
				if classDecl == nil || classDecl.Members == nil {
					return
				}
				checkClassLike(ctx, node.TypeParameters(), classDecl.Members.Nodes)
			},
			ast.KindClassExpression: func(node *ast.Node) {
				classExpr := node.AsClassExpression()
				if classExpr == nil || classExpr.Members == nil {
					return
				}
				checkClassLike(ctx, node.TypeParameters(), classExpr.Members.Nodes)
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				decl := node.AsVariableDeclaration()
				if decl == nil || decl.Initializer == nil || decl.Initializer.Kind != ast.KindArrowFunction {
					return
				}
				arrowNode := decl.Initializer.AsNode()
				if len(arrowNode.TypeParameters()) > 0 {
					return
				}
				arrow := decl.Initializer.AsArrowFunction()
				if arrow == nil || arrow.Parameters == nil {
					return
				}
				reportGenericArrowTypeParameterFallback(ctx, arrowNode, arrow.Parameters.Nodes, arrow.Type, arrow.Body)
			},
		}
	},
})
