package explicit_module_boundary_types

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ExplicitModuleBoundaryTypesOptions struct {
	AllowArgumentsExplicitlyTypedAsAny        bool     `json:"allowArgumentsExplicitlyTypedAsAny"`
	AllowDirectConstAssertionInArrowFunctions bool     `json:"allowDirectConstAssertionInArrowFunctions"`
	AllowHigherOrderFunctions                 bool     `json:"allowHigherOrderFunctions"`
	AllowTypedFunctionExpressions             bool     `json:"allowTypedFunctionExpressions"`
	AllowOverloadFunctions                    bool     `json:"allowOverloadFunctions"`
	AllowedNames                              []string `json:"allowedNames"`
}

func parseOptions(options any) ExplicitModuleBoundaryTypesOptions {
	opts := ExplicitModuleBoundaryTypesOptions{
		AllowArgumentsExplicitlyTypedAsAny:        false,
		AllowDirectConstAssertionInArrowFunctions: true,
		AllowHigherOrderFunctions:                 true,
		AllowTypedFunctionExpressions:             true,
		AllowOverloadFunctions:                    false,
		AllowedNames:                              []string{},
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
	if v, ok := optsMap["allowArgumentsExplicitlyTypedAsAny"].(bool); ok {
		opts.AllowArgumentsExplicitlyTypedAsAny = v
	}
	if v, ok := optsMap["allowDirectConstAssertionInArrowFunctions"].(bool); ok {
		opts.AllowDirectConstAssertionInArrowFunctions = v
	}
	if v, ok := optsMap["allowHigherOrderFunctions"].(bool); ok {
		opts.AllowHigherOrderFunctions = v
	}
	if v, ok := optsMap["allowTypedFunctionExpressions"].(bool); ok {
		opts.AllowTypedFunctionExpressions = v
	}
	if v, ok := optsMap["allowOverloadFunctions"].(bool); ok {
		opts.AllowOverloadFunctions = v
	}
	if v, ok := optsMap["allowedNames"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				opts.AllowedNames = append(opts.AllowedNames, s)
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

func buildMissingArgTypeMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingArgType",
		Description: "Argument '" + name + "' should be typed.",
	}
}

func buildMissingArgTypeUnnamedMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingArgTypeUnnamed",
		Description: "All arguments should be typed.",
	}
}

func buildAnyTypedArgMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "anyTypedArg",
		Description: "Argument '" + name + "' should be typed with a non-any type.",
	}
}

func buildAnyTypedArgUnnamedMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "anyTypedArgUnnamed",
		Description: "All arguments should be typed with a non-any type.",
	}
}

func isAllowedName(name string, allowed []string) bool {
	for _, n := range allowed {
		if n == name {
			return true
		}
	}
	return false
}

func staticNameFromNode(node *ast.Node) (string, bool) {
	if node == nil {
		return "", false
	}

	switch node.Kind {
	case ast.KindIdentifier:
		id := node.AsIdentifier()
		if id == nil {
			return "", false
		}
		return id.Text, true
	case ast.KindStringLiteral:
		lit := node.AsStringLiteral()
		if lit == nil {
			return "", false
		}
		return lit.Text, true
	case ast.KindNumericLiteral:
		lit := node.AsNumericLiteral()
		if lit == nil {
			return "", false
		}
		return lit.Text, true
	case ast.KindNoSubstitutionTemplateLiteral:
		lit := node.AsNoSubstitutionTemplateLiteral()
		if lit == nil {
			return "", false
		}
		return lit.Text, true
	case ast.KindNullKeyword:
		return "null", true
	case ast.KindTrueKeyword:
		return "true", true
	case ast.KindFalseKeyword:
		return "false", true
	case ast.KindComputedPropertyName:
		computed := node.AsComputedPropertyName()
		if computed == nil || computed.Expression == nil {
			return "", false
		}
		return staticNameFromNode(unwrapReturnedExpression(computed.Expression))
	}

	return "", false
}

func checkParameters(ctx rule.RuleContext, params []*ast.Node, opts ExplicitModuleBoundaryTypesOptions) {
	for _, p := range params {
		if p == nil || !ast.IsParameter(p) {
			continue
		}
		param := p.AsParameterDeclaration()
		if param == nil || param.Name() == nil {
			continue
		}
		hasAccessibilityModifier := ast.GetCombinedModifierFlags(p)&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0
		isRestParameterProperty := hasAccessibilityModifier && param.DotDotDotToken != nil
		isRestParameter := param.DotDotDotToken != nil
		hasNamedIdentifier := param.Name().Kind == ast.KindIdentifier
		name := ""
		if hasNamedIdentifier {
			name = param.Name().AsIdentifier().Text
		}

		// Assignment patterns are considered typed by assignment value in upstream rule.
		if param.Initializer != nil && param.Type == nil {
			continue
		}

		if param.Type == nil {
			reportNode := p
			if param.Name() != nil && !isRestParameterProperty && !isRestParameter {
				reportNode = param.Name()
			}
			if hasNamedIdentifier {
				ctx.ReportNode(reportNode, buildMissingArgTypeMessage(name))
			} else {
				ctx.ReportNode(reportNode, buildMissingArgTypeUnnamedMessage())
			}
			continue
		}
		if !opts.AllowArgumentsExplicitlyTypedAsAny && param.Type.Kind == ast.KindAnyKeyword {
			reportNode := p
			if param.Name() != nil && !isRestParameterProperty && !isRestParameter {
				reportNode = param.Name()
			}
			if hasNamedIdentifier {
				ctx.ReportNode(reportNode, buildAnyTypedArgMessage(name))
			} else {
				ctx.ReportNode(reportNode, buildAnyTypedArgUnnamedMessage())
			}
		}
	}
}

func checkParametersWithReportNode(ctx rule.RuleContext, params []*ast.Node, opts ExplicitModuleBoundaryTypesOptions, forcedReportNode *ast.Node) {
	if forcedReportNode == nil {
		checkParameters(ctx, params, opts)
		return
	}
	for _, p := range params {
		if p == nil || !ast.IsParameter(p) {
			continue
		}
		param := p.AsParameterDeclaration()
		if param == nil || param.Name() == nil {
			continue
		}
		hasNamedIdentifier := param.Name().Kind == ast.KindIdentifier
		name := ""
		if hasNamedIdentifier {
			name = param.Name().AsIdentifier().Text
		}
		if param.Initializer != nil && param.Type == nil {
			continue
		}
		if param.Type == nil {
			if hasNamedIdentifier {
				ctx.ReportNode(forcedReportNode, buildMissingArgTypeMessage(name))
			} else {
				ctx.ReportNode(forcedReportNode, buildMissingArgTypeUnnamedMessage())
			}
			continue
		}
		if !opts.AllowArgumentsExplicitlyTypedAsAny && param.Type.Kind == ast.KindAnyKeyword {
			if hasNamedIdentifier {
				ctx.ReportNode(forcedReportNode, buildAnyTypedArgMessage(name))
			} else {
				ctx.ReportNode(forcedReportNode, buildAnyTypedArgUnnamedMessage())
			}
		}
	}
}

func unwrapReturnedExpression(node *ast.Node) *ast.Node {
	current := node
	for current != nil {
		switch current.Kind {
		case ast.KindParenthesizedExpression:
			paren := current.AsParenthesizedExpression()
			if paren == nil || paren.Expression == nil {
				return current
			}
			current = paren.Expression
		case ast.KindAsExpression:
			asExpr := current.AsAsExpression()
			if asExpr == nil || asExpr.Expression == nil {
				return current
			}
			current = asExpr.Expression
		case ast.KindNonNullExpression:
			nonNull := current.AsNonNullExpression()
			if nonNull == nil || nonNull.Expression == nil {
				return current
			}
			current = nonNull.Expression
		default:
			return current
		}
	}
	return nil
}

func hasImmediateFunctionReturn(body *ast.BlockOrExpression) bool {
	if body == nil || body.Kind != ast.KindBlock {
		return false
	}
	block := body.AsBlock()
	if block == nil || block.Statements == nil || len(block.Statements.Nodes) == 0 {
		return false
	}

	foundReturn := false
	for _, statement := range block.Statements.Nodes {
		if statement == nil {
			continue
		}
		switch statement.Kind {
		case ast.KindIfStatement, ast.KindSwitchStatement, ast.KindForStatement, ast.KindForInStatement, ast.KindForOfStatement, ast.KindWhileStatement, ast.KindDoStatement, ast.KindTryStatement:
			return false
		}
		if statement.Kind != ast.KindReturnStatement {
			continue
		}
		foundReturn = true
		returnStmt := statement.AsReturnStatement()
		if returnStmt == nil || returnStmt.Expression == nil {
			return false
		}
		expr := unwrapReturnedExpression(returnStmt.Expression)
		if expr == nil {
			return false
		}
		switch expr.Kind {
		case ast.KindArrowFunction:
			if expr.AsArrowFunction() == nil {
				return false
			}
		case ast.KindFunctionExpression:
			if expr.AsFunctionExpression() == nil {
				return false
			}
		default:
			return false
		}
	}

	return foundReturn
}

func getImmediateReturnedFunctions(body *ast.BlockOrExpression) []*ast.Node {
	if body == nil {
		return nil
	}
	if body.Kind == ast.KindBlock {
		block := body.AsBlock()
		if block == nil || block.Statements == nil {
			return nil
		}
		returnedFns := []*ast.Node{}
		for _, statement := range block.Statements.Nodes {
			if statement == nil || statement.Kind != ast.KindReturnStatement {
				continue
			}
			returnStmt := statement.AsReturnStatement()
			if returnStmt == nil || returnStmt.Expression == nil {
				return nil
			}
			expr := unwrapReturnedExpression(returnStmt.Expression)
			if expr == nil {
				return nil
			}
			if expr.Kind != ast.KindArrowFunction && expr.Kind != ast.KindFunctionExpression {
				return nil
			}
			returnedFns = append(returnedFns, expr)
		}
		if len(returnedFns) == 0 {
			return nil
		}
		return returnedFns
	}

	expr := unwrapReturnedExpression(body.AsNode())
	if expr == nil {
		return nil
	}
	switch expr.Kind {
	case ast.KindArrowFunction:
		if expr.AsArrowFunction() != nil {
			return []*ast.Node{expr}
		}
	case ast.KindFunctionExpression:
		if expr.AsFunctionExpression() != nil {
			return []*ast.Node{expr}
		}
	}
	return nil
}

func isHigherOrderFunctionBody(body *ast.BlockOrExpression) bool {
	if body == nil {
		return false
	}
	if body.Kind == ast.KindBlock {
		return hasImmediateFunctionReturn(body)
	}
	return len(getImmediateReturnedFunctions(body)) > 0
}

func getImmediateReturnedFunction(body *ast.BlockOrExpression) *ast.Node {
	if body == nil {
		return nil
	}
	returnedFns := getImmediateReturnedFunctions(body)
	if len(returnedFns) == 0 {
		return nil
	}
	return returnedFns[len(returnedFns)-1]
}

func reportHigherOrderReturnedFunctions(ctx rule.RuleContext, body *ast.BlockOrExpression, opts ExplicitModuleBoundaryTypesOptions) {
	returnedFn := getImmediateReturnedFunction(body)
	if returnedFn == nil {
		return
	}

	switch returnedFn.Kind {
	case ast.KindArrowFunction:
		arrow := returnedFn.AsArrowFunction()
		if arrow == nil {
			return
		}
		isHigherOrder := opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(arrow.Body)
		if arrow.Type == nil && !isHigherOrder {
			ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
		}
		if arrow.Parameters != nil {
			checkParameters(ctx, arrow.Parameters.Nodes, opts)
		}
		if isHigherOrder && arrow.Type == nil {
			reportHigherOrderReturnedFunctions(ctx, arrow.Body, opts)
		}
	case ast.KindFunctionExpression:
		fnExpr := returnedFn.AsFunctionExpression()
		if fnExpr == nil {
			return
		}
		isHigherOrder := opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(fnExpr.Body)
		if fnExpr.Type == nil && !isHigherOrder {
			ctx.ReportRange(functionExpressionKeywordRange(returnedFn), buildMissingReturnTypeMessage())
		}
		if fnExpr.Parameters != nil {
			checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
		}
		if isHigherOrder && fnExpr.Type == nil {
			reportHigherOrderReturnedFunctions(ctx, fnExpr.Body, opts)
		}
	}
}

func functionDeclarationSignatureRange(fn *ast.FunctionDeclaration) core.TextRange {
	if fn == nil {
		return core.NewTextRange(0, 0)
	}
	start := fn.Pos()
	if fn.Name() != nil {
		candidate := fn.Name().Pos() - len("function ") + 1
		if candidate >= start {
			start = candidate
		}
	}

	end := fn.End()
	if fn.Name() != nil {
		end = fn.Name().End()
	}
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func functionExpressionKeywordRange(node *ast.Node) core.TextRange {
	if node == nil {
		return core.NewTextRange(0, 0)
	}
	start := node.Pos() + 1
	end := start + len("function ")
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func functionKeywordRangeInNode(sourceFile *ast.SourceFile, node *ast.Node) core.TextRange {
	if sourceFile == nil || node == nil {
		return core.NewTextRange(0, 0)
	}
	text := sourceFile.Text()
	start := node.Pos()
	end := node.End()
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	if start >= end {
		return core.NewTextRange(start, start)
	}
	segment := text[start:end]
	if idx := strings.Index(segment, "function"); idx >= 0 {
		functionStart := start + idx
		functionEnd := functionStart + len("function") + 1
		if functionEnd > end {
			functionEnd = end
		}
		return core.NewTextRange(functionStart, functionEnd)
	}
	return core.NewTextRange(start, start)
}

func arrowOperatorRange(sourceFile *ast.SourceFile, arrow *ast.ArrowFunction) core.TextRange {
	if sourceFile == nil || arrow == nil || arrow.Body == nil {
		return core.NewTextRange(0, 0)
	}
	start := arrow.Pos()
	if arrow.Parameters != nil && len(arrow.Parameters.Nodes) > 0 {
		lastParam := arrow.Parameters.Nodes[len(arrow.Parameters.Nodes)-1]
		if lastParam != nil {
			start = lastParam.End()
		}
	}
	if arrow.Type != nil {
		start = arrow.Type.End()
	}
	end := arrow.Body.Pos()
	text := sourceFile.Text()
	if start >= 0 && end > start && end <= len(text) {
		segment := text[start:end]
		if idx := strings.Index(segment, "=>"); idx >= 0 {
			return core.NewTextRange(start+idx, start+idx+len("=>"))
		}
	}
	return core.NewTextRange(start, start+len("=>"))
}

func hasFunctionOverloadSignatures(node *ast.Node, fn *ast.FunctionDeclaration) bool {
	if node == nil || fn == nil || node.Parent == nil {
		return false
	}

	currentName := ""
	hasName := fn.Name() != nil
	if hasName {
		currentName = fn.Name().Text()
	}
	isAnonymousDefaultExport := !hasName && ast.HasSyntacticModifier(node, ast.ModifierFlagsExport) && ast.HasSyntacticModifier(node, ast.ModifierFlagsDefault)
	var siblings []*ast.Node
	switch node.Parent.Kind {
	case ast.KindSourceFile:
		source := node.Parent.AsSourceFile()
		if source == nil || source.Statements == nil {
			return false
		}
		siblings = source.Statements.Nodes
	case ast.KindModuleBlock:
		module := node.Parent.AsModuleBlock()
		if module == nil || module.Statements == nil {
			return false
		}
		siblings = module.Statements.Nodes
	default:
		return false
	}

	currentIndex := -1
	for i, sibling := range siblings {
		if sibling == node {
			currentIndex = i
			break
		}
	}
	if currentIndex <= 0 {
		return false
	}

	for i := range currentIndex {
		sibling := siblings[i]
		if sibling == nil || sibling.Kind != ast.KindFunctionDeclaration {
			continue
		}
		overload := sibling.AsFunctionDeclaration()
		if overload == nil {
			continue
		}
		if hasName {
			if overload.Name() == nil || overload.Name().Text() != currentName {
				continue
			}
		} else {
			if !isAnonymousDefaultExport {
				continue
			}
			if overload.Name() != nil {
				continue
			}
			if !ast.HasSyntacticModifier(sibling, ast.ModifierFlagsExport) || !ast.HasSyntacticModifier(sibling, ast.ModifierFlagsDefault) {
				continue
			}
		}
		if overload.Body == nil {
			return true
		}
	}
	return false
}

func hasMethodOverloadSignatures(node *ast.Node, method *ast.MethodDeclaration) bool {
	if node == nil || method == nil || method.Name() == nil || node.Parent == nil {
		return false
	}

	targetName, ok := staticNameFromNode(method.Name())
	if !ok {
		return false
	}
	targetStatic := ast.HasSyntacticModifier(node, ast.ModifierFlagsStatic)

	var members []*ast.Node
	switch node.Parent.Kind {
	case ast.KindClassDeclaration:
		classDecl := node.Parent.AsClassDeclaration()
		if classDecl == nil || classDecl.Members == nil {
			return false
		}
		members = classDecl.Members.Nodes
	case ast.KindClassExpression:
		classExpr := node.Parent.AsClassExpression()
		if classExpr == nil || classExpr.Members == nil {
			return false
		}
		members = classExpr.Members.Nodes
	default:
		return false
	}

	for _, member := range members {
		if member == nil {
			continue
		}
		if member == node {
			break
		}
		if member.Kind != ast.KindMethodDeclaration {
			continue
		}
		methodDecl := member.AsMethodDeclaration()
		if methodDecl == nil || methodDecl.Name() == nil || methodDecl.Body != nil {
			continue
		}
		if ast.HasSyntacticModifier(member, ast.ModifierFlagsStatic) != targetStatic {
			continue
		}
		name, ok := staticNameFromNode(methodDecl.Name())
		if ok && name == targetName {
			return true
		}
	}

	return false
}

func hasDeclaratorTypeAnnotation(sourceFile *ast.SourceFile, decl *ast.VariableDeclaration, value *ast.Node) bool {
	if decl == nil || decl.Name() == nil {
		return false
	}
	if decl.Type != nil {
		return true
	}
	if sourceFile == nil || value == nil {
		return false
	}
	text := sourceFile.Text()
	start := decl.Name().End()
	end := value.Pos()
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	segment := text[start:end]
	return strings.Contains(segment, ":")
}

func findEnclosingVariableStatement(node *ast.Node) *ast.Node {
	current := node
	for current != nil {
		if current.Kind == ast.KindVariableStatement {
			return current
		}
		current = current.Parent
	}
	return nil
}

func isExportedClassLikeNode(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindClassDeclaration:
		return isExportedFunction(node)
	case ast.KindClassExpression:
		return isExportedFunction(findEnclosingVariableStatement(node))
	default:
		return false
	}
}

func bodyHasDirectConstAssertion(sourceFile *ast.SourceFile, body *ast.BlockOrExpression) bool {
	if sourceFile == nil || body == nil || body.Kind == ast.KindBlock {
		return false
	}
	text := sourceFile.Text()
	start := body.Pos()
	end := body.End()
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	segment := text[start:end]
	return strings.Contains(segment, " as const")
}

func leadingTokenOnLineBeforePos(sourceFile *ast.SourceFile, pos int) int {
	if sourceFile == nil {
		return pos
	}

	text := sourceFile.Text()
	if pos < 0 || pos > len(text) {
		return pos
	}

	lineStart := pos
	for lineStart > 0 {
		ch := text[lineStart-1]
		if ch == '\n' || ch == '\r' {
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

func propertyInitializerBoundaryRange(sourceFile *ast.SourceFile, prop *ast.PropertyDeclaration) core.TextRange {
	if prop == nil || prop.Name() == nil || prop.Initializer == nil {
		return core.NewTextRange(0, 0)
	}
	start := leadingTokenOnLineBeforePos(sourceFile, prop.Initializer.Pos())
	end := prop.Initializer.Pos() + 1
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func functionExpressionPropertyBoundaryRange(sourceFile *ast.SourceFile, prop *ast.PropertyDeclaration, fnExpr *ast.FunctionExpression) core.TextRange {
	if prop == nil || prop.Initializer == nil || fnExpr == nil {
		return core.NewTextRange(0, 0)
	}
	start := leadingTokenOnLineBeforePos(sourceFile, prop.Initializer.Pos())
	end := fnExpr.End()
	if fnExpr.Body != nil {
		end = fnExpr.Body.Pos() - 2
	}
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func accessorKeywordRange(nameNode *ast.Node, keyword string) core.TextRange {
	if nameNode == nil {
		return core.NewTextRange(0, 0)
	}
	start := nameNode.Pos() - len(keyword)
	if start < 0 || start > nameNode.Pos() {
		start = nameNode.Pos()
	}
	end := nameNode.End()
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func methodSignatureRangeWithoutReturnType(method *ast.MethodDeclaration) core.TextRange {
	if method == nil || method.Name() == nil {
		return core.NewTextRange(0, 0)
	}
	start := method.Name().End()
	end := method.End()
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func objectPropertyInitializerBoundaryRange(sourceFile *ast.SourceFile, prop *ast.PropertyAssignment) core.TextRange {
	if sourceFile == nil || prop == nil || prop.Name() == nil || prop.Initializer == nil {
		return core.TextRange{}
	}
	nameRange := utils.TrimNodeTextRange(sourceFile, prop.Name())
	initializerRange := utils.TrimNodeTextRange(sourceFile, prop.Initializer)
	start := nameRange.Pos()
	end := initializerRange.Pos()
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func reportObjectLiteralFunctionExpressions(ctx rule.RuleContext, objectLiteral *ast.ObjectLiteralExpression, opts ExplicitModuleBoundaryTypesOptions) {
	if objectLiteral == nil || objectLiteral.Properties == nil {
		return
	}

	for _, propertyNode := range objectLiteral.Properties.Nodes {
		if propertyNode == nil {
			continue
		}

		switch propertyNode.Kind {
		case ast.KindPropertyAssignment:
			prop := propertyNode.AsPropertyAssignment()
			if prop == nil || prop.Initializer == nil {
				continue
			}
			if name, ok := staticNameFromNode(prop.Name()); ok && isAllowedName(name, opts.AllowedNames) {
				continue
			}
			initializer := unwrapReturnedExpression(prop.Initializer)
			if initializer == nil {
				continue
			}
			switch initializer.Kind {
			case ast.KindArrowFunction:
				arrow := initializer.AsArrowFunction()
				if arrow == nil {
					continue
				}
				if arrow.Type == nil {
					if opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(arrow.Body) {
						continue
					}
					ctx.ReportRange(objectPropertyInitializerBoundaryRange(ctx.SourceFile, prop), buildMissingReturnTypeMessage())
				}
				if arrow.Parameters != nil {
					checkParameters(ctx, arrow.Parameters.Nodes, opts)
				}
			case ast.KindFunctionExpression:
				fnExpr := initializer.AsFunctionExpression()
				if fnExpr == nil {
					continue
				}
				if fnExpr.Type == nil {
					ctx.ReportRange(objectPropertyInitializerBoundaryRange(ctx.SourceFile, prop), buildMissingReturnTypeMessage())
				}
				if fnExpr.Parameters != nil {
					checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
				}
			case ast.KindObjectLiteralExpression:
				nested := initializer.AsObjectLiteralExpression()
				reportObjectLiteralFunctionExpressions(ctx, nested, opts)
			}
		case ast.KindMethodDeclaration:
			method := propertyNode.AsMethodDeclaration()
			if method == nil {
				continue
			}
			if name, ok := staticNameFromNode(method.Name()); ok && isAllowedName(name, opts.AllowedNames) {
				continue
			}
			if method.Type == nil {
				ctx.ReportNode(method.Name(), buildMissingReturnTypeMessage())
			}
			if method.Parameters != nil {
				checkParameters(ctx, method.Parameters.Nodes, opts)
			}
		}
	}
}

type exportedIdentifierFunctionValue struct {
	expression   *ast.Node
	declaration  *ast.VariableDeclaration
	functionDecl *ast.FunctionDeclaration
}

func findExportedIdentifierFunctionValues(sourceFile *ast.SourceFile, identifier string, beforePos int) []exportedIdentifierFunctionValue {
	values := []exportedIdentifierFunctionValue{}
	if sourceFile == nil || sourceFile.Statements == nil || identifier == "" {
		return values
	}

	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil {
			continue
		}
		if statement.Pos() >= beforePos {
			break
		}

		switch statement.Kind {
		case ast.KindFunctionDeclaration:
			functionDecl := statement.AsFunctionDeclaration()
			if functionDecl == nil || functionDecl.Name() == nil || functionDecl.Name().Text() != identifier {
				continue
			}
			values = append(values, exportedIdentifierFunctionValue{functionDecl: functionDecl})
		case ast.KindVariableStatement:
			varStmt := statement.AsVariableStatement()
			if varStmt == nil || varStmt.DeclarationList == nil {
				continue
			}
			declList := varStmt.DeclarationList.AsVariableDeclarationList()
			if declList == nil || declList.Declarations == nil {
				continue
			}
			for _, declarationNode := range declList.Declarations.Nodes {
				if declarationNode == nil || declarationNode.Kind != ast.KindVariableDeclaration {
					continue
				}
				declaration := declarationNode.AsVariableDeclaration()
				if declaration == nil || declaration.Name() == nil || declaration.Name().Kind != ast.KindIdentifier || declaration.Initializer == nil {
					continue
				}
				if declaration.Name().AsIdentifier().Text != identifier {
					continue
				}
				values = append(values, exportedIdentifierFunctionValue{
					expression:  declaration.Initializer.AsNode(),
					declaration: declaration,
				})
			}
		case ast.KindExpressionStatement:
			exprStmt := statement.AsExpressionStatement()
			if exprStmt == nil || exprStmt.Expression == nil {
				continue
			}
			expr := unwrapReturnedExpression(exprStmt.Expression)
			if expr == nil || expr.Kind != ast.KindBinaryExpression {
				continue
			}
			binaryExpr := expr.AsBinaryExpression()
			if binaryExpr == nil || binaryExpr.Left == nil || binaryExpr.Right == nil || binaryExpr.OperatorToken.Kind != ast.KindEqualsToken {
				continue
			}
			left := unwrapReturnedExpression(binaryExpr.Left)
			if left == nil || left.Kind != ast.KindIdentifier || left.AsIdentifier().Text != identifier {
				continue
			}
			values = append(values, exportedIdentifierFunctionValue{expression: binaryExpr.Right})
		}
	}

	return values
}

func reportExportedIdentifierFunctionReturnType(ctx rule.RuleContext, identifierNode *ast.Node, exportAssignmentNode *ast.Node, opts ExplicitModuleBoundaryTypesOptions) {
	if identifierNode == nil || identifierNode.Kind != ast.KindIdentifier || exportAssignmentNode == nil {
		return
	}
	identifierName := identifierNode.AsIdentifier().Text
	if identifierName == "" {
		return
	}
	if isAllowedName(identifierName, opts.AllowedNames) {
		return
	}

	candidates := findExportedIdentifierFunctionValues(ctx.SourceFile, identifierName, exportAssignmentNode.Pos())
	if len(candidates) == 0 {
		return
	}

	for _, candidate := range candidates {
		if candidate.functionDecl != nil {
			functionDecl := candidate.functionDecl
			if functionDecl.Type == nil {
				if !opts.AllowHigherOrderFunctions || !hasImmediateFunctionReturn(functionDecl.Body) {
					ctx.ReportRange(functionDeclarationSignatureRange(functionDecl), buildMissingReturnTypeMessage())
				}
			}
			if functionDecl.Parameters != nil {
				checkParameters(ctx, functionDecl.Parameters.Nodes, opts)
			}
			if opts.AllowHigherOrderFunctions && functionDecl.Type == nil && hasImmediateFunctionReturn(functionDecl.Body) {
				reportHigherOrderReturnedFunctions(ctx, functionDecl.Body, opts)
			}
			continue
		}

		if candidate.expression == nil {
			continue
		}

		// Explicit assertions are always considered typed in upstream behavior.
		if candidate.expression.Kind == ast.KindAsExpression || candidate.expression.Kind == ast.KindTypeAssertionExpression {
			continue
		}

		initializer := unwrapReturnedExpression(candidate.expression)
		if initializer == nil {
			continue
		}

		switch initializer.Kind {
		case ast.KindArrowFunction:
			arrow := initializer.AsArrowFunction()
			if arrow == nil {
				continue
			}
			if candidate.declaration != nil && opts.AllowTypedFunctionExpressions && hasDeclaratorTypeAnnotation(ctx.SourceFile, candidate.declaration, initializer) {
				continue
			}
			if arrow.Type == nil {
				if opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(arrow.Body) {
					reportHigherOrderReturnedFunctions(ctx, arrow.Body, opts)
				} else if !opts.AllowDirectConstAssertionInArrowFunctions || !bodyHasDirectConstAssertion(ctx.SourceFile, arrow.Body) {
					ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
				}
			}
			if arrow.Parameters != nil && candidate.declaration == nil {
				checkParameters(ctx, arrow.Parameters.Nodes, opts)
			}
		case ast.KindFunctionExpression:
			fnExpr := initializer.AsFunctionExpression()
			if fnExpr == nil {
				continue
			}
			if candidate.declaration != nil && opts.AllowTypedFunctionExpressions && hasDeclaratorTypeAnnotation(ctx.SourceFile, candidate.declaration, initializer) {
				continue
			}
			if fnExpr.Type == nil {
				if opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(fnExpr.Body) {
					reportHigherOrderReturnedFunctions(ctx, fnExpr.Body, opts)
				} else {
					ctx.ReportRange(functionExpressionKeywordRange(initializer), buildMissingReturnTypeMessage())
				}
			}
			shouldCheckFnExprParameters := candidate.declaration == nil
			if candidate.declaration != nil {
				stmt := findEnclosingVariableStatement(candidate.declaration.AsNode())
				if !isExportedFunction(stmt) {
					shouldCheckFnExprParameters = true
				}
			}
			if fnExpr.Parameters != nil && shouldCheckFnExprParameters {
				checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
			}
		}
	}
}

func reportExportedIdentifierFunctionsInExpression(ctx rule.RuleContext, expression *ast.Node, exportAssignmentNode *ast.Node, opts ExplicitModuleBoundaryTypesOptions) {
	if expression == nil {
		return
	}
	if expression.Kind == ast.KindIdentifier {
		reportExportedIdentifierFunctionReturnType(ctx, expression, exportAssignmentNode, opts)
		return
	}
	expression.ForEachChild(func(child *ast.Node) bool {
		reportExportedIdentifierFunctionsInExpression(ctx, child, exportAssignmentNode, opts)
		return false
	})
}

func collectDefaultExportedIdentifierNames(sourceFile *ast.SourceFile) map[string]bool {
	names := map[string]bool{}
	if sourceFile == nil || sourceFile.Statements == nil {
		return names
	}
	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindExportAssignment {
			if statement.Kind != ast.KindExportDeclaration {
				continue
			}
			exportDecl := statement.AsExportDeclaration()
			if exportDecl == nil || exportDecl.ExportClause == nil || exportDecl.ExportClause.Kind != ast.KindNamedExports {
				continue
			}
			namedExports := exportDecl.ExportClause.AsNamedExports()
			if namedExports == nil || namedExports.Elements == nil {
				continue
			}
			for _, element := range namedExports.Elements.Nodes {
				specifier := element.AsExportSpecifier()
				if specifier == nil {
					continue
				}
				target := specifier.PropertyName
				if target == nil {
					target = specifier.Name()
				}
				if target != nil && target.Kind == ast.KindIdentifier {
					names[target.AsIdentifier().Text] = true
				}
			}
			continue
		}
		exportAssignment := statement.AsExportAssignment()
		if exportAssignment == nil || exportAssignment.Expression == nil {
			continue
		}
		expr := unwrapReturnedExpression(exportAssignment.Expression)
		if expr == nil {
			continue
		}
		reportExportedIdentifierNamesFromExpression(expr, names)
	}
	return names
}

func reportExportedIdentifierNamesFromExpression(expression *ast.Node, names map[string]bool) {
	if expression == nil {
		return
	}
	if expression.Kind == ast.KindIdentifier {
		names[expression.AsIdentifier().Text] = true
		return
	}
	expression.ForEachChild(func(child *ast.Node) bool {
		reportExportedIdentifierNamesFromExpression(child, names)
		return false
	})
}

func isClassLikeBoundaryNode(classNode *ast.Node, defaultExportedIdentifiers map[string]bool) bool {
	if isExportedClassLikeNode(classNode) {
		return true
	}
	if classNode == nil || classNode.Kind != ast.KindClassDeclaration {
		return false
	}
	classDecl := classNode.AsClassDeclaration()
	if classDecl == nil || classDecl.Name() == nil {
		return false
	}
	return defaultExportedIdentifiers[classDecl.Name().Text()]
}

func propertyHasAccessorModifier(prop *ast.PropertyDeclaration) bool {
	if prop == nil || prop.Modifiers() == nil {
		return false
	}
	for _, mod := range prop.Modifiers().Nodes {
		if mod != nil && mod.Kind == ast.KindAccessorKeyword {
			return true
		}
	}
	return false
}

func nodeSourceText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	text := sourceFile.Text()
	start := node.Pos()
	end := node.End()
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	if start >= end {
		return ""
	}
	return text[start:end]
}

func isExportedFunction(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return ast.HasSyntacticModifier(node, ast.ModifierFlagsExport) || ast.HasSyntacticModifier(node, ast.ModifierFlagsDefault)
}

var ExplicitModuleBoundaryTypesRule = rule.CreateRule(rule.Rule{
	Name: "explicit-module-boundary-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		defaultExportedIdentifiers := collectDefaultExportedIdentifierNames(ctx.SourceFile)
		return rule.RuleListeners{
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				fn := node.AsFunctionDeclaration()
				if fn == nil || !isExportedFunction(node) {
					return
				}
				if fn.Name() != nil {
					name := fn.Name().Text()
					if isAllowedName(name, opts.AllowedNames) {
						return
					}
				}
				if opts.AllowOverloadFunctions && hasFunctionOverloadSignatures(node, fn) {
					return
				}
				if fn.Type == nil {
					if !opts.AllowHigherOrderFunctions || !hasImmediateFunctionReturn(fn.Body) {
						if fn.Name() == nil {
							ctx.ReportRange(functionKeywordRangeInNode(ctx.SourceFile, node), buildMissingReturnTypeMessage())
						} else {
							ctx.ReportRange(functionDeclarationSignatureRange(fn), buildMissingReturnTypeMessage())
						}
					}
				}
				if fn.Parameters != nil {
					checkParameters(ctx, fn.Parameters.Nodes, opts)
				}
				if opts.AllowHigherOrderFunctions && fn.Type == nil && hasImmediateFunctionReturn(fn.Body) {
					reportHigherOrderReturnedFunctions(ctx, fn.Body, opts)
				}
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				method := node.AsMethodDeclaration()
				if method == nil || method.Name() == nil {
					return
				}
				if name, ok := staticNameFromNode(method.Name()); ok && isAllowedName(name, opts.AllowedNames) {
					return
				}
				if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) || method.Name().Kind == ast.KindPrivateIdentifier {
					return
				}
				if node.Parent == nil || !ast.IsClassLike(node.Parent) {
					return
				}
				classNode := node.Parent
				if !isClassLikeBoundaryNode(classNode, defaultExportedIdentifiers) {
					return
				}
				if opts.AllowOverloadFunctions && hasMethodOverloadSignatures(node, method) {
					return
				}
				if method.Type == nil {
					if !opts.AllowHigherOrderFunctions || !hasImmediateFunctionReturn(method.Body) {
						if method.Body == nil {
							ctx.ReportRange(methodSignatureRangeWithoutReturnType(method), buildMissingReturnTypeMessage())
						} else {
							reportNode := node
							if method.Name() != nil {
								reportNode = method.Name()
							}
							ctx.ReportNode(reportNode, buildMissingReturnTypeMessage())
						}
					}
				}
				if method.Parameters != nil {
					checkParameters(ctx, method.Parameters.Nodes, opts)
				}
				if opts.AllowHigherOrderFunctions && method.Type == nil && hasImmediateFunctionReturn(method.Body) {
					reportHigherOrderReturnedFunctions(ctx, method.Body, opts)
				}
			},
			ast.KindConstructor: func(node *ast.Node) {
				constructorDecl := node.AsConstructorDeclaration()
				if constructorDecl == nil {
					return
				}
				modifierFlags := ast.GetCombinedModifierFlags(node)
				if modifierFlags&(ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected) != 0 {
					return
				}
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isClassLikeBoundaryNode(node.Parent, defaultExportedIdentifiers) {
					return
				}
				if constructorDecl.Parameters != nil {
					checkParameters(ctx, constructorDecl.Parameters.Nodes, opts)
				}
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				prop := node.AsPropertyDeclaration()
				if prop == nil || prop.Name() == nil || prop.Initializer == nil {
					return
				}
				if name, ok := staticNameFromNode(prop.Name()); ok && isAllowedName(name, opts.AllowedNames) {
					return
				}
				if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) {
					return
				}
				if prop.Name().Kind == ast.KindPrivateIdentifier {
					return
				}
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isClassLikeBoundaryNode(node.Parent, defaultExportedIdentifiers) {
					return
				}

				if opts.AllowTypedFunctionExpressions && prop.Type != nil {
					return
				}

				init := unwrapReturnedExpression(prop.Initializer)
				if init == nil {
					return
				}
				switch init.Kind {
				case ast.KindArrowFunction:
					arrow := init.AsArrowFunction()
					if arrow == nil {
						return
					}
					isAutoAccessor := propertyHasAccessorModifier(prop) || strings.Contains(nodeSourceText(ctx.SourceFile, node), "accessor")
					if isAutoAccessor && arrow.Parameters != nil {
						checkParametersWithReportNode(ctx, arrow.Parameters.Nodes, opts, node)
					}
					if arrow.Type == nil {
						ctx.ReportRange(propertyInitializerBoundaryRange(ctx.SourceFile, prop), buildMissingReturnTypeMessage())
					}
					if !isAutoAccessor && arrow.Parameters != nil {
						checkParameters(ctx, arrow.Parameters.Nodes, opts)
					}
				case ast.KindFunctionExpression:
					fnExpr := init.AsFunctionExpression()
					if fnExpr == nil {
						return
					}
					if fnExpr.Type == nil {
						ctx.ReportRange(functionExpressionPropertyBoundaryRange(ctx.SourceFile, prop, fnExpr), buildMissingReturnTypeMessage())
					}
					if fnExpr.Parameters != nil {
						checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
					}
				}
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				decl := node.AsVariableDeclaration()
				if decl == nil || decl.Initializer == nil {
					return
				}
				stmt := findEnclosingVariableStatement(node)
				if !isExportedFunction(stmt) {
					return
				}
				statementText := nodeSourceText(ctx.SourceFile, stmt)
				if strings.Contains(statementText, " as ") || strings.Contains(statementText, "= <") {
					return
				}
				rawInitializer := decl.Initializer.AsNode()
				if opts.AllowTypedFunctionExpressions {
					declarationText := nodeSourceText(ctx.SourceFile, node)
					initializerText := nodeSourceText(ctx.SourceFile, rawInitializer)
					if hasDeclaratorTypeAnnotation(ctx.SourceFile, decl, rawInitializer) {
						return
					}
					if rawInitializer.Kind == ast.KindAsExpression || rawInitializer.Kind == ast.KindTypeAssertionExpression {
						return
					}
					if strings.Contains(initializerText, " as ") || strings.HasPrefix(strings.TrimSpace(initializerText), "<") {
						return
					}
					if strings.Contains(declarationText, " as ") || strings.Contains(declarationText, "= <") {
						return
					}
				}
				initializer := unwrapReturnedExpression(rawInitializer)
				if initializer == nil || initializer.Kind != ast.KindObjectLiteralExpression {
					return
				}
				reportObjectLiteralFunctionExpressions(ctx, initializer.AsObjectLiteralExpression(), opts)
			},
			ast.KindGetAccessor: func(node *ast.Node) {
				getter := node.AsGetAccessorDeclaration()
				if getter == nil || getter.Name() == nil {
					return
				}
				if name, ok := staticNameFromNode(getter.Name()); ok && isAllowedName(name, opts.AllowedNames) {
					return
				}
				if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) || getter.Name().Kind == ast.KindPrivateIdentifier {
					return
				}
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isClassLikeBoundaryNode(node.Parent, defaultExportedIdentifiers) {
					return
				}
				if getter.Type == nil {
					ctx.ReportRange(accessorKeywordRange(getter.Name(), "get"), buildMissingReturnTypeMessage())
				}
			},
			ast.KindSetAccessor: func(node *ast.Node) {
				setter := node.AsSetAccessorDeclaration()
				if setter == nil || setter.Name() == nil {
					return
				}
				if name, ok := staticNameFromNode(setter.Name()); ok && isAllowedName(name, opts.AllowedNames) {
					return
				}
				if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) || setter.Name().Kind == ast.KindPrivateIdentifier {
					return
				}
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isClassLikeBoundaryNode(node.Parent, defaultExportedIdentifiers) {
					return
				}
				if setter.Parameters != nil {
					checkParameters(ctx, setter.Parameters.Nodes, opts)
				}
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				arrow := node.AsArrowFunction()
				if arrow == nil || arrow.Parent == nil {
					return
				}
				if arrow.Parent.Kind != ast.KindVariableDeclaration {
					return
				}
				decl := arrow.Parent.AsVariableDeclaration()
				if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
					return
				}
				if opts.AllowTypedFunctionExpressions && hasDeclaratorTypeAnnotation(ctx.SourceFile, decl, node) {
					return
				}
				isBoundaryArrow := false
				higherOrderHandled := false
				name := decl.Name().AsIdentifier().Text
				if !isAllowedName(name, opts.AllowedNames) {
					stmt := findEnclosingVariableStatement(decl.AsNode())
					if isExportedFunction(stmt) && arrow.Type == nil {
						isBoundaryArrow = true
						if opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(arrow.Body) {
							reportHigherOrderReturnedFunctions(ctx, arrow.Body, opts)
							higherOrderHandled = true
						} else if !opts.AllowDirectConstAssertionInArrowFunctions || !bodyHasDirectConstAssertion(ctx.SourceFile, arrow.Body) {
							ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
						}
					}
				}
				if arrow.Parameters != nil {
					checkParameters(ctx, arrow.Parameters.Nodes, opts)
				}
				if opts.AllowHigherOrderFunctions && arrow.Type == nil && isBoundaryArrow && !higherOrderHandled && isHigherOrderFunctionBody(arrow.Body) {
					reportHigherOrderReturnedFunctions(ctx, arrow.Body, opts)
				}
			},
			ast.KindFunctionExpression: func(node *ast.Node) {
				fnExpr := node.AsFunctionExpression()
				if fnExpr == nil || fnExpr.Parent == nil {
					return
				}
				if fnExpr.Parent.Kind != ast.KindVariableDeclaration {
					return
				}
				decl := fnExpr.Parent.AsVariableDeclaration()
				if decl == nil {
					return
				}
				if opts.AllowTypedFunctionExpressions && hasDeclaratorTypeAnnotation(ctx.SourceFile, decl, node) {
					return
				}
				stmt := findEnclosingVariableStatement(decl.AsNode())
				isBoundaryFunctionExpression := isExportedFunction(stmt)
				if !isBoundaryFunctionExpression {
					return
				}

				if fnExpr.Type == nil {
					if !opts.AllowHigherOrderFunctions || !isHigherOrderFunctionBody(fnExpr.Body) {
						ctx.ReportRange(functionExpressionKeywordRange(node), buildMissingReturnTypeMessage())
					}
				}
				if fnExpr.Parameters != nil {
					checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
				}
				if opts.AllowHigherOrderFunctions && fnExpr.Type == nil && isBoundaryFunctionExpression && isHigherOrderFunctionBody(fnExpr.Body) {
					reportHigherOrderReturnedFunctions(ctx, fnExpr.Body, opts)
				}
			},
			ast.KindExportAssignment: func(node *ast.Node) {
				exportAssignment := node.AsExportAssignment()
				if exportAssignment == nil || exportAssignment.Expression == nil {
					return
				}

				expr := unwrapReturnedExpression(exportAssignment.Expression)
				if expr == nil {
					return
				}

				switch expr.Kind {
				case ast.KindArrowFunction:
					arrow := expr.AsArrowFunction()
					if arrow == nil {
						return
					}
					if arrow.Type == nil {
						if !opts.AllowHigherOrderFunctions || !isHigherOrderFunctionBody(arrow.Body) {
							ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
						}
					}
					if arrow.Parameters != nil {
						checkParameters(ctx, arrow.Parameters.Nodes, opts)
					}
					if opts.AllowHigherOrderFunctions && arrow.Type == nil && isHigherOrderFunctionBody(arrow.Body) {
						reportHigherOrderReturnedFunctions(ctx, arrow.Body, opts)
					}
				case ast.KindFunctionExpression:
					fnExpr := expr.AsFunctionExpression()
					if fnExpr == nil {
						return
					}
					if fnExpr.Type == nil {
						if !opts.AllowHigherOrderFunctions || !isHigherOrderFunctionBody(fnExpr.Body) {
							ctx.ReportRange(functionExpressionKeywordRange(expr), buildMissingReturnTypeMessage())
						}
					}
					if fnExpr.Parameters != nil {
						checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
					}
					if opts.AllowHigherOrderFunctions && fnExpr.Type == nil && isHigherOrderFunctionBody(fnExpr.Body) {
						reportHigherOrderReturnedFunctions(ctx, fnExpr.Body, opts)
					}
				case ast.KindIdentifier:
					reportExportedIdentifierFunctionReturnType(ctx, expr, node, opts)
				default:
					reportExportedIdentifierFunctionsInExpression(ctx, expr, node, opts)
				}
			},
			ast.KindExportDeclaration: func(node *ast.Node) {
				exportDecl := node.AsExportDeclaration()
				if exportDecl == nil || exportDecl.ExportClause == nil || exportDecl.ExportClause.Kind != ast.KindNamedExports {
					return
				}
				namedExports := exportDecl.ExportClause.AsNamedExports()
				if namedExports == nil || namedExports.Elements == nil {
					return
				}
				for _, element := range namedExports.Elements.Nodes {
					specifier := element.AsExportSpecifier()
					if specifier == nil {
						continue
					}
					target := specifier.PropertyName
					if target == nil {
						target = specifier.Name()
					}
					if target == nil || target.Kind != ast.KindIdentifier {
						continue
					}
					reportExportedIdentifierFunctionReturnType(ctx, target, node, opts)
				}
			},
		}
	},
})
