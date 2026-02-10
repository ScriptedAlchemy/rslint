package explicit_module_boundary_types

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
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
			if param.Name() != nil {
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
			if param.Name() != nil {
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
	if block == nil || block.Statements == nil || len(block.Statements.Nodes) != 1 {
		return false
	}
	statement := block.Statements.Nodes[0]
	if statement == nil || statement.Kind != ast.KindReturnStatement {
		return false
	}
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
		return expr.AsArrowFunction() != nil
	case ast.KindFunctionExpression:
		return expr.AsFunctionExpression() != nil
	}
	return false
}

func isHigherOrderFunctionBody(body *ast.BlockOrExpression) bool {
	if body == nil {
		return false
	}
	if body.Kind == ast.KindBlock {
		return hasImmediateFunctionReturn(body)
	}

	expr := unwrapReturnedExpression(body.AsNode())
	if expr == nil {
		return false
	}
	return expr.Kind == ast.KindArrowFunction || expr.Kind == ast.KindFunctionExpression
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
	if node == nil || fn == nil || fn.Name() == nil || node.Parent == nil {
		return false
	}

	currentName := fn.Name().Text()
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

	for i := 0; i < currentIndex; i++ {
		sibling := siblings[i]
		if sibling == nil || sibling.Kind != ast.KindFunctionDeclaration {
			continue
		}
		overload := sibling.AsFunctionDeclaration()
		if overload == nil || overload.Name() == nil || overload.Name().Text() != currentName {
			continue
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

func isExportedFunction(node *ast.Node) bool {
	return ast.HasSyntacticModifier(node, ast.ModifierFlagsExport) || ast.HasSyntacticModifier(node, ast.ModifierFlagsDefault)
}

var ExplicitModuleBoundaryTypesRule = rule.CreateRule(rule.Rule{
	Name: "explicit-module-boundary-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				fn := node.AsFunctionDeclaration()
				if fn == nil || fn.Name() == nil || !isExportedFunction(node) {
					return
				}
				name := fn.Name().Text()
				if isAllowedName(name, opts.AllowedNames) {
					return
				}
				if opts.AllowOverloadFunctions && hasFunctionOverloadSignatures(node, fn) {
					return
				}
				if fn.Type == nil {
					if !(opts.AllowHigherOrderFunctions && hasImmediateFunctionReturn(fn.Body)) {
						ctx.ReportRange(functionDeclarationSignatureRange(fn), buildMissingReturnTypeMessage())
					}
				}
				if fn.Parameters != nil {
					checkParameters(ctx, fn.Parameters.Nodes, opts)
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
				if !isExportedClassLikeNode(classNode) {
					return
				}
				if opts.AllowOverloadFunctions && hasMethodOverloadSignatures(node, method) {
					return
				}
				if method.Type == nil {
					if !(opts.AllowHigherOrderFunctions && hasImmediateFunctionReturn(method.Body)) {
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
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isExportedClassLikeNode(node.Parent) {
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
					if arrow.Type == nil {
						ctx.ReportRange(propertyInitializerBoundaryRange(ctx.SourceFile, prop), buildMissingReturnTypeMessage())
					}
					if arrow.Parameters != nil {
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
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isExportedClassLikeNode(node.Parent) {
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
				if node.Parent == nil || !ast.IsClassLike(node.Parent) || !isExportedClassLikeNode(node.Parent) {
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
				name := decl.Name().AsIdentifier().Text
				if !isAllowedName(name, opts.AllowedNames) {
					stmt := findEnclosingVariableStatement(decl.AsNode())
					if isExportedFunction(stmt) && arrow.Type == nil {
						if opts.AllowDirectConstAssertionInArrowFunctions && bodyHasDirectConstAssertion(ctx.SourceFile, arrow.Body) {
							return
						}
						if opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(arrow.Body) {
							return
						}
						ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
					}
				}
				if arrow.Parameters != nil {
					checkParameters(ctx, arrow.Parameters.Nodes, opts)
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
				if !isExportedFunction(stmt) {
					return
				}

				if fnExpr.Type == nil {
					ctx.ReportRange(functionExpressionKeywordRange(node), buildMissingReturnTypeMessage())
				}
				if fnExpr.Parameters != nil {
					checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
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
						if !(opts.AllowHigherOrderFunctions && isHigherOrderFunctionBody(arrow.Body)) {
							ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
						}
					}
					if arrow.Parameters != nil {
						checkParameters(ctx, arrow.Parameters.Nodes, opts)
					}
				case ast.KindFunctionExpression:
					fnExpr := expr.AsFunctionExpression()
					if fnExpr == nil {
						return
					}
					if fnExpr.Type == nil {
						ctx.ReportRange(functionExpressionKeywordRange(expr), buildMissingReturnTypeMessage())
					}
					if fnExpr.Parameters != nil {
						checkParameters(ctx, fnExpr.Parameters.Nodes, opts)
					}
				}
			},
		}
	},
})
