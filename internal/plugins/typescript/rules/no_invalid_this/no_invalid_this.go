package no_invalid_this

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

var jsdocThisPattern = regexp.MustCompile(`@this\b`)

func buildUnexpectedThisMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpectedThis",
		Description: "Unexpected 'this'.",
	}
}

type noInvalidThisOptions struct {
	CapIsConstructor bool `json:"capIsConstructor"`
}

func parseOptions(options any) noInvalidThisOptions {
	opts := noInvalidThisOptions{CapIsConstructor: true}
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
	if capIsConstructor, ok := optsMap["capIsConstructor"].(bool); ok {
		opts.CapIsConstructor = capIsConstructor
	}
	return opts
}

func hasThisParameter(node *ast.Node) bool {
	if node == nil {
		return false
	}
	var params []*ast.Node
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		fn := node.AsFunctionDeclaration()
		if fn != nil && fn.Parameters != nil {
			params = fn.Parameters.Nodes
		}
	case ast.KindFunctionExpression:
		fn := node.AsFunctionExpression()
		if fn != nil && fn.Parameters != nil {
			params = fn.Parameters.Nodes
		}
	}
	for _, paramNode := range params {
		if paramNode == nil || paramNode.Kind != ast.KindParameter {
			continue
		}
		param := paramNode.AsParameterDeclaration()
		if param == nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
			continue
		}
		if param.Name().AsIdentifier().Text == "this" {
			return true
		}
	}
	return false
}

func startsWithUpper(name string) bool {
	for _, r := range name {
		return unicode.IsUpper(r)
	}
	return false
}

func functionName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		fn := node.AsFunctionDeclaration()
		if fn != nil && fn.Name() != nil {
			return fn.Name().Text()
		}
	case ast.KindFunctionExpression:
		fn := node.AsFunctionExpression()
		if fn != nil && fn.Name() != nil {
			return fn.Name().Text()
		}
	}
	return ""
}

func isExpressionContainerWrapper(parent *ast.Node, current *ast.Node) bool {
	if parent == nil || current == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindParenthesizedExpression:
		expr := parent.AsParenthesizedExpression()
		return expr != nil && expr.Expression == current
	case ast.KindBinaryExpression:
		expr := parent.AsBinaryExpression()
		if expr == nil {
			return false
		}
		switch expr.OperatorToken.Kind {
		case ast.KindBarBarToken, ast.KindAmpersandAmpersandToken, ast.KindQuestionQuestionToken:
			return expr.Left == current || expr.Right == current
		case ast.KindCommaToken:
			return expr.Right == current
		}
	case ast.KindConditionalExpression:
		expr := parent.AsConditionalExpression()
		return expr != nil && (expr.WhenTrue == current || expr.WhenFalse == current)
	}
	return false
}

func expressionInMethodValueContext(node *ast.Node) bool {
	current := node
	for current != nil && current.Parent != nil {
		parent := current.Parent
		switch parent.Kind {
		case ast.KindPropertyAssignment:
			prop := parent.AsPropertyAssignment()
			return prop != nil && prop.Initializer == current
		case ast.KindBinaryExpression:
			assign := parent.AsBinaryExpression()
			if assign != nil &&
				ast.IsAssignmentOperator(assign.OperatorToken.Kind) &&
				assign.Right == current &&
				(assign.Left.Kind == ast.KindPropertyAccessExpression || assign.Left.Kind == ast.KindElementAccessExpression) {
				return true
			}
		}
		if isExpressionContainerWrapper(parent, current) {
			current = parent
			continue
		}
		break
	}
	return false
}

func functionExpressionReturnedFromIIFEMethodContext(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindFunctionExpression || node.Parent == nil {
		return false
	}
	if node.Parent.Kind == ast.KindArrowFunction {
		arrow := node.Parent.AsArrowFunction()
		if arrow != nil && arrow.Body == node {
			outerExpr := node.Parent
			if outerExpr.Parent != nil && outerExpr.Parent.Kind == ast.KindParenthesizedExpression {
				paren := outerExpr.Parent.AsParenthesizedExpression()
				if paren != nil && paren.Expression == outerExpr {
					outerExpr = outerExpr.Parent
				}
			}
			if outerExpr.Parent == nil || outerExpr.Parent.Kind != ast.KindCallExpression {
				return false
			}
			call := outerExpr.Parent.AsCallExpression()
			if call == nil || call.Expression != outerExpr {
				return false
			}
			return expressionInMethodValueContext(outerExpr.Parent)
		}
	}
	if node.Parent.Kind != ast.KindReturnStatement {
		return false
	}
	current := node.Parent
	for current != nil {
		if current.Kind == ast.KindFunctionExpression || current.Kind == ast.KindArrowFunction {
			outer := current
			outerExpr := outer
			if outerExpr.Parent != nil && outerExpr.Parent.Kind == ast.KindParenthesizedExpression {
				paren := outerExpr.Parent.AsParenthesizedExpression()
				if paren != nil && paren.Expression == outerExpr {
					outerExpr = outerExpr.Parent
				}
			}
			if outerExpr.Parent == nil || outerExpr.Parent.Kind != ast.KindCallExpression {
				return false
			}
			call := outerExpr.Parent.AsCallExpression()
			if call == nil || call.Expression != outerExpr {
				return false
			}
			return expressionInMethodValueContext(outerExpr.Parent)
		}
		if current.Kind == ast.KindFunctionDeclaration {
			return false
		}
		current = current.Parent
	}
	return false
}

func functionExpressionIsMethodLike(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindFunctionExpression {
		return false
	}
	if expressionInMethodValueContext(node) {
		return true
	}
	return functionExpressionReturnedFromIIFEMethodContext(node)
}

func functionExpressionBoundAtCreation(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindFunctionExpression {
		return false
	}

	isNonNullish := func(arg *ast.Node) bool {
		if arg == nil {
			return false
		}
		if arg.Kind == ast.KindNullKeyword {
			return false
		}
		if arg.Kind == ast.KindIdentifier && arg.AsIdentifier().Text == "undefined" {
			return false
		}
		if arg.Kind == ast.KindVoidExpression {
			return false
		}
		return true
	}

	functionExpressionWithKnownThisArg := func(node *ast.Node) bool {
		if node.Parent == nil || node.Parent.Kind != ast.KindCallExpression {
			return false
		}
		call := node.Parent.AsCallExpression()
		if call == nil || call.Arguments == nil || call.Expression == nil {
			return false
		}
		args := call.Arguments.Nodes
		nonNullishAt := func(index int) bool {
			if index < 0 || index >= len(args) {
				return false
			}
			return isNonNullish(args[index])
		}
		if call.Expression.Kind == ast.KindPropertyAccessExpression {
			access := call.Expression.AsPropertyAccessExpression()
			if access == nil {
				return false
			}
			name := access.Name().Text()
			if access.Expression != nil && access.Expression.Kind == ast.KindIdentifier && access.Expression.AsIdentifier().Text == "Array" && name == "from" {
				return len(args) >= 3 && args[1] == node && nonNullishAt(2)
			}
			switch name {
			case "forEach", "map", "filter", "every", "some", "find", "findIndex", "flatMap":
				return len(args) >= 2 && args[0] == node && nonNullishAt(1)
			}
		}
		return false
	}

	if functionExpressionWithKnownThisArg(node) {
		return true
	}

	if node.Parent != nil && node.Parent.Kind == ast.KindCallExpression {
		call := node.Parent.AsCallExpression()
		if call != nil && call.Expression != nil && call.Expression.Kind == ast.KindPropertyAccessExpression {
			access := call.Expression.AsPropertyAccessExpression()
			if access != nil && access.Expression != nil && access.Expression.Kind == ast.KindIdentifier && access.Expression.AsIdentifier().Text == "Reflect" && access.Name().Text() == "apply" && call.Arguments != nil && len(call.Arguments.Nodes) >= 2 && call.Arguments.Nodes[0] == node {
				return isNonNullish(call.Arguments.Nodes[1])
			}
		}
	}

	expr := node
	for expr.Parent != nil && expr.Parent.Kind == ast.KindParenthesizedExpression {
		paren := expr.Parent.AsParenthesizedExpression()
		if paren == nil || paren.Expression != expr {
			break
		}
		expr = expr.Parent
	}
	if expr.Parent == nil || expr.Parent.Kind != ast.KindPropertyAccessExpression {
		return false
	}
	access := expr.Parent.AsPropertyAccessExpression()
	if access == nil || access.Expression != expr || access.Parent == nil || access.Parent.Kind != ast.KindCallExpression {
		return false
	}
	call := access.Parent.AsCallExpression()
	if call == nil {
		return false
	}
	name := access.Name().Text()
	if name != "bind" && name != "call" && name != "apply" {
		return false
	}
	if call.Arguments == nil || len(call.Arguments.Nodes) == 0 {
		return false
	}
	return isNonNullish(call.Arguments.Nodes[0])
}

func functionExpressionAssignedToConstructorVariable(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindFunctionExpression || node.Parent == nil {
		return false
	}
	if node.Parent.Kind == ast.KindVariableDeclaration {
		decl := node.Parent.AsVariableDeclaration()
		if decl == nil || decl.Initializer != node || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
			return false
		}
		return startsWithUpper(decl.Name().AsIdentifier().Text)
	}
	if node.Parent.Kind == ast.KindBinaryExpression {
		assignment := node.Parent.AsBinaryExpression()
		if assignment == nil || !ast.IsAssignmentOperator(assignment.OperatorToken.Kind) || assignment.Right != node || assignment.Left == nil || assignment.Left.Kind != ast.KindIdentifier {
			return false
		}
		return startsWithUpper(assignment.Left.AsIdentifier().Text)
	}
	if node.Parent.Kind == ast.KindParameter {
		param := node.Parent.AsParameterDeclaration()
		if param == nil || param.Initializer != node || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
			return false
		}
		return startsWithUpper(param.Name().AsIdentifier().Text)
	}
	return false
}

func currentAllowed(stack []bool) bool {
	if len(stack) == 0 {
		return false
	}
	return stack[len(stack)-1]
}

func hasThisJSDoc(node *ast.Node, sourceFile *ast.SourceFile) bool {
	if node == nil || sourceFile == nil {
		return false
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	start := trimmed.Pos()
	if start <= 0 {
		return false
	}
	text := sourceFile.Text()
	if start > len(text) {
		return false
	}
	if node.Kind == ast.KindFunctionExpression && node.Parent != nil && node.Parent.Kind == ast.KindReturnStatement {
		returnStmt := node.Parent
		stmtStart := returnStmt.Pos()
		if stmtStart >= 0 && stmtStart < start && stmtStart < len(text) {
			if jsdocThisPattern.MatchString(text[stmtStart:start]) {
				return true
			}
		}
	}
	prefix := text[:start]
	commentEnd := strings.LastIndex(prefix, "*/")
	if commentEnd < 0 {
		return false
	}
	afterComment := prefix[commentEnd+2:]
	if strings.TrimSpace(afterComment) != "" {
		return false
	}
	commentStart := strings.LastIndex(prefix[:commentEnd], "/**")
	if commentStart < 0 {
		commentStart = strings.LastIndex(prefix[:commentEnd], "/*")
		if commentStart < 0 {
			return false
		}
	}
	comment := prefix[commentStart : commentEnd+2]
	return jsdocThisPattern.MatchString(comment)
}

func pushForFunction(stack []bool, node *ast.Node, sourceFile *ast.SourceFile, opts noInvalidThisOptions) []bool {
	allowed := false
	if hasThisParameter(node) {
		allowed = true
	} else if opts.CapIsConstructor && startsWithUpper(functionName(node)) {
		allowed = true
	} else if opts.CapIsConstructor && functionExpressionAssignedToConstructorVariable(node) {
		allowed = true
	} else if node.Kind == ast.KindFunctionExpression && (functionExpressionIsMethodLike(node) || functionExpressionBoundAtCreation(node)) {
		allowed = true
	} else if hasThisJSDoc(node, sourceFile) {
		allowed = true
	}
	return append(stack, allowed)
}

func isAllowedClassPropertyContext(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindPropertyDeclaration:
			return true
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression:
			return false
		}
		current = current.Parent
	}
	return false
}

func isAllowedByAncestors(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindMethodDeclaration, ast.KindConstructor:
			return true
		case ast.KindArrowFunction:
			// lexical this; keep walking
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression:
			return false
		}
		current = current.Parent
	}
	return false
}

var NoInvalidThisRule = rule.CreateRule(rule.Rule{
	Name: "no-invalid-this",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		thisAllowedStack := []bool{}

		return rule.RuleListeners{
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				thisAllowedStack = pushForFunction(thisAllowedStack, node, ctx.SourceFile, opts)
			},
			rule.ListenerOnExit(ast.KindFunctionDeclaration): func(node *ast.Node) {
				if len(thisAllowedStack) > 0 {
					thisAllowedStack = thisAllowedStack[:len(thisAllowedStack)-1]
				}
			},
			ast.KindFunctionExpression: func(node *ast.Node) {
				thisAllowedStack = pushForFunction(thisAllowedStack, node, ctx.SourceFile, opts)
			},
			rule.ListenerOnExit(ast.KindFunctionExpression): func(node *ast.Node) {
				if len(thisAllowedStack) > 0 {
					thisAllowedStack = thisAllowedStack[:len(thisAllowedStack)-1]
				}
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				// Arrow functions use lexical this.
				thisAllowedStack = append(thisAllowedStack, currentAllowed(thisAllowedStack))
			},
			rule.ListenerOnExit(ast.KindArrowFunction): func(node *ast.Node) {
				if len(thisAllowedStack) > 0 {
					thisAllowedStack = thisAllowedStack[:len(thisAllowedStack)-1]
				}
			},
			ast.KindThisKeyword: func(node *ast.Node) {
				if currentAllowed(thisAllowedStack) || isAllowedByAncestors(node) || isAllowedClassPropertyContext(node) {
					return
				}
				ctx.ReportNode(node, buildUnexpectedThisMessage())
			},
		}
	},
})
