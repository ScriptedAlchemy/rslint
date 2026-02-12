package explicit_function_return_type

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type explicitFunctionReturnTypeOptions struct {
	AllowExpressions                          bool
	AllowTypedFunctionExpressions             bool
	AllowHigherOrderFunctions                 bool
	AllowDirectConstAssertionInArrowFunctions bool
	AllowedNames                              []string
}

func parseOptions(options any) explicitFunctionReturnTypeOptions {
	opts := explicitFunctionReturnTypeOptions{
		AllowExpressions:                          true,
		AllowTypedFunctionExpressions:             true,
		AllowHigherOrderFunctions:                 true,
		AllowDirectConstAssertionInArrowFunctions: true,
		AllowedNames:                              []string{},
	}
	if options == nil {
		return opts
	}

	var optionsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		optionsMap, _ = arr[0].(map[string]interface{})
	} else {
		optionsMap, _ = options.(map[string]interface{})
	}
	if optionsMap == nil {
		return opts
	}

	if value, ok := optionsMap["allowExpressions"].(bool); ok {
		opts.AllowExpressions = value
	}
	if value, ok := optionsMap["allowTypedFunctionExpressions"].(bool); ok {
		opts.AllowTypedFunctionExpressions = value
	}
	if value, ok := optionsMap["allowHigherOrderFunctions"].(bool); ok {
		opts.AllowHigherOrderFunctions = value
	}
	if value, ok := optionsMap["allowDirectConstAssertionInArrowFunctions"].(bool); ok {
		opts.AllowDirectConstAssertionInArrowFunctions = value
	}
	if values, ok := optionsMap["allowedNames"].([]interface{}); ok {
		for _, value := range values {
			if name, ok := value.(string); ok {
				opts.AllowedNames = append(opts.AllowedNames, name)
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

func hasAllowedName(name string, allowed []string) bool {
	if name == "" {
		return false
	}
	for _, allowedName := range allowed {
		if allowedName == name {
			return true
		}
	}
	return false
}

func functionName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration != nil && functionDeclaration.Name() != nil {
			return functionDeclaration.Name().Text()
		}
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		if methodDeclaration != nil && methodDeclaration.Name() != nil {
			return methodDeclaration.Name().Text()
		}
	}
	return ""
}

func hasExplicitReturnType(node *ast.Node) bool {
	if node == nil {
		return true
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		return functionDeclaration == nil || functionDeclaration.Type != nil
	case ast.KindFunctionExpression:
		functionExpression := node.AsFunctionExpression()
		return functionExpression == nil || functionExpression.Type != nil
	case ast.KindArrowFunction:
		arrowFunction := node.AsArrowFunction()
		return arrowFunction == nil || arrowFunction.Type != nil
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		return methodDeclaration == nil || methodDeclaration.Type != nil
	case ast.KindGetAccessor:
		getAccessor := node.AsGetAccessorDeclaration()
		return getAccessor == nil || getAccessor.Type != nil
	}
	return true
}

func isExpressionFunction(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	for parent != nil {
		switch parent.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindPrefixUnaryExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			parent = parent.Parent
			continue
		}
		break
	}
	if parent == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindExpressionStatement,
		ast.KindCallExpression,
		ast.KindNewExpression,
		ast.KindPropertyAssignment,
		ast.KindArrayLiteralExpression,
		ast.KindReturnStatement,
		ast.KindBinaryExpression,
		ast.KindPropertyDeclaration,
		ast.KindJsxExpression:
		return true
	}
	return false
}

func isTypedFunctionExpressionContext(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	for parent != nil {
		switch parent.Kind {
		case ast.KindParenthesizedExpression, ast.KindNonNullExpression:
			parent = parent.Parent
			continue
		}
		break
	}
	if parent == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		variableDeclaration := parent.AsVariableDeclaration()
		return variableDeclaration != nil && variableDeclaration.Type != nil
	case ast.KindPropertyDeclaration:
		propertyDeclaration := parent.AsPropertyDeclaration()
		return propertyDeclaration != nil && propertyDeclaration.Type != nil
	case ast.KindPropertyAssignment:
		propertyAssignment := parent.AsPropertyAssignment()
		if propertyAssignment == nil || propertyAssignment.Name() == nil {
			return false
		}
		if propertyAssignment.Parent == nil || propertyAssignment.Parent.Kind != ast.KindObjectLiteralExpression || propertyAssignment.Parent.Parent == nil {
			return false
		}
		switch propertyAssignment.Parent.Parent.Kind {
		case ast.KindAsExpression, ast.KindTypeAssertionExpression, ast.KindSatisfiesExpression:
			return true
		}
	case ast.KindParameter:
		parameter := parent.AsParameterDeclaration()
		return parameter != nil && parameter.Type != nil
	case ast.KindAsExpression, ast.KindTypeAssertionExpression, ast.KindSatisfiesExpression:
		return true
	case ast.KindJsxExpression:
		return node.Parent.Parent != nil && node.Parent.Parent.Kind == ast.KindJsxAttribute
	case ast.KindJsxAttribute:
		return true
	}
	return false
}

func returnsFunctionLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	var body *ast.BlockOrExpression
	switch node.Kind {
	case ast.KindArrowFunction:
		arrowFunction := node.AsArrowFunction()
		if arrowFunction == nil {
			return false
		}
		body = arrowFunction.Body
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration == nil || functionDeclaration.Body == nil {
			return false
		}
		body = functionDeclaration.Body
	case ast.KindFunctionExpression:
		functionExpression := node.AsFunctionExpression()
		if functionExpression == nil || functionExpression.Body == nil {
			return false
		}
		body = functionExpression.Body
	}
	if body == nil {
		return false
	}
	if body.Kind != ast.KindBlock {
		return body.Kind == ast.KindArrowFunction || body.Kind == ast.KindFunctionExpression
	}
	block := body.AsBlock()
	if block == nil || block.Statements == nil {
		return false
	}
	for _, statement := range block.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindReturnStatement {
			continue
		}
		returnStatement := statement.AsReturnStatement()
		if returnStatement == nil || returnStatement.Expression == nil {
			continue
		}
		if returnStatement.Expression.Kind == ast.KindArrowFunction || returnStatement.Expression.Kind == ast.KindFunctionExpression {
			return true
		}
	}
	return false
}

func hasDirectConstAssertionInArrow(sourceFile *ast.SourceFile, node *ast.Node) bool {
	if sourceFile == nil || node == nil || node.Kind != ast.KindArrowFunction {
		return false
	}
	arrowFunction := node.AsArrowFunction()
	if arrowFunction == nil || arrowFunction.Body == nil || arrowFunction.Body.Kind == ast.KindBlock {
		return false
	}
	bodyRange := utils.TrimNodeTextRange(sourceFile, arrowFunction.Body.AsNode())
	text := sourceFile.Text()
	if bodyRange.Pos() < 0 || bodyRange.End() > len(text) || bodyRange.Pos() >= bodyRange.End() {
		return false
	}
	return strings.Contains(text[bodyRange.Pos():bodyRange.End()], " as const")
}

func isDirectlyReturnedFunction(node *ast.Node) bool {
	if node == nil {
		return false
	}
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindParenthesizedExpression {
			continue
		}
		if current.Kind == ast.KindReturnStatement {
			return true
		}
		if current.Kind == ast.KindArrowFunction {
			arrowFunction := current.AsArrowFunction()
			return arrowFunction != nil && arrowFunction.Body != nil && arrowFunction.Body.AsNode() == node
		}
		return false
	}
	return false
}

func arrowOperatorRange(sourceFile *ast.SourceFile, arrow *ast.ArrowFunction) core.TextRange {
	if sourceFile == nil || arrow == nil || arrow.Body == nil {
		return core.NewTextRange(0, 0)
	}
	start := arrow.Pos()
	if arrow.Type != nil {
		start = arrow.Type.End()
	} else if arrow.Parameters != nil && len(arrow.Parameters.Nodes) > 0 {
		lastParam := arrow.Parameters.Nodes[len(arrow.Parameters.Nodes)-1]
		if lastParam != nil {
			start = lastParam.End()
		}
	}
	end := arrow.Body.Pos()
	text := sourceFile.Text()
	if start >= 0 && end > start && end <= len(text) {
		segment := text[start:end]
		if index := strings.Index(segment, "=>"); index >= 0 {
			return core.NewTextRange(start+index, start+index+3)
		}
	}
	return core.NewTextRange(start, start+3)
}

func functionKeywordRange(sourceFile *ast.SourceFile, node *ast.Node) core.TextRange {
	if sourceFile == nil || node == nil {
		return core.NewTextRange(0, 0)
	}
	nodeRange := utils.TrimNodeTextRange(sourceFile, node)
	text := sourceFile.Text()
	if nodeRange.Pos() < 0 || nodeRange.End() > len(text) || nodeRange.Pos() >= nodeRange.End() {
		return core.NewTextRange(nodeRange.Pos(), nodeRange.Pos())
	}
	segment := text[nodeRange.Pos():nodeRange.End()]
	if index := strings.Index(segment, "function"); index >= 0 {
		start := nodeRange.Pos() + index
		return core.NewTextRange(start, start+len("function"))
	}
	return core.NewTextRange(nodeRange.Pos(), nodeRange.Pos())
}

func functionDeclarationSignatureRange(sourceFile *ast.SourceFile, functionDeclaration *ast.FunctionDeclaration) core.TextRange {
	if sourceFile == nil || functionDeclaration == nil {
		return core.NewTextRange(0, 0)
	}
	node := functionDeclaration.AsNode()
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	start := trimmed.Pos()
	if functionDeclaration.Name() != nil {
		return core.NewTextRange(start, functionDeclaration.Name().End())
	}
	return functionKeywordRange(sourceFile, node)
}

func shouldIgnore(node *ast.Node, ctx rule.RuleContext, opts explicitFunctionReturnTypeOptions) bool {
	if node == nil {
		return true
	}
	if hasAllowedName(functionName(node), opts.AllowedNames) {
		return true
	}
	if opts.AllowExpressions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression) && isExpressionFunction(node) {
		return true
	}
	if opts.AllowTypedFunctionExpressions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression) && isTypedFunctionExpressionContext(node) {
		return true
	}
	if opts.AllowHigherOrderFunctions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression || node.Kind == ast.KindFunctionDeclaration) && returnsFunctionLike(node) {
		return true
	}
	if opts.AllowHigherOrderFunctions && (node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression) && isDirectlyReturnedFunction(node) {
		return true
	}
	if opts.AllowDirectConstAssertionInArrowFunctions && hasDirectConstAssertionInArrow(ctx.SourceFile, node) {
		return true
	}
	return false
}

func reportMissingReturnType(ctx rule.RuleContext, node *ast.Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case ast.KindArrowFunction:
		arrow := node.AsArrowFunction()
		if arrow != nil {
			ctx.ReportRange(arrowOperatorRange(ctx.SourceFile, arrow), buildMissingReturnTypeMessage())
			return
		}
	case ast.KindFunctionExpression:
		ctx.ReportRange(functionKeywordRange(ctx.SourceFile, node), buildMissingReturnTypeMessage())
		return
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration != nil {
			ctx.ReportRange(functionDeclarationSignatureRange(ctx.SourceFile, functionDeclaration), buildMissingReturnTypeMessage())
			return
		}
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		if methodDeclaration != nil && methodDeclaration.Name() != nil {
			ctx.ReportNode(methodDeclaration.Name(), buildMissingReturnTypeMessage())
			return
		}
	case ast.KindGetAccessor:
		getAccessor := node.AsGetAccessorDeclaration()
		if getAccessor != nil && getAccessor.Name() != nil {
			ctx.ReportNode(getAccessor.Name(), buildMissingReturnTypeMessage())
			return
		}
	}
	ctx.ReportNode(node, buildMissingReturnTypeMessage())
}

var ExplicitFunctionReturnTypeRule = rule.CreateRule(rule.Rule{
	Name: "explicit-function-return-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		checkNode := func(node *ast.Node) {
			if node == nil {
				return
			}
			if hasExplicitReturnType(node) || shouldIgnore(node, ctx, opts) {
				return
			}
			reportMissingReturnType(ctx, node)
		}

		return rule.RuleListeners{
			ast.KindFunctionDeclaration: checkNode,
			ast.KindFunctionExpression:  checkNode,
			ast.KindArrowFunction:       checkNode,
			ast.KindMethodDeclaration:   checkNode,
			ast.KindGetAccessor:         checkNode,
		}
	},
})
