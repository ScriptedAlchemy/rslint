package no_unused_expressions

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type NoUnusedExpressionsOptions struct {
	AllowShortCircuit    bool `json:"allowShortCircuit"`
	AllowTaggedTemplates bool `json:"allowTaggedTemplates"`
	AllowTernary         bool `json:"allowTernary"`
}

func parseOptions(options any) NoUnusedExpressionsOptions {
	opts := NoUnusedExpressionsOptions{
		AllowShortCircuit:    false,
		AllowTaggedTemplates: false,
		AllowTernary:         false,
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

	if v, ok := optsMap["allowShortCircuit"].(bool); ok {
		opts.AllowShortCircuit = v
	}
	if v, ok := optsMap["allowTaggedTemplates"].(bool); ok {
		opts.AllowTaggedTemplates = v
	}
	if v, ok := optsMap["allowTernary"].(bool); ok {
		opts.AllowTernary = v
	}

	return opts
}

func buildUnusedExpressionMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unusedExpression",
		Description: "Expected an assignment or function call and instead saw an expression.",
	}
}

func unwrapTSExpressions(node *ast.Node) *ast.Node {
	for node != nil {
		switch node.Kind {
		case ast.KindAsExpression:
			node = node.AsAsExpression().Expression
		case ast.KindTypeAssertionExpression:
			node = node.AsTypeAssertion().Expression
		case ast.KindNonNullExpression:
			node = node.AsNonNullExpression().Expression
		default:
			return node
		}
	}
	return node
}

func isImportCall(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindCallExpression {
		return false
	}
	call := node.AsCallExpression()
	return call != nil && call.Expression != nil && call.Expression.Kind == ast.KindImportKeyword
}

func getContainerStatements(node *ast.Node) []*ast.Node {
	if node == nil || node.Parent == nil {
		return nil
	}

	parent := node.Parent
	switch parent.Kind {
	case ast.KindSourceFile:
		if source := parent.AsSourceFile(); source != nil && source.Statements != nil {
			return source.Statements.Nodes
		}
	case ast.KindBlock:
		if block := parent.AsBlock(); block != nil && block.Statements != nil {
			return block.Statements.Nodes
		}
	case ast.KindModuleBlock:
		if module := parent.AsModuleBlock(); module != nil && module.Statements != nil {
			return module.Statements.Nodes
		}
	}

	return nil
}

func isDirectivePrologue(node *ast.Node) bool {
	if node == nil || !ast.IsPrologueDirective(node) {
		return false
	}

	statements := getContainerStatements(node)
	if len(statements) == 0 {
		return false
	}

	index := -1
	for i, stmt := range statements {
		if stmt == node {
			index = i
			break
		}
	}
	if index == -1 {
		return false
	}

	for i := range index {
		if !ast.IsPrologueDirective(statements[i]) {
			return false
		}
	}

	return true
}

func isValidExpression(node *ast.Node, opts NoUnusedExpressionsOptions) bool {
	if node == nil {
		return false
	}

	node = ast.SkipParentheses(node)
	node = unwrapTSExpressions(node)
	if node == nil {
		return false
	}

	switch node.Kind {
	case ast.KindCallExpression, ast.KindNewExpression, ast.KindAwaitExpression, ast.KindYieldExpression:
		return true
	case ast.KindDeleteExpression:
		return true
	case ast.KindPostfixUnaryExpression:
		return true
	case ast.KindPrefixUnaryExpression:
		// ++x and --x have side effects
		prefix := node.AsPrefixUnaryExpression()
		if prefix != nil && (prefix.Operator == ast.KindPlusPlusToken || prefix.Operator == ast.KindMinusMinusToken) {
			return true
		}
		return false
	case ast.KindTaggedTemplateExpression:
		return opts.AllowTaggedTemplates
	case ast.KindBinaryExpression:
		binary := node.AsBinaryExpression()
		if binary == nil {
			return false
		}
		if ast.IsAssignmentExpression(node, true) {
			return true
		}

		if opts.AllowShortCircuit &&
			(binary.OperatorToken.Kind == ast.KindAmpersandAmpersandToken ||
				binary.OperatorToken.Kind == ast.KindBarBarToken ||
				binary.OperatorToken.Kind == ast.KindQuestionQuestionToken) {
			return isValidExpression(binary.Right, opts)
		}

		return false
	case ast.KindConditionalExpression:
		if !opts.AllowTernary {
			return false
		}
		conditional := node.AsConditionalExpression()
		if conditional == nil {
			return false
		}
		return isValidExpression(conditional.WhenTrue, opts) && isValidExpression(conditional.WhenFalse, opts)
	default:
		if isImportCall(node) {
			return true
		}
		return false
	}
}

var NoUnusedExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "no-unused-expressions",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindExpressionStatement: func(node *ast.Node) {
				stmt := node.AsExpressionStatement()
				if stmt == nil || stmt.Expression == nil {
					return
				}

				if isDirectivePrologue(node) {
					return
				}

				if isValidExpression(stmt.Expression, opts) {
					return
				}

				ctx.ReportNode(node, buildUnusedExpressionMessage())
			},
		}
	},
})
