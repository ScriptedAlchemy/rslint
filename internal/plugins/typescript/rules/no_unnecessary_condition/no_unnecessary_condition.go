package no_unnecessary_condition

import (
	"fmt"
	"strconv"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type NoUnnecessaryConditionOptions struct {
	AllowConstantLoopConditions                            *string `json:"allowConstantLoopConditions,omitempty"`
	AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing *bool   `json:"allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing,omitempty"`
	CheckTypePredicates                                    *bool   `json:"checkTypePredicates,omitempty"`
}

func parseOptions(options any) NoUnnecessaryConditionOptions {
	opts := NoUnnecessaryConditionOptions{
		AllowConstantLoopConditions:                            utils.Ref("never"),
		AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing: utils.Ref(false),
		CheckTypePredicates:                                    utils.Ref(false),
	}

	if options == nil {
		return opts
	}

	// Handle direct map format
	if m, ok := options.(map[string]any); ok {
		parseOptionsFromMap(m, &opts)
		return opts
	}

	// Handle array format: [{ option: value }]
	if arr, ok := options.([]any); ok {
		if len(arr) > 0 {
			if m, ok := arr[0].(map[string]any); ok {
				parseOptionsFromMap(m, &opts)
			}
		}
	}

	return opts
}

func parseOptionsFromMap(m map[string]any, opts *NoUnnecessaryConditionOptions) {
	if v, ok := m["allowConstantLoopConditions"]; ok {
		// Can be boolean or string
		switch val := v.(type) {
		case bool:
			if val {
				opts.AllowConstantLoopConditions = utils.Ref("always")
			} else {
				opts.AllowConstantLoopConditions = utils.Ref("never")
			}
		case string:
			opts.AllowConstantLoopConditions = utils.Ref(val)
		}
	}
	if v, ok := m["allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing"].(bool); ok {
		opts.AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing = utils.Ref(v)
	}
	if v, ok := m["checkTypePredicates"].(bool); ok {
		opts.CheckTypePredicates = utils.Ref(v)
	}
}

// Rule message builders
func buildAlwaysFalsyMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "alwaysFalsy",
		Description: "Unnecessary conditional, value is always falsy.",
	}
}

func buildAlwaysTruthyMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "alwaysTruthy",
		Description: "Unnecessary conditional, value is always truthy.",
	}
}

func buildNeverMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "never",
		Description: "Unnecessary conditional, value is `never`.",
	}
}

func buildAlwaysNullishMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "alwaysNullish",
		Description: "Unnecessary conditional, left-hand side of `??` operator is always `null` or `undefined`.",
	}
}

func buildNeverNullishMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "neverNullish",
		Description: "Unnecessary conditional, expected left-hand side of `??` operator to be possibly null or undefined.",
	}
}

func buildNoStrictNullCheckMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noStrictNullCheck",
		Description: "This rule requires the `strictNullChecks` compiler option to be turned on to function correctly.",
	}
}

func buildComparisonBetweenLiteralTypesMessage(left, operator, right string, result bool) rule.RuleMessage {
	trueOrFalse := "false"
	if result {
		trueOrFalse = "true"
	}
	return rule.RuleMessage{
		Id: "comparisonBetweenLiteralTypes",
		Description: fmt.Sprintf(
			"Unnecessary conditional, comparison is always %s, since `%s %s %s` is %s.",
			trueOrFalse,
			left,
			operator,
			right,
			trueOrFalse,
		),
	}
}

// Type checking utilities using the correct RSLint APIs
func isNeverType(typeOfNode *checker.Type) bool {
	return utils.IsTypeFlagSet(typeOfNode, checker.TypeFlagsNever)
}

func isNullType(typeOfNode *checker.Type) bool {
	return utils.IsTypeFlagSet(typeOfNode, checker.TypeFlagsNull)
}

func isUndefinedType(typeOfNode *checker.Type) bool {
	return utils.IsTypeFlagSet(typeOfNode, checker.TypeFlagsUndefined)
}

func isVoidType(typeOfNode *checker.Type) bool {
	return utils.IsTypeFlagSet(typeOfNode, checker.TypeFlagsVoid)
}

// Check if type could be nullish (null | undefined)
func isPossiblyNullish(typeOfNode *checker.Type) bool {
	if isNullType(typeOfNode) || isUndefinedType(typeOfNode) || isVoidType(typeOfNode) {
		return true
	}

	// For union types, check if any constituent could be nullish
	if utils.IsUnionType(typeOfNode) {
		for _, unionType := range utils.UnionTypeParts(typeOfNode) {
			if isPossiblyNullish(unionType) {
				return true
			}
		}
	}
	return false
}

// isTypeNeverNullish checks if a type can never be null or undefined
func isTypeNeverNullish(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil {
		return false
	}

	// Check for any or unknown types - these could be nullish
	flags := checker.Type_flags(t)
	if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown|checker.TypeFlagsTypeParameter) != 0 {
		return false
	}

	// Check if the type itself is null, undefined, or void
	if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
		return false
	}

	// For union types, check if any constituent could be nullish
	if utils.IsUnionType(t) {
		for _, unionType := range t.Types() {
			typeFlags := checker.Type_flags(unionType)
			if typeFlags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
				return false
			}
		}
	}

	// If we get here, the type cannot be nullish
	return true
}

// isAlwaysTruthy checks if a type is always truthy (cannot be falsy)
func isAlwaysTruthy(t *checker.Type) bool {
	if t == nil {
		return false
	}

	flags := checker.Type_flags(t)

	// Any and unknown could be falsy
	if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown) != 0 {
		return false
	}

	// Never type cannot have a value
	if flags&checker.TypeFlagsNever != 0 {
		return false
	}

	// These types are always falsy or could be falsy
	if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
		return false
	}

	// Check for union types - all parts must be truthy
	if utils.IsUnionType(t) {
		for _, unionType := range t.Types() {
			if !isAlwaysTruthy(unionType) {
				return false
			}
		}
		return true
	}

	// Boolean type (not literal) can be true or false, so not always truthy
	if flags&checker.TypeFlagsBoolean != 0 {
		return false
	}

	// Boolean literals - check if it's the 'true' literal
	if flags&checker.TypeFlagsBooleanLiteral != 0 {
		if utils.IsIntrinsicType(t) {
			intrinsic := t.AsIntrinsicType()
			if intrinsic != nil && intrinsic.IntrinsicName() == "true" {
				return true
			}
		}
		return false
	}

	// Number literals could be 0, -0, or NaN (falsy values)
	if flags&checker.TypeFlagsNumberLiteral != 0 {
		// Would need to check the actual value
		// For now, conservatively return false
		return false
	}

	// String literals could be "" (falsy)
	if flags&checker.TypeFlagsStringLiteral != 0 {
		// Would need to check for empty string
		// For now, conservatively return false
		return false
	}

	// BigInt literals could be 0n (falsy)
	if flags&checker.TypeFlagsBigIntLiteral != 0 {
		// Would need to check for 0n
		return false
	}

	// Object types are always truthy
	if flags&checker.TypeFlagsObject != 0 {
		return true
	}

	return false
}

func isConditionalAlwaysNecessary(t *checker.Type) bool {
	if t == nil {
		return false
	}
	for _, part := range utils.UnionTypeParts(t) {
		if utils.IsTypeFlagSet(part, checker.TypeFlagsAny|checker.TypeFlagsUnknown|checker.TypeFlagsTypeParameter) {
			return true
		}
	}
	return false
}

// isAlwaysFalsy checks if a type is always falsy
func isAlwaysFalsy(t *checker.Type) bool {
	if t == nil {
		return false
	}

	flags := checker.Type_flags(t)

	// Null, undefined, and void are always falsy
	if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
		return true
	}

	// Check for literal false
	if flags&checker.TypeFlagsBooleanLiteral != 0 {
		if utils.IsIntrinsicType(t) {
			intrinsic := t.AsIntrinsicType()
			if intrinsic != nil && intrinsic.IntrinsicName() == "false" {
				return true
			}
		}
	}

	// Would need to check for literal 0, -0, NaN, "", 0n
	// For now, we don't mark these as always falsy

	return false
}

func constBooleanLiteralValue(ctx rule.RuleContext, node *ast.Node) (bool, bool) {
	if node == nil {
		return false, false
	}

	if node.Kind == ast.KindTrueKeyword {
		return true, true
	}
	if node.Kind == ast.KindFalseKeyword {
		return false, true
	}
	if node.Kind != ast.KindIdentifier || ctx.TypeChecker == nil {
		return false, false
	}

	symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
	if symbol == nil || symbol.ValueDeclaration == nil {
		return false, false
	}

	decl := symbol.ValueDeclaration
	if decl.Kind != ast.KindVariableDeclaration || decl.Parent == nil || decl.Parent.Kind != ast.KindVariableDeclarationList {
		return false, false
	}

	declList := decl.Parent.AsVariableDeclarationList()
	if declList == nil || declList.Flags&ast.NodeFlagsConst == 0 {
		return false, false
	}

	initializer := decl.AsVariableDeclaration().Initializer
	if initializer == nil {
		return false, false
	}
	if initializer.Kind == ast.KindTrueKeyword {
		return true, true
	}
	if initializer.Kind == ast.KindFalseKeyword {
		return false, true
	}

	return false, false
}

// checkCondition checks if a condition is unnecessary (always true/false/never)
func checkCondition(ctx rule.RuleContext, node *ast.Node, isNegated bool) {
	if node == nil {
		return
	}

	if value, ok := constBooleanLiteralValue(ctx, node); ok {
		if value {
			ctx.ReportNode(node, buildAlwaysTruthyMessage())
		} else {
			ctx.ReportNode(node, buildAlwaysFalsyMessage())
		}
		return
	}

	// Get the type of the condition expression
	conditionType := ctx.TypeChecker.GetTypeAtLocation(node)
	if conditionType == nil {
		return
	}

	// Check for never type
	if isNeverType(conditionType) {
		ctx.ReportNode(node, buildNeverMessage())
		return
	}

	// Check for always truthy
	if isAlwaysTruthy(conditionType) {
		ctx.ReportNode(node, buildAlwaysTruthyMessage())
		return
	}

	// Check for always falsy
	if isAlwaysFalsy(conditionType) {
		ctx.ReportNode(node, buildAlwaysFalsyMessage())
		return
	}
}

// isBooleanOperator checks if a token kind represents a boolean comparison operator
func isBooleanOperator(kind ast.Kind) bool {
	switch kind {
	case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken,
		ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken,
		ast.KindLessThanToken, ast.KindLessThanEqualsToken,
		ast.KindGreaterThanToken, ast.KindGreaterThanEqualsToken:
		return true
	}
	return false
}

func boolOperatorToken(kind ast.Kind) (string, bool) {
	switch kind {
	case ast.KindLessThanToken:
		return "<", true
	case ast.KindGreaterThanToken:
		return ">", true
	case ast.KindLessThanEqualsToken:
		return "<=", true
	case ast.KindGreaterThanEqualsToken:
		return ">=", true
	case ast.KindEqualsEqualsToken:
		return "==", true
	case ast.KindEqualsEqualsEqualsToken:
		return "===", true
	case ast.KindExclamationEqualsToken:
		return "!=", true
	case ast.KindExclamationEqualsEqualsToken:
		return "!==", true
	}
	return "", false
}

func trimNodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	text := sourceFile.Text()
	if trimmed.Pos() < 0 || trimmed.End() > len(text) || trimmed.Pos() >= trimmed.End() {
		return ""
	}
	return text[trimmed.Pos():trimmed.End()]
}

func staticLiteralValue(ctx rule.RuleContext, node *ast.Node, depth int) (any, bool) {
	if node == nil || depth > 3 {
		return nil, false
	}
	switch node.Kind {
	case ast.KindTrueKeyword:
		return true, true
	case ast.KindFalseKeyword:
		return false, true
	case ast.KindNullKeyword:
		return nil, true
	case ast.KindStringLiteral:
		return node.AsStringLiteral().Text, true
	case ast.KindNumericLiteral:
		lit := node.AsNumericLiteral()
		if lit == nil {
			return nil, false
		}
		number, err := strconv.ParseFloat(lit.Text, 64)
		if err != nil {
			return nil, false
		}
		return number, true
	case ast.KindPrefixUnaryExpression:
		expr := node.AsPrefixUnaryExpression()
		if expr == nil || expr.Operand == nil || expr.Operand.Kind != ast.KindNumericLiteral {
			return nil, false
		}
		value, ok := staticLiteralValue(ctx, expr.Operand, depth+1)
		if !ok {
			return nil, false
		}
		number, ok := value.(float64)
		if !ok {
			return nil, false
		}
		if expr.Operator == ast.KindMinusToken {
			return -number, true
		}
		if expr.Operator == ast.KindPlusToken {
			return number, true
		}
	case ast.KindIdentifier:
		identifier := node.AsIdentifier()
		if identifier == nil {
			return nil, false
		}
		if identifier.Text == "undefined" {
			return "undefined", true
		}
		if ctx.TypeChecker == nil {
			return nil, false
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
		if symbol == nil || symbol.ValueDeclaration == nil || symbol.ValueDeclaration.Kind != ast.KindVariableDeclaration {
			return nil, false
		}
		decl := symbol.ValueDeclaration.AsVariableDeclaration()
		if decl == nil || decl.Initializer == nil || decl.AsNode().Parent == nil || decl.AsNode().Parent.Kind != ast.KindVariableDeclarationList {
			return nil, false
		}
		declList := decl.AsNode().Parent.AsVariableDeclarationList()
		if declList == nil || declList.Flags&ast.NodeFlagsConst == 0 {
			return nil, false
		}
		return staticLiteralValue(ctx, decl.Initializer, depth+1)
	}

	return nil, false
}

func compareStaticValues(left any, operator string, right any) (bool, bool) {
	switch operator {
	case "==", "===":
		switch l := left.(type) {
		case bool:
			r, ok := right.(bool)
			if !ok {
				return false, false
			}
			return l == r, true
		case float64:
			r, ok := right.(float64)
			if !ok {
				return false, false
			}
			return l == r, true
		case string:
			r, ok := right.(string)
			if !ok {
				return false, false
			}
			return l == r, true
		case nil:
			return right == nil, true
		}
	case "!=", "!==":
		value, ok := compareStaticValues(left, map[string]string{"!=": "==", "!==": "==="}[operator], right)
		if !ok {
			return false, false
		}
		return !value, true
	case "<", "<=", ">", ">=":
		if leftNumber, ok := left.(float64); ok {
			rightNumber, ok := right.(float64)
			if !ok {
				return false, false
			}
			switch operator {
			case "<":
				return leftNumber < rightNumber, true
			case "<=":
				return leftNumber <= rightNumber, true
			case ">":
				return leftNumber > rightNumber, true
			case ">=":
				return leftNumber >= rightNumber, true
			}
		}
	}
	return false, false
}

var NoUnnecessaryConditionRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-condition",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		// Check for strict null checks
		compilerOptions := ctx.Program.Options()
		isStrictNullChecks := utils.IsStrictCompilerOptionEnabled(
			compilerOptions,
			compilerOptions.StrictNullChecks,
		)

		if !isStrictNullChecks && !*opts.AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing {
			// Report at the beginning of the file
			ctx.ReportNode(&ast.Node{}, buildNoStrictNullCheckMessage())
			return rule.RuleListeners{}
		}

		return rule.RuleListeners{
			// If statement conditions
			ast.KindIfStatement: func(node *ast.Node) {
				ifStmt := node.AsIfStatement()
				if ifStmt != nil {
					checkCondition(ctx, ifStmt.Expression, false)
				}
			},

			// While loop conditions
			ast.KindWhileStatement: func(node *ast.Node) {
				whileStmt := node.AsWhileStatement()
				if whileStmt != nil && whileStmt.Expression != nil {
					// Handle constant loop conditions
					if *opts.AllowConstantLoopConditions != "never" {
						if _, ok := constBooleanLiteralValue(ctx, whileStmt.Expression); ok {
							return
						}
					}
					checkCondition(ctx, whileStmt.Expression, false)
				}
			},

			// For loop conditions
			ast.KindForStatement: func(node *ast.Node) {
				forStmt := node.AsForStatement()
				if forStmt != nil && forStmt.Condition != nil {
					if *opts.AllowConstantLoopConditions != "never" {
						if _, ok := constBooleanLiteralValue(ctx, forStmt.Condition); ok {
							return
						}
					}
					checkCondition(ctx, forStmt.Condition, false)
				}
			},

			// Do-while loop conditions
			ast.KindDoStatement: func(node *ast.Node) {
				doStmt := node.AsDoStatement()
				if doStmt != nil && doStmt.Expression != nil {
					if *opts.AllowConstantLoopConditions != "never" {
						if _, ok := constBooleanLiteralValue(ctx, doStmt.Expression); ok {
							return
						}
					}
					checkCondition(ctx, doStmt.Expression, false)
				}
			},

			// Conditional expressions (ternary)
			ast.KindConditionalExpression: func(node *ast.Node) {
				condExpr := node.AsConditionalExpression()
				if condExpr != nil {
					checkCondition(ctx, condExpr.Condition, false)
				}
			},

			// Binary expressions (comparisons and logical expressions)
			ast.KindBinaryExpression: func(node *ast.Node) {
				binExpr := node.AsBinaryExpression()
				if binExpr != nil {
					// Handle logical AND/OR
					if binExpr.OperatorToken.Kind == ast.KindAmpersandAmpersandToken ||
						binExpr.OperatorToken.Kind == ast.KindBarBarToken {
						checkCondition(ctx, binExpr.Left, false)
						checkCondition(ctx, binExpr.Right, false)
						return
					}

					// Handle nullish coalescing operator (??)
					if binExpr.OperatorToken.Kind == ast.KindQuestionQuestionToken {
						leftType := ctx.TypeChecker.GetTypeAtLocation(binExpr.Left)
						if leftType != nil {
							if isConditionalAlwaysNecessary(leftType) {
								return
							}
							// Check if left side can never be nullish (null or undefined)
							if isTypeNeverNullish(leftType, ctx.TypeChecker) {
								ctx.ReportNode(binExpr.Left, buildNeverNullishMessage())
							}
							// Check if left side is always nullish
							if isAlwaysFalsy(leftType) && isPossiblyNullish(leftType) {
								ctx.ReportNode(binExpr.Left, buildAlwaysNullishMessage())
							}
						}
						return
					}

					// Handle boolean comparisons
					if isBooleanOperator(binExpr.OperatorToken.Kind) {
						leftValue, leftOK := staticLiteralValue(ctx, binExpr.Left, 0)
						rightValue, rightOK := staticLiteralValue(ctx, binExpr.Right, 0)
						operatorToken, tokenOK := boolOperatorToken(binExpr.OperatorToken.Kind)
						if leftOK && rightOK && tokenOK {
							if result, ok := compareStaticValues(leftValue, operatorToken, rightValue); ok {
								leftText := trimNodeText(ctx.SourceFile, binExpr.Left)
								rightText := trimNodeText(ctx.SourceFile, binExpr.Right)
								ctx.ReportNode(node, buildComparisonBetweenLiteralTypesMessage(leftText, operatorToken, rightText, result))
							}
						}
					}
				}
			},
			ast.KindSwitchStatement: func(node *ast.Node) {
				switchStmt := node.AsSwitchStatement()
				if switchStmt != nil && switchStmt.Expression != nil {
					checkCondition(ctx, switchStmt.Expression, false)
				}
			},
		}
	},
})
