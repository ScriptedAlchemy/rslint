package strict_boolean_expressions

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildConditionErrorOtherMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "conditionErrorOther",
		Description: "Unexpected value in conditional. A boolean expression is required.",
	}
}

type strictBooleanExpressionsOptions struct {
	AllowAny             bool
	AllowNullableBoolean bool
	AllowNullableEnum    bool
	AllowNullableNumber  bool
	AllowNullableObject  bool
	AllowNullableString  bool
	AllowNumber          bool
	AllowString          bool
}

func defaultStrictBooleanExpressionsOptions() strictBooleanExpressionsOptions {
	return strictBooleanExpressionsOptions{
		AllowAny:             false,
		AllowNullableBoolean: false,
		AllowNullableEnum:    false,
		AllowNullableNumber:  false,
		AllowNullableObject:  true,
		AllowNullableString:  false,
		AllowNumber:          true,
		AllowString:          false,
	}
}

func applyStrictBooleanOptionsMap(opts strictBooleanExpressionsOptions, values map[string]any) strictBooleanExpressionsOptions {
	if allowAny, ok := values["allowAny"].(bool); ok {
		opts.AllowAny = allowAny
	}
	if allowNullableBoolean, ok := values["allowNullableBoolean"].(bool); ok {
		opts.AllowNullableBoolean = allowNullableBoolean
	}
	if allowNullableEnum, ok := values["allowNullableEnum"].(bool); ok {
		opts.AllowNullableEnum = allowNullableEnum
	}
	if allowNullableNumber, ok := values["allowNullableNumber"].(bool); ok {
		opts.AllowNullableNumber = allowNullableNumber
	}
	if allowNullableObject, ok := values["allowNullableObject"].(bool); ok {
		opts.AllowNullableObject = allowNullableObject
	}
	if allowNullableString, ok := values["allowNullableString"].(bool); ok {
		opts.AllowNullableString = allowNullableString
	}
	if allowNumber, ok := values["allowNumber"].(bool); ok {
		opts.AllowNumber = allowNumber
	}
	if allowString, ok := values["allowString"].(bool); ok {
		opts.AllowString = allowString
	}
	return opts
}

func parseStrictBooleanExpressionsOptions(options any) strictBooleanExpressionsOptions {
	opts := defaultStrictBooleanExpressionsOptions()

	switch values := options.(type) {
	case map[string]interface{}:
		opts = applyStrictBooleanOptionsMap(opts, values)
	case []interface{}:
		if len(values) == 0 {
			return opts
		}
		first := values[0]
		if firstMap, ok := first.(map[string]interface{}); ok {
			opts = applyStrictBooleanOptionsMap(opts, firstMap)
		}
	}

	return opts
}

func isBooleanLikeSyntax(node *ast.Node) bool {
	if node == nil {
		return true
	}
	switch node.Kind {
	case ast.KindTrueKeyword, ast.KindFalseKeyword:
		return true
	case ast.KindPrefixUnaryExpression:
		unary := node.AsPrefixUnaryExpression()
		return unary != nil && unary.Operator == ast.KindExclamationToken
	case ast.KindBinaryExpression:
		binary := node.AsBinaryExpression()
		if binary == nil {
			return false
		}
		switch binary.OperatorToken.Kind {
		case ast.KindEqualsEqualsToken, ast.KindExclamationEqualsToken, ast.KindEqualsEqualsEqualsToken, ast.KindExclamationEqualsEqualsToken, ast.KindLessThanToken, ast.KindLessThanEqualsToken, ast.KindGreaterThanToken, ast.KindGreaterThanEqualsToken, ast.KindAmpersandAmpersandToken, ast.KindBarBarToken:
			return true
		}
	}
	return false
}

func isConditionTypeAllowed(condType *checker.Type, opts strictBooleanExpressionsOptions) bool {
	if condType == nil {
		return true
	}

	parts := utils.UnionTypeParts(condType)
	if len(parts) == 0 {
		parts = []*checker.Type{condType}
	}

	hasNullish := false
	hasAny := false
	hasBoolean := false
	hasNumber := false
	hasString := false
	hasEnum := false
	hasObject := false
	hasOther := false

	for _, part := range parts {
		if part == nil {
			continue
		}
		flags := checker.Type_flags(part)
		if flags&checker.TypeFlagsNever != 0 {
			continue
		}
		if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
			hasNullish = true
			continue
		}
		if flags&checker.TypeFlagsAny != 0 {
			hasAny = true
			continue
		}
		if flags&checker.TypeFlagsEnumLike != 0 {
			hasEnum = true
			continue
		}
		if flags&checker.TypeFlagsBooleanLike != 0 {
			hasBoolean = true
			continue
		}
		if flags&(checker.TypeFlagsNumberLike|checker.TypeFlagsBigIntLike) != 0 {
			hasNumber = true
			continue
		}
		if flags&checker.TypeFlagsStringLike != 0 {
			hasString = true
			continue
		}
		if flags&(checker.TypeFlagsObject|checker.TypeFlagsNonPrimitive) != 0 {
			hasObject = true
			continue
		}
		hasOther = true
	}

	if hasOther {
		return false
	}
	if hasAny && !opts.AllowAny {
		return false
	}
	if hasString && !opts.AllowString {
		return false
	}
	if hasNumber && !opts.AllowNumber {
		return false
	}
	if hasObject && !hasNullish {
		return false
	}

	if hasNullish {
		if hasBoolean && !opts.AllowNullableBoolean {
			return false
		}
		if hasEnum && !opts.AllowNullableEnum {
			return false
		}
		if hasNumber && !opts.AllowNullableNumber {
			return false
		}
		if hasString && !opts.AllowNullableString {
			return false
		}
		if hasObject && !opts.AllowNullableObject {
			return false
		}
		if !hasBoolean && !hasEnum && !hasNumber && !hasString && !hasObject && !hasAny {
			return false
		}
	}

	return hasAny || hasBoolean || hasEnum || hasNumber || hasString || hasObject
}

func checkCondition(ctx rule.RuleContext, cond *ast.Node, opts strictBooleanExpressionsOptions) {
	cond = ast.SkipParentheses(cond)
	if cond == nil {
		return
	}

	switch cond.Kind {
	case ast.KindPrefixUnaryExpression:
		unary := cond.AsPrefixUnaryExpression()
		if unary != nil && unary.Operator == ast.KindExclamationToken {
			checkCondition(ctx, unary.Operand, opts)
			return
		}
	case ast.KindBinaryExpression:
		binary := cond.AsBinaryExpression()
		if binary != nil && (binary.OperatorToken.Kind == ast.KindAmpersandAmpersandToken || binary.OperatorToken.Kind == ast.KindBarBarToken) {
			checkCondition(ctx, binary.Left, opts)
			checkCondition(ctx, binary.Right, opts)
			return
		}
	}

	if ctx.TypeChecker == nil {
		if isBooleanLikeSyntax(cond) {
			return
		}
		ctx.ReportNode(cond, buildConditionErrorOtherMessage())
		return
	}

	condType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, cond)
	if isConditionTypeAllowed(condType, opts) {
		return
	}
	ctx.ReportNode(cond, buildConditionErrorOtherMessage())
}

var StrictBooleanExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "strict-boolean-expressions",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseStrictBooleanExpressionsOptions(options)

		return rule.RuleListeners{
			ast.KindIfStatement: func(node *ast.Node) {
				stmt := node.AsIfStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression, opts)
			},
			ast.KindWhileStatement: func(node *ast.Node) {
				stmt := node.AsWhileStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression, opts)
			},
			ast.KindDoStatement: func(node *ast.Node) {
				stmt := node.AsDoStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression, opts)
			},
			ast.KindForStatement: func(node *ast.Node) {
				stmt := node.AsForStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Condition, opts)
			},
			ast.KindConditionalExpression: func(node *ast.Node) {
				cond := node.AsConditionalExpression()
				if cond == nil {
					return
				}
				checkCondition(ctx, cond.Condition, opts)
			},
		}
	},
})
