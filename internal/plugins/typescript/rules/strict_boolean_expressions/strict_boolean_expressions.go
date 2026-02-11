package strict_boolean_expressions

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildConditionErrorMessage(messageId string) rule.RuleMessage {
	descriptions := map[string]string{
		"conditionErrorAny":             "Unexpected any value in conditional.",
		"conditionErrorNullableBoolean": "Unexpected nullable boolean value in conditional.",
		"conditionErrorNullableEnum":    "Unexpected nullable enum value in conditional.",
		"conditionErrorNullableNumber":  "Unexpected nullable number value in conditional.",
		"conditionErrorNullableObject":  "Unexpected nullable object value in conditional.",
		"conditionErrorNullableString":  "Unexpected nullable string value in conditional.",
		"conditionErrorNullish":         "Unexpected nullish value in conditional. The condition is always false.",
		"conditionErrorNumber":          "Unexpected number value in conditional.",
		"conditionErrorObject":          "Unexpected object value in conditional. The condition is always true.",
		"conditionErrorString":          "Unexpected string value in conditional.",
		"conditionErrorOther":           "Unexpected value in conditional. A boolean expression is required.",
	}
	description, ok := descriptions[messageId]
	if !ok {
		messageId = "conditionErrorOther"
		description = descriptions[messageId]
	}
	return rule.RuleMessage{
		Id:          messageId,
		Description: description,
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
		AllowString:          true,
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

func conditionErrorMessageID(condType *checker.Type, opts strictBooleanExpressionsOptions) string {
	if condType == nil {
		return ""
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
	hasNonNeverValue := false

	for _, part := range parts {
		if part == nil {
			continue
		}
		flags := checker.Type_flags(part)
		if flags&checker.TypeFlagsNever != 0 {
			continue
		}
		hasNonNeverValue = true
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

	if !hasNonNeverValue {
		return ""
	}
	if hasOther {
		return "conditionErrorOther"
	}
	if hasNullish && !hasAny && !hasBoolean && !hasEnum && !hasNumber && !hasString && !hasObject {
		return "conditionErrorNullish"
	}
	if hasAny && !opts.AllowAny {
		return "conditionErrorAny"
	}
	if hasNullish {
		if hasBoolean && !opts.AllowNullableBoolean {
			return "conditionErrorNullableBoolean"
		}
		if hasEnum && !opts.AllowNullableEnum {
			return "conditionErrorNullableEnum"
		}
		if hasNumber && !opts.AllowNullableNumber {
			return "conditionErrorNullableNumber"
		}
		if hasString && !opts.AllowNullableString {
			return "conditionErrorNullableString"
		}
		if hasObject && !opts.AllowNullableObject {
			return "conditionErrorNullableObject"
		}
	}

	if hasObject && !hasNullish {
		return "conditionErrorObject"
	}
	if hasNumber && !opts.AllowNumber {
		return "conditionErrorNumber"
	}
	if hasEnum && !opts.AllowNumber {
		return "conditionErrorNumber"
	}
	if hasString && !opts.AllowString {
		return "conditionErrorString"
	}
	return ""
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
		ctx.ReportNode(cond, buildConditionErrorMessage("conditionErrorOther"))
		return
	}

	condType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, cond)
	messageId := conditionErrorMessageID(condType, opts)
	if messageId == "" {
		return
	}
	ctx.ReportNode(cond, buildConditionErrorMessage(messageId))
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
