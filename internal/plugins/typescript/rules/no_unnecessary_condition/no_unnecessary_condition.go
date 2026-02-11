package no_unnecessary_condition

import (
	"fmt"
	"strconv"
	"strings"

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

func buildAlwaysFalsyFuncMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "alwaysFalsyFunc",
		Description: "Unnecessary conditional, function always returns a falsy value.",
	}
}

func buildAlwaysTruthyFuncMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "alwaysTruthyFunc",
		Description: "Unnecessary conditional, function always returns a truthy value.",
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

func buildNoOverlapBooleanExpressionMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noOverlapBooleanExpression",
		Description: "Unnecessary conditional, the two sides of this comparison do not overlap.",
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
func isPossiblyNullish(typeOfNode *checker.Type, typeChecker *checker.Checker) bool {
	if typeOfNode == nil {
		return false
	}
	if isNullType(typeOfNode) || isUndefinedType(typeOfNode) || isVoidType(typeOfNode) {
		return true
	}
	if utils.IsTypeFlagSet(typeOfNode, checker.TypeFlagsTypeParameter) {
		if typeChecker != nil {
			if constraint := typeChecker.GetConstraintOfTypeParameter(typeOfNode); constraint != nil && constraint != typeOfNode {
				return isPossiblyNullish(constraint, typeChecker)
			}
		}
		return false
	}

	// For union types, check if any constituent could be nullish
	if utils.IsUnionType(typeOfNode) {
		for _, unionType := range utils.UnionTypeParts(typeOfNode) {
			if isPossiblyNullish(unionType, typeChecker) {
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
	if flags&checker.TypeFlagsTypeParameter != 0 {
		if typeChecker != nil {
			if constraint := typeChecker.GetConstraintOfTypeParameter(t); constraint != nil && constraint != t {
				return isTypeNeverNullish(constraint, typeChecker)
			}
		}
		return false
	}
	if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown) != 0 {
		return false
	}
	if flags&(checker.TypeFlagsTypeVariable|checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution) != 0 {
		if typeChecker != nil {
			if constraint := checker.Checker_getBaseConstraintOfType(typeChecker, t); constraint != nil && constraint != t {
				return isTypeNeverNullish(constraint, typeChecker)
			}
		}
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

func typeCanIncludeNull(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil {
		return true
	}
	flags := checker.Type_flags(t)
	if flags&checker.TypeFlagsNull != 0 {
		return true
	}
	if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown|checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution) != 0 {
		return true
	}
	if flags&checker.TypeFlagsTypeParameter != 0 {
		if typeChecker != nil {
			if constraint := typeChecker.GetConstraintOfTypeParameter(t); constraint != nil && constraint != t {
				return typeCanIncludeNull(constraint, typeChecker)
			}
		}
		return true
	}
	if utils.IsUnionType(t) {
		for _, part := range t.Types() {
			if typeCanIncludeNull(part, typeChecker) {
				return true
			}
		}
	}
	return false
}

func typeCanIncludeUndefined(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil {
		return true
	}
	flags := checker.Type_flags(t)
	if flags&(checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
		return true
	}
	if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown|checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution) != 0 {
		return true
	}
	if flags&checker.TypeFlagsTypeParameter != 0 {
		if typeChecker != nil {
			if constraint := typeChecker.GetConstraintOfTypeParameter(t); constraint != nil && constraint != t {
				return typeCanIncludeUndefined(constraint, typeChecker)
			}
		}
		return true
	}
	if utils.IsUnionType(t) {
		for _, part := range t.Types() {
			if typeCanIncludeUndefined(part, typeChecker) {
				return true
			}
		}
	}
	return false
}

func reportStaticLiteralComparison(ctx rule.RuleContext, node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return false
	}
	binExpr := node.AsBinaryExpression()
	if binExpr == nil || !isBooleanOperator(binExpr.OperatorToken.Kind) {
		return false
	}

	leftValue, leftOK := staticLiteralValue(ctx, binExpr.Left, 0)
	rightValue, rightOK := staticLiteralValue(ctx, binExpr.Right, 0)
	operatorToken, tokenOK := boolOperatorToken(binExpr.OperatorToken.Kind)
	if !leftOK || !rightOK || !tokenOK {
		return false
	}
	result, ok := compareStaticValues(leftValue, operatorToken, rightValue)
	if !ok {
		return false
	}

	leftText := trimNodeText(ctx.SourceFile, binExpr.Left)
	rightText := trimNodeText(ctx.SourceFile, binExpr.Right)
	ctx.ReportNode(node, buildComparisonBetweenLiteralTypesMessage(leftText, operatorToken, rightText, result))
	return true
}

func literalValueFromType(typeChecker *checker.Checker, t *checker.Type) (any, bool, string) {
	if t == nil {
		return nil, false, ""
	}

	flags := checker.Type_flags(t)
	if flags&checker.TypeFlagsNull != 0 {
		return nil, true, "null"
	}
	if flags&checker.TypeFlagsUndefined != 0 {
		return "undefined", true, "undefined"
	}

	if flags&(checker.TypeFlagsBooleanLiteral|checker.TypeFlagsStringLiteral|checker.TypeFlagsNumberLiteral|checker.TypeFlagsBigIntLiteral|checker.TypeFlagsEnumLiteral) != 0 {
		if literal := t.AsLiteralType(); literal != nil {
			switch value := checker.LiteralType_value(literal).(type) {
			case bool:
				if value {
					return true, true, "true"
				}
				return false, true, "false"
			case string:
				return value, true, strconv.Quote(value)
			case float64:
				return value, true, strconv.FormatFloat(value, 'f', -1, 64)
			case int:
				return float64(value), true, strconv.Itoa(value)
			case int32:
				return float64(value), true, strconv.FormatInt(int64(value), 10)
			case int64:
				return float64(value), true, strconv.FormatInt(value, 10)
			default:
				numericText := fmt.Sprint(value)
				if flags&checker.TypeFlagsBigIntLiteral != 0 {
					trimmed := strings.TrimSpace(numericText)
					if !strings.HasSuffix(trimmed, "n") {
						trimmed += "n"
					}
					if parsed, err := strconv.ParseFloat(strings.TrimSuffix(trimmed, "n"), 64); err == nil {
						return parsed, true, trimmed
					}
				}
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(numericText), 64); err == nil {
					return parsed, true, numericText
				}
			}
		}
	}

	if typeChecker == nil {
		return nil, false, ""
	}
	typeText := strings.TrimSpace(typeChecker.TypeToString(t))
	if typeText == "true" {
		return true, true, "true"
	}
	if typeText == "false" {
		return false, true, "false"
	}
	if typeText == "null" {
		return nil, true, "null"
	}
	if typeText == "undefined" {
		return "undefined", true, "undefined"
	}
	if strings.HasPrefix(typeText, `"`) && strings.HasSuffix(typeText, `"`) {
		unquoted, err := strconv.Unquote(typeText)
		if err == nil {
			return unquoted, true, typeText
		}
	}
	if strings.HasPrefix(typeText, `'`) && strings.HasSuffix(typeText, `'`) {
		unquoted, err := strconv.Unquote(strings.ReplaceAll(typeText, `'`, `"`))
		if err == nil {
			return unquoted, true, strconv.Quote(unquoted)
		}
	}
	if numeric, err := strconv.ParseFloat(typeText, 64); err == nil {
		return numeric, true, typeText
	}
	if isBigIntLiteralTypeString(typeText) {
		return typeText, true, typeText
	}

	return nil, false, ""
}

func isBigIntLiteralTypeString(typeText string) bool {
	if !strings.HasSuffix(typeText, "n") {
		return false
	}
	trimmed := typeText[:len(typeText)-1]
	if trimmed == "" {
		return false
	}
	if trimmed[0] == '-' || trimmed[0] == '+' {
		trimmed = trimmed[1:]
	}
	if trimmed == "" {
		return false
	}
	for _, ch := range trimmed {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func reportTypeLiteralComparison(ctx rule.RuleContext, node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return false
	}
	binExpr := node.AsBinaryExpression()
	if binExpr == nil || !isBooleanOperator(binExpr.OperatorToken.Kind) {
		return false
	}
	if ctx.TypeChecker == nil {
		return false
	}

	leftType := ctx.TypeChecker.GetTypeAtLocation(binExpr.Left)
	rightType := ctx.TypeChecker.GetTypeAtLocation(binExpr.Right)
	if leftType == nil || rightType == nil {
		return false
	}
	leftValue, leftOK, leftText := literalValueFromType(ctx.TypeChecker, leftType)
	rightValue, rightOK, rightText := literalValueFromType(ctx.TypeChecker, rightType)
	operatorToken, tokenOK := boolOperatorToken(binExpr.OperatorToken.Kind)
	if !tokenOK {
		return false
	}
	if !leftOK || !rightOK {
		leftFlags := checker.Type_flags(leftType)
		rightFlags := checker.Type_flags(rightType)
		if leftFlags&checker.TypeFlagsEnumLiteral != 0 && rightFlags&checker.TypeFlagsEnumLiteral != 0 {
			leftEnumText := ctx.TypeChecker.TypeToString(leftType)
			rightEnumText := ctx.TypeChecker.TypeToString(rightType)
			switch operatorToken {
			case "==", "===":
				ctx.ReportNode(node, buildComparisonBetweenLiteralTypesMessage(leftEnumText, operatorToken, rightEnumText, leftEnumText == rightEnumText))
				return true
			case "!=", "!==":
				ctx.ReportNode(node, buildComparisonBetweenLiteralTypesMessage(leftEnumText, operatorToken, rightEnumText, leftEnumText != rightEnumText))
				return true
			}
		}
		isEqualityOperator := operatorToken == "==" || operatorToken == "===" || operatorToken == "!=" || operatorToken == "!=="
		if isEqualityOperator {
			isNullLiteral := func(v any) bool {
				return v == nil
			}
			isUndefinedLiteral := func(v any) bool {
				return v == "undefined"
			}
			hasLooseEquality := operatorToken == "==" || operatorToken == "!="
			overlapsWithNullLiteral := func(comparedType *checker.Type) bool {
				if hasLooseEquality {
					return typeCanIncludeNull(comparedType, ctx.TypeChecker) || typeCanIncludeUndefined(comparedType, ctx.TypeChecker)
				}
				return typeCanIncludeNull(comparedType, ctx.TypeChecker)
			}
			overlapsWithUndefinedLiteral := func(comparedType *checker.Type) bool {
				if hasLooseEquality {
					return typeCanIncludeUndefined(comparedType, ctx.TypeChecker) || typeCanIncludeNull(comparedType, ctx.TypeChecker)
				}
				return typeCanIncludeUndefined(comparedType, ctx.TypeChecker)
			}

			if binExpr.Left.Kind == ast.KindIdentifier && rightOK && ((isNullLiteral(rightValue) && !overlapsWithNullLiteral(leftType)) || (isUndefinedLiteral(rightValue) && !overlapsWithUndefinedLiteral(leftType))) {
				ctx.ReportNode(node, buildNoOverlapBooleanExpressionMessage())
				return true
			}
			if binExpr.Right.Kind == ast.KindIdentifier && leftOK && ((isNullLiteral(leftValue) && !overlapsWithNullLiteral(rightType)) || (isUndefinedLiteral(leftValue) && !overlapsWithUndefinedLiteral(rightType))) {
				ctx.ReportNode(node, buildNoOverlapBooleanExpressionMessage())
				return true
			}
		}
		return false
	}
	result, ok := compareStaticValues(leftValue, operatorToken, rightValue)
	if !ok {
		return false
	}
	displayLeft := leftText
	displayRight := rightText
	if checker.Type_flags(leftType)&checker.TypeFlagsEnumLiteral != 0 {
		displayLeft = ctx.TypeChecker.TypeToString(leftType)
	}
	if checker.Type_flags(rightType)&checker.TypeFlagsEnumLiteral != 0 {
		displayRight = ctx.TypeChecker.TypeToString(rightType)
	}
	ctx.ReportNode(node, buildComparisonBetweenLiteralTypesMessage(displayLeft, operatorToken, displayRight, result))
	return true
}

func literalTruthiness(t *checker.Type, typeChecker *checker.Checker) (bool, bool) {
	if t == nil {
		return false, false
	}

	if literal := t.AsLiteralType(); literal != nil {
		switch literalValue := checker.LiteralType_value(literal).(type) {
		case bool:
			return true, literalValue
		case string:
			return true, literalValue != ""
		}
	}

	if typeChecker == nil {
		return false, false
	}

	typeString := typeChecker.TypeToString(t)
	flags := checker.Type_flags(t)

	if flags&checker.TypeFlagsBooleanLiteral != 0 {
		if typeString == "true" {
			return true, true
		}
		if typeString == "false" {
			return true, false
		}
	}

	if flags&checker.TypeFlagsStringLiteral != 0 {
		return true, typeString != `""` && typeString != `''`
	}

	if flags&checker.TypeFlagsNumberLiteral != 0 {
		normalized := strings.TrimSpace(typeString)
		return true, normalized != "0" && normalized != "-0" && normalized != "NaN"
	}

	if flags&checker.TypeFlagsBigIntLiteral != 0 {
		return true, strings.TrimSpace(typeString) != "0n"
	}

	return false, false
}

// isAlwaysTruthy checks if a type is always truthy (cannot be falsy)
func isAlwaysTruthy(t *checker.Type, typeChecker *checker.Checker) bool {
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
	// Type parameters may have constraints that determine truthiness.
	if flags&checker.TypeFlagsTypeParameter != 0 {
		if typeChecker != nil {
			if constraint := typeChecker.GetConstraintOfTypeParameter(t); constraint != nil && constraint != t {
				return isAlwaysTruthy(constraint, typeChecker)
			}
		}
		return false
	}
	if flags&(checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution) != 0 {
		return false
	}

	// If a non-union/intersection type cannot be falsy, it's always truthy.
	if !utils.IsUnionType(t) && !utils.IsIntersectionType(t) && flags&checker.TypeFlagsPossiblyFalsy == 0 {
		return true
	}

	// These types are always falsy or could be falsy
	if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
		return false
	}

	// Check for union types - all parts must be truthy
	if utils.IsUnionType(t) {
		for _, unionType := range t.Types() {
			if !isAlwaysTruthy(unionType, typeChecker) {
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
		if known, truthy := literalTruthiness(t, typeChecker); known {
			return truthy
		}
		return false
	}

	// Number literals could be 0, -0, or NaN (falsy values)
	if flags&checker.TypeFlagsNumberLiteral != 0 {
		if known, truthy := literalTruthiness(t, typeChecker); known {
			return truthy
		}
		return false
	}

	// String literals could be "" (falsy)
	if flags&checker.TypeFlagsStringLiteral != 0 {
		if known, truthy := literalTruthiness(t, typeChecker); known {
			return truthy
		}
		return false
	}

	// BigInt literals could be 0n (falsy)
	if flags&checker.TypeFlagsBigIntLiteral != 0 {
		if known, truthy := literalTruthiness(t, typeChecker); known {
			return truthy
		}
		return false
	}

	// Object types are always truthy
	if flags&(checker.TypeFlagsObject|checker.TypeFlagsNonPrimitive) != 0 {
		return true
	}

	return false
}

func isConditionalAlwaysNecessary(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil {
		return false
	}
	for _, part := range utils.UnionTypeParts(t) {
		if utils.IsTypeFlagSet(part, checker.TypeFlagsAny|checker.TypeFlagsUnknown) {
			return true
		}
		if utils.IsTypeFlagSet(part, checker.TypeFlagsTypeParameter) {
			if typeChecker != nil {
				if constraint := typeChecker.GetConstraintOfTypeParameter(part); constraint != nil && constraint != part {
					if isConditionalAlwaysNecessary(constraint, typeChecker) {
						return true
					}
					continue
				}
			}
			return true
		}
	}
	return false
}

// isAlwaysFalsy checks if a type is always falsy
func isAlwaysFalsy(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil {
		return false
	}

	flags := checker.Type_flags(t)

	// Null, undefined, and void are always falsy
	if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
		return true
	}
	// Type parameters may have constraints that determine truthiness.
	if flags&checker.TypeFlagsTypeParameter != 0 {
		if typeChecker != nil {
			if constraint := typeChecker.GetConstraintOfTypeParameter(t); constraint != nil && constraint != t {
				return isAlwaysFalsy(constraint, typeChecker)
			}
		}
		return false
	}
	if flags&(checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution) != 0 {
		return false
	}

	// Union types are always falsy only if all members are always falsy.
	if utils.IsUnionType(t) {
		for _, unionType := range t.Types() {
			if !isAlwaysFalsy(unionType, typeChecker) {
				return false
			}
		}
		return true
	}

	// Check for literal false
	if flags&checker.TypeFlagsBooleanLiteral != 0 {
		if known, truthy := literalTruthiness(t, typeChecker); known {
			return !truthy
		}
		return false
	}

	if flags&(checker.TypeFlagsStringLiteral|checker.TypeFlagsNumberLiteral|checker.TypeFlagsBigIntLiteral) != 0 {
		if known, truthy := literalTruthiness(t, typeChecker); known {
			return !truthy
		}
		return false
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
	if node.Kind == ast.KindPrefixUnaryExpression {
		prefix := node.AsPrefixUnaryExpression()
		if prefix != nil && prefix.Operator == ast.KindExclamationToken {
			checkCondition(ctx, prefix.Operand, !isNegated)
			return
		}
	}
	if node.Kind == ast.KindElementAccessExpression {
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
	if node.Kind == ast.KindBinaryExpression {
		binExpr := node.AsBinaryExpression()
		if binExpr != nil && (binExpr.OperatorToken.Kind == ast.KindAmpersandAmpersandToken || binExpr.OperatorToken.Kind == ast.KindBarBarToken) {
			return
		}
	}

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
	if isAlwaysTruthy(conditionType, ctx.TypeChecker) {
		if isNegated {
			ctx.ReportNode(node, buildAlwaysFalsyMessage())
		} else {
			ctx.ReportNode(node, buildAlwaysTruthyMessage())
		}
		return
	}

	// Check for always falsy
	if isAlwaysFalsy(conditionType, ctx.TypeChecker) {
		if isNegated {
			ctx.ReportNode(node, buildAlwaysTruthyMessage())
		} else {
			ctx.ReportNode(node, buildAlwaysFalsyMessage())
		}
		return
	}
}

func isConditionPosition(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	switch parent.Kind {
	case ast.KindIfStatement:
		stmt := parent.AsIfStatement()
		return stmt != nil && stmt.Expression == node
	case ast.KindWhileStatement:
		stmt := parent.AsWhileStatement()
		return stmt != nil && stmt.Expression == node
	case ast.KindDoStatement:
		stmt := parent.AsDoStatement()
		return stmt != nil && stmt.Expression == node
	case ast.KindForStatement:
		stmt := parent.AsForStatement()
		return stmt != nil && stmt.Condition == node
	case ast.KindConditionalExpression:
		expr := parent.AsConditionalExpression()
		return expr != nil && expr.Condition == node
	case ast.KindSwitchStatement:
		stmt := parent.AsSwitchStatement()
		return stmt != nil && stmt.Expression == node
	}
	return false
}

func isInConditionChain(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if isConditionPosition(node) {
		return true
	}
	parent := node.Parent
	if parent == nil || parent.Kind != ast.KindBinaryExpression {
		return false
	}
	parentBin := parent.AsBinaryExpression()
	if parentBin == nil {
		return false
	}
	if parentBin.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && parentBin.OperatorToken.Kind != ast.KindBarBarToken {
		return false
	}
	if parentBin.Left != node && parentBin.Right != node {
		return false
	}
	return isInConditionChain(parent)
}

func isAllowedConstantLoopCondition(ctx rule.RuleContext, node *ast.Node, mode string) bool {
	if mode == "never" {
		return false
	}
	if mode == "always" {
		_, ok := staticLiteralValue(ctx, node, 0)
		return ok
	}
	if mode == "only-allowed-literals" {
		value, ok := staticLiteralValue(ctx, node, 0)
		if !ok {
			return false
		}
		switch v := value.(type) {
		case bool:
			return true
		case float64:
			return v == 0 || v == 1
		case int:
			return v == 0 || v == 1
		case int32:
			return v == 0 || v == 1
		case int64:
			return v == 0 || v == 1
		}
	}
	return false
}

var arrayPredicateMethodNames = map[string]bool{
	"filter":        true,
	"find":          true,
	"findLast":      true,
	"findIndex":     true,
	"findLastIndex": true,
	"some":          true,
	"every":         true,
}

func isArrayLikeReceiver(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}

	isArrayOrIntersection := func(t *checker.Type) bool {
		if t == nil {
			return false
		}
		if utils.IsTypeFlagSet(t, checker.TypeFlagsIntersection) {
			parts := t.Types()
			if len(parts) == 0 {
				return false
			}
			for _, part := range parts {
				if !checker.Checker_isArrayOrTupleType(ctx.TypeChecker, part) {
					return false
				}
			}
			return true
		}
		return checker.Checker_isArrayOrTupleType(ctx.TypeChecker, t)
	}

	t := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
	parts := utils.UnionTypeParts(t)
	if len(parts) == 0 {
		parts = []*checker.Type{t}
	}
	hasArrayLike := false
	for _, part := range parts {
		if part == nil {
			continue
		}
		if utils.IsTypeFlagSet(part, checker.TypeFlagsNull|checker.TypeFlagsUndefined) {
			continue
		}
		if !isArrayOrIntersection(part) {
			return false
		}
		hasArrayLike = true
	}
	return hasArrayLike
}

func getCallMethodName(ctx rule.RuleContext, expr *ast.Node) (string, *ast.Node, bool) {
	if expr == nil {
		return "", nil, false
	}
	expr = ast.SkipParentheses(expr)
	switch expr.Kind {
	case ast.KindPropertyAccessExpression:
		access := expr.AsPropertyAccessExpression()
		if access == nil || access.Name() == nil {
			return "", nil, false
		}
		return access.Name().Text(), access.Expression, true
	case ast.KindElementAccessExpression:
		access := expr.AsElementAccessExpression()
		if access == nil || access.Expression == nil || access.ArgumentExpression == nil {
			return "", nil, false
		}
		value, ok := staticLiteralValue(ctx, access.ArgumentExpression, 0)
		if !ok {
			return "", nil, false
		}
		methodName, ok := value.(string)
		if !ok {
			return "", nil, false
		}
		return methodName, access.Expression, true
	}
	return "", nil, false
}

func collectReturnExpressionsSkippingNestedFunctions(node *ast.Node, skipNestedFunctions bool, out *[]*ast.Node) {
	if node == nil {
		return
	}
	if node.Kind == ast.KindReturnStatement {
		returnStatement := node.AsReturnStatement()
		if returnStatement != nil && returnStatement.Expression != nil {
			*out = append(*out, returnStatement.Expression)
		}
		return
	}
	if skipNestedFunctions && ast.IsFunctionLike(node) {
		return
	}
	node.ForEachChild(func(child *ast.Node) bool {
		collectReturnExpressionsSkippingNestedFunctions(child, true, out)
		return false
	})
}

func reportPredicateInlineCallbackReturnConditions(ctx rule.RuleContext, callback *ast.Node) bool {
	if callback == nil {
		return false
	}
	switch callback.Kind {
	case ast.KindArrowFunction:
		arrow := callback.AsArrowFunction()
		if arrow == nil || arrow.Body == nil {
			return false
		}
		bodyNode := arrow.Body.AsNode()
		if bodyNode == nil {
			return false
		}
		if bodyNode.Kind != ast.KindBlock {
			checkCondition(ctx, bodyNode, false)
			return true
		}
		returnExprs := []*ast.Node{}
		collectReturnExpressionsSkippingNestedFunctions(bodyNode, false, &returnExprs)
		for _, expr := range returnExprs {
			checkCondition(ctx, expr, false)
		}
		return true
	case ast.KindFunctionExpression:
		functionExpression := callback.AsFunctionExpression()
		if functionExpression == nil || functionExpression.Body == nil {
			return false
		}
		returnExprs := []*ast.Node{}
		collectReturnExpressionsSkippingNestedFunctions(functionExpression.Body.AsNode(), false, &returnExprs)
		for _, expr := range returnExprs {
			checkCondition(ctx, expr, false)
		}
		return true
	}
	return false
}

func callbackFunctionReturnTruthiness(ctx rule.RuleContext, callback *ast.Node) (bool, bool) {
	if callback == nil || ctx.TypeChecker == nil {
		return false, false
	}
	callbackType := ctx.TypeChecker.GetTypeAtLocation(callback)
	if callbackType == nil {
		return false, false
	}
	signatures := utils.GetCallSignatures(ctx.TypeChecker, callbackType)
	if len(signatures) == 0 {
		return false, false
	}

	allTruthy := true
	allFalsy := true
	anyReturnType := false

	for _, signature := range signatures {
		if signature == nil {
			continue
		}
		returnType := checker.Checker_getReturnTypeOfSignature(ctx.TypeChecker, signature)
		if returnType == nil {
			continue
		}
		anyReturnType = true
		returnsTruthy := isAlwaysTruthy(returnType, ctx.TypeChecker)
		returnsFalsy := isAlwaysFalsy(returnType, ctx.TypeChecker)
		if !returnsTruthy {
			allTruthy = false
		}
		if !returnsFalsy {
			allFalsy = false
		}
	}

	if !anyReturnType {
		return false, false
	}
	if allTruthy && !allFalsy {
		return true, true
	}
	if allFalsy && !allTruthy {
		return true, false
	}
	return false, false
}

func checkArrayPredicateCallback(ctx rule.RuleContext, node *ast.Node) {
	call := node.AsCallExpression()
	if call == nil || call.Expression == nil || call.Arguments == nil || len(call.Arguments.Nodes) == 0 {
		return
	}
	methodName, receiver, ok := getCallMethodName(ctx, call.Expression)
	if !ok || !arrayPredicateMethodNames[methodName] || !isArrayLikeReceiver(ctx, receiver) {
		return
	}

	callback := call.Arguments.Nodes[0]
	if callback == nil {
		return
	}

	if reportPredicateInlineCallbackReturnConditions(ctx, callback) {
		return
	}

	if known, truthy := callbackFunctionReturnTruthiness(ctx, callback); known {
		if truthy {
			ctx.ReportNode(callback, buildAlwaysTruthyFuncMessage())
		} else {
			ctx.ReportNode(callback, buildAlwaysFalsyFuncMessage())
		}
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

func normalizeConstantValue(value any) (any, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		return v, true
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return nil, false
}

func staticLiteralValue(ctx rule.RuleContext, node *ast.Node, depth int) (any, bool) {
	if node == nil || depth > 3 {
		return nil, false
	}
	if ctx.TypeChecker != nil {
		if constValue := ctx.TypeChecker.GetConstantValue(node); constValue != nil {
			if normalized, ok := normalizeConstantValue(constValue); ok {
				return normalized, true
			}
		}
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

func toLooseNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, true
		}
		if trimmed == "undefined" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

func compareStrictStaticValues(left any, right any) (bool, bool) {
	switch l := left.(type) {
	case bool:
		r, ok := right.(bool)
		if !ok {
			return false, true
		}
		return l == r, true
	case float64:
		r, ok := right.(float64)
		if !ok {
			return false, true
		}
		return l == r, true
	case string:
		r, ok := right.(string)
		if !ok {
			return false, true
		}
		return l == r, true
	case nil:
		return right == nil, true
	}
	return false, false
}

func compareLooseStaticValues(left any, right any) (bool, bool) {
	if strictResult, strictKnown := compareStrictStaticValues(left, right); strictKnown && strictResult {
		return true, true
	}

	if left == nil {
		return right == nil, true
	}
	if right == nil {
		return false, true
	}

	if leftNumber, leftOK := toLooseNumber(left); leftOK {
		if rightNumber, rightOK := toLooseNumber(right); rightOK {
			return leftNumber == rightNumber, true
		}
	}

	if leftString, ok := left.(string); ok {
		if rightString, ok := right.(string); ok {
			return leftString == rightString, true
		}
	}

	return false, true
}

func compareStaticValues(left any, operator string, right any) (bool, bool) {
	switch operator {
	case "===":
		return compareStrictStaticValues(left, right)
	case "==":
		return compareLooseStaticValues(left, right)
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
		if leftString, ok := left.(string); ok {
			rightString, ok := right.(string)
			if !ok {
				return false, false
			}
			switch operator {
			case "<":
				return leftString < rightString, true
			case "<=":
				return leftString <= rightString, true
			case ">":
				return leftString > rightString, true
			case ">=":
				return leftString >= rightString, true
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
					if isAllowedConstantLoopCondition(ctx, whileStmt.Expression, *opts.AllowConstantLoopConditions) {
						return
					}
					checkCondition(ctx, whileStmt.Expression, false)
				}
			},

			// For loop conditions
			ast.KindForStatement: func(node *ast.Node) {
				forStmt := node.AsForStatement()
				if forStmt != nil && forStmt.Condition != nil {
					if isAllowedConstantLoopCondition(ctx, forStmt.Condition, *opts.AllowConstantLoopConditions) {
						return
					}
					checkCondition(ctx, forStmt.Condition, false)
				}
			},

			// Do-while loop conditions
			ast.KindDoStatement: func(node *ast.Node) {
				doStmt := node.AsDoStatement()
				if doStmt != nil && doStmt.Expression != nil {
					if isAllowedConstantLoopCondition(ctx, doStmt.Expression, *opts.AllowConstantLoopConditions) {
						return
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
						if isInConditionChain(node) {
							checkCondition(ctx, binExpr.Right, false)
						}
						return
					}

					// Handle nullish coalescing operator (??)
					if binExpr.OperatorToken.Kind == ast.KindQuestionQuestionToken {
						leftType := ctx.TypeChecker.GetTypeAtLocation(binExpr.Left)
						if leftType != nil {
							if ast.IsOptionalChain(binExpr.Left) {
								return
							}
							if binExpr.Left.Kind == ast.KindElementAccessExpression {
								elementAccess := binExpr.Left.AsElementAccessExpression()
								if elementAccess != nil && elementAccess.ArgumentExpression != nil {
									argumentKind := elementAccess.ArgumentExpression.Kind
									if argumentKind != ast.KindNumericLiteral && argumentKind != ast.KindStringLiteral {
										return
									}
								}
							}
							if isConditionalAlwaysNecessary(leftType, ctx.TypeChecker) {
								return
							}
							if isNeverType(leftType) {
								ctx.ReportNode(binExpr.Left, buildNeverMessage())
								return
							}
							// Check if left side can never be nullish (null or undefined)
							if isTypeNeverNullish(leftType, ctx.TypeChecker) {
								ctx.ReportNode(binExpr.Left, buildNeverNullishMessage())
							}
							// Check if left side is always nullish
							if isAlwaysFalsy(leftType, ctx.TypeChecker) && isPossiblyNullish(leftType, ctx.TypeChecker) {
								ctx.ReportNode(binExpr.Left, buildAlwaysNullishMessage())
							}
						}
						return
					}
					if reportStaticLiteralComparison(ctx, node) {
						return
					}
					if reportTypeLiteralComparison(ctx, node) {
						return
					}
				}
			},
			ast.KindCallExpression: func(node *ast.Node) {
				checkArrayPredicateCallback(ctx, node)
			},
			ast.KindCaseClause: func(node *ast.Node) {
				if node == nil || node.Expression() == nil || node.Parent == nil || node.Parent.Parent == nil || node.Parent.Parent.Expression() == nil {
					return
				}
				leftValue, leftOK := staticLiteralValue(ctx, node.Parent.Parent.Expression(), 0)
				rightValue, rightOK := staticLiteralValue(ctx, node.Expression(), 0)
				if !leftOK || !rightOK {
					return
				}
				if result, ok := compareStaticValues(leftValue, "===", rightValue); ok {
					leftText := trimNodeText(ctx.SourceFile, node.Parent.Parent.Expression())
					rightText := trimNodeText(ctx.SourceFile, node.Expression())
					ctx.ReportNode(node.Expression(), buildComparisonBetweenLiteralTypesMessage(leftText, "===", rightText, result))
				}
			},
		}
	},
})
