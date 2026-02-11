package strict_boolean_expressions

import (
	"strconv"
	"strings"

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
		"noStrictNullCheck":             "This rule requires the `strictNullChecks` compiler option to be turned on to function correctly.",
		"predicateCannotBeAsync":        "Predicate function should not be async.",
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
	AllowAny                     bool
	AllowNullableBoolean         bool
	AllowNullableEnum            bool
	AllowNullableNumber          bool
	AllowNullableObject          bool
	AllowNullableString          bool
	AllowNumber                  bool
	AllowString                  bool
	AllowWithoutStrictNullChecks bool
	AllowNullableNumberSet       bool
	AllowNullableObjectSet       bool
	AllowNullableStringSet       bool
	AllowNumberSet               bool
	AllowStringSet               bool
}

func defaultStrictBooleanExpressionsOptions() strictBooleanExpressionsOptions {
	return strictBooleanExpressionsOptions{
		AllowAny:                     false,
		AllowNullableBoolean:         false,
		AllowNullableEnum:            false,
		AllowNullableNumber:          false,
		AllowNullableObject:          true,
		AllowNullableString:          false,
		AllowNumber:                  true,
		AllowString:                  true,
		AllowWithoutStrictNullChecks: false,
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
	if raw, exists := values["allowNullableNumber"]; exists {
		if allowNullableNumber, ok := raw.(bool); ok {
			opts.AllowNullableNumber = allowNullableNumber
		}
		opts.AllowNullableNumberSet = true
	}
	if raw, exists := values["allowNullableObject"]; exists {
		if allowNullableObject, ok := raw.(bool); ok {
			opts.AllowNullableObject = allowNullableObject
		}
		opts.AllowNullableObjectSet = true
	}
	if raw, exists := values["allowNullableString"]; exists {
		if allowNullableString, ok := raw.(bool); ok {
			opts.AllowNullableString = allowNullableString
		}
		opts.AllowNullableStringSet = true
	}
	if raw, exists := values["allowNumber"]; exists {
		if allowNumber, ok := raw.(bool); ok {
			opts.AllowNumber = allowNumber
		}
		opts.AllowNumberSet = true
	}
	if raw, exists := values["allowString"]; exists {
		if allowString, ok := raw.(bool); ok {
			opts.AllowString = allowString
		}
		opts.AllowStringSet = true
	}
	if allowWithoutStrictNullChecks, ok := values["allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing"].(bool); ok {
		opts.AllowWithoutStrictNullChecks = allowWithoutStrictNullChecks
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
	nonNullishPrimitiveSeen := false
	allNonNullishPrimitivesDefinitelyTruthy := true
	hasOnlyLiteralNonNullishPrimitives := true

	for _, part := range parts {
		if part == nil {
			continue
		}
		flags := checker.Type_flags(part)
		if flags&checker.TypeFlagsNever != 0 {
			continue
		}
		hasNonNeverValue = true
		if flags&checker.TypeFlagsIntersection != 0 {
			intersectionParts := part.Types()
			if len(intersectionParts) == 0 {
				continue
			}
			for _, intersectionPart := range intersectionParts {
				if intersectionPart == nil {
					continue
				}
				intersectionFlags := checker.Type_flags(intersectionPart)
				if intersectionFlags&checker.TypeFlagsNever != 0 {
					continue
				}
				if intersectionFlags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
					hasNullish = true
					continue
				}
				if intersectionFlags&(checker.TypeFlagsBooleanLike|checker.TypeFlagsStringLike|checker.TypeFlagsNumberLike|checker.TypeFlagsBigIntLike|checker.TypeFlagsEnumLike) != 0 {
					nonNullishPrimitiveSeen = true
					if !utils.IsTypeFlagSet(intersectionPart, checker.TypeFlagsStringLiteral|checker.TypeFlagsNumberLiteral|checker.TypeFlagsBigIntLiteral|checker.TypeFlagsBooleanLiteral|checker.TypeFlagsEnumLiteral) {
						hasOnlyLiteralNonNullishPrimitives = false
					}
					if utils.IsTypeFlagSet(intersectionPart, checker.TypeFlagsPossiblyFalsy) {
						allNonNullishPrimitivesDefinitelyTruthy = false
					}
				} else {
					allNonNullishPrimitivesDefinitelyTruthy = false
					hasOnlyLiteralNonNullishPrimitives = false
				}
				if intersectionFlags&checker.TypeFlagsAny != 0 {
					hasAny = true
					continue
				}
				if intersectionFlags&(checker.TypeFlagsTypeParameter|checker.TypeFlagsTypeVariable|checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution|checker.TypeFlagsInstantiable|checker.TypeFlagsInstantiableNonPrimitive|checker.TypeFlagsInstantiablePrimitive) != 0 {
					hasAny = true
					continue
				}
				if intersectionFlags&checker.TypeFlagsEnumLike != 0 {
					hasEnum = true
					continue
				}
				if intersectionFlags&checker.TypeFlagsBooleanLike != 0 {
					hasBoolean = true
					continue
				}
				if intersectionFlags&(checker.TypeFlagsNumberLike|checker.TypeFlagsBigIntLike) != 0 {
					hasNumber = true
					continue
				}
				if intersectionFlags&checker.TypeFlagsStringLike != 0 {
					hasString = true
					continue
				}
				if intersectionFlags&checker.TypeFlagsESSymbolLike != 0 {
					hasObject = true
					continue
				}
				if intersectionFlags&(checker.TypeFlagsObject|checker.TypeFlagsNonPrimitive) != 0 {
					continue
				}
				hasOther = true
			}
			continue
		}
		if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid) != 0 {
			hasNullish = true
			continue
		}
		if flags&(checker.TypeFlagsBooleanLike|checker.TypeFlagsStringLike|checker.TypeFlagsNumberLike|checker.TypeFlagsBigIntLike|checker.TypeFlagsEnumLike) != 0 {
			nonNullishPrimitiveSeen = true
			if !utils.IsTypeFlagSet(part, checker.TypeFlagsStringLiteral|checker.TypeFlagsNumberLiteral|checker.TypeFlagsBigIntLiteral|checker.TypeFlagsBooleanLiteral|checker.TypeFlagsEnumLiteral) {
				hasOnlyLiteralNonNullishPrimitives = false
			}
			if utils.IsTypeFlagSet(part, checker.TypeFlagsPossiblyFalsy) {
				allNonNullishPrimitivesDefinitelyTruthy = false
			}
		} else {
			allNonNullishPrimitivesDefinitelyTruthy = false
			hasOnlyLiteralNonNullishPrimitives = false
		}
		if flags&checker.TypeFlagsAny != 0 {
			hasAny = true
			continue
		}
		if flags&(checker.TypeFlagsTypeParameter|checker.TypeFlagsTypeVariable|checker.TypeFlagsIndexedAccess|checker.TypeFlagsIndex|checker.TypeFlagsConditional|checker.TypeFlagsSubstitution|checker.TypeFlagsInstantiable|checker.TypeFlagsInstantiableNonPrimitive|checker.TypeFlagsInstantiablePrimitive) != 0 {
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
		if flags&checker.TypeFlagsESSymbolLike != 0 {
			hasObject = true
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
	nonNullishCategoryCount := 0
	if hasBoolean {
		nonNullishCategoryCount++
	}
	if hasNumber || hasEnum {
		nonNullishCategoryCount++
	}
	if hasString {
		nonNullishCategoryCount++
	}
	if hasObject {
		nonNullishCategoryCount++
	}
	if nonNullishCategoryCount > 1 {
		return "conditionErrorOther"
	}
	if hasNullish && nonNullishPrimitiveSeen && hasOnlyLiteralNonNullishPrimitives && allNonNullishPrimitivesDefinitelyTruthy {
		return ""
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

func getCallMethodName(callExpression *ast.Node) (string, *ast.Node, bool) {
	if callExpression == nil {
		return "", nil, false
	}

	callExpression = ast.SkipParentheses(callExpression)
	switch callExpression.Kind {
	case ast.KindPropertyAccessExpression:
		access := callExpression.AsPropertyAccessExpression()
		if access == nil || access.Name() == nil {
			return "", nil, false
		}
		return access.Name().Text(), access.Expression, true
	case ast.KindElementAccessExpression:
		access := callExpression.AsElementAccessExpression()
		if access == nil || access.Expression == nil || access.ArgumentExpression == nil {
			return "", nil, false
		}
		argument := ast.SkipParentheses(access.ArgumentExpression)
		if argument == nil || argument.Kind != ast.KindStringLiteral {
			return "", nil, false
		}
		return argument.AsStringLiteral().Text, access.Expression, true
	}

	return "", nil, false
}

func checkCallbackFunctionReturnType(ctx rule.RuleContext, callback *ast.Node, opts strictBooleanExpressionsOptions) {
	if callback == nil || ctx.TypeChecker == nil {
		return
	}

	callbackType := ctx.TypeChecker.GetTypeAtLocation(callback)
	if callbackType == nil {
		return
	}
	signatures := utils.GetCallSignatures(ctx.TypeChecker, callbackType)
	if len(signatures) == 0 {
		signatures = nil
	}

	seenAllowed := false
	reportMessageID := ""

	for _, signature := range signatures {
		if signature == nil {
			continue
		}
		returnType := checker.Checker_getReturnTypeOfSignature(ctx.TypeChecker, signature)
		effectiveReturnType := returnType
		if effectiveReturnType != nil {
			if baseConstraint := checker.Checker_getBaseConstraintOfType(ctx.TypeChecker, effectiveReturnType); baseConstraint != nil {
				effectiveReturnType = baseConstraint
			}
		}
		messageID := conditionErrorMessageID(effectiveReturnType, opts)
		if messageID == "" {
			seenAllowed = true
			continue
		}
		if reportMessageID == "" {
			reportMessageID = messageID
			continue
		}
		if reportMessageID != messageID {
			reportMessageID = "conditionErrorOther"
		}
	}

	if callback != nil && callback.Kind == ast.KindIdentifier {
		symbol := ctx.TypeChecker.GetSymbolAtLocation(callback)
		if symbol != nil {
			for _, declaration := range symbol.Declarations {
				if declaration == nil || !ast.IsFunctionLike(declaration) {
					continue
				}
				returnTypeNode := declaration.Type()
				if returnTypeNode == nil {
					continue
				}
				returnType := ctx.TypeChecker.GetTypeAtLocation(returnTypeNode)
				if returnType == nil {
					continue
				}
				if baseConstraint := checker.Checker_getBaseConstraintOfType(ctx.TypeChecker, returnType); baseConstraint != nil {
					returnType = baseConstraint
				}
				messageID := conditionErrorMessageID(returnType, opts)
				if messageID == "" {
					seenAllowed = true
					continue
				}
				if reportMessageID == "" {
					reportMessageID = messageID
					continue
				}
				if reportMessageID != messageID {
					reportMessageID = "conditionErrorOther"
				}
			}
		}
	}

	if reportMessageID == "" {
		return
	}
	if seenAllowed {
		reportMessageID = "conditionErrorOther"
	}
	ctx.ReportNode(callback, buildConditionErrorMessage(reportMessageID))
}

func typeParameterNameFromTypeNode(typeNode *ast.Node) (string, bool) {
	if typeNode == nil {
		return "", false
	}
	typeNode = ast.SkipParentheses(typeNode)
	if typeNode == nil {
		return "", false
	}
	switch typeNode.Kind {
	case ast.KindIdentifier:
		identifier := typeNode.AsIdentifier()
		if identifier == nil || identifier.Text == "" {
			return "", false
		}
		return identifier.Text, true
	case ast.KindTypeReference:
		typeReference := typeNode.AsTypeReferenceNode()
		if typeReference == nil || typeReference.TypeName == nil || typeReference.TypeName.Kind != ast.KindIdentifier {
			return "", false
		}
		if typeReference.TypeArguments != nil && len(typeReference.TypeArguments.Nodes) > 0 {
			return "", false
		}
		return typeReference.TypeName.AsIdentifier().Text, true
	default:
		return "", false
	}
}

func genericTypeParameterConstraintForIdentifier(ctx rule.RuleContext, node *ast.Node) (*checker.Type, bool) {
	if ctx.TypeChecker == nil || node == nil || node.Kind != ast.KindIdentifier {
		return nil, false
	}

	symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
	if symbol == nil {
		return nil, false
	}

	for _, declaration := range symbol.Declarations {
		if declaration == nil || declaration.Kind != ast.KindParameter {
			continue
		}
		parameter := declaration.AsParameterDeclaration()
		if parameter == nil || parameter.Type == nil {
			continue
		}

		typeParameterName, ok := typeParameterNameFromTypeNode(parameter.Type)
		if !ok {
			continue
		}

		for parent := declaration.Parent; parent != nil; parent = parent.Parent {
			typeParameters := parent.TypeParameters()
			if len(typeParameters) == 0 {
				continue
			}
			for _, typeParameterNode := range typeParameters {
				if typeParameterNode == nil || typeParameterNode.Kind != ast.KindTypeParameter {
					continue
				}
				typeParameter := typeParameterNode.AsTypeParameter()
				if typeParameter == nil || typeParameter.Name() == nil {
					continue
				}
				if typeParameter.Name().Text() != typeParameterName {
					continue
				}
				if typeParameter.Constraint == nil {
					return nil, true
				}
				return ctx.TypeChecker.GetTypeAtLocation(typeParameter.Constraint), true
			}
		}
	}

	return nil, false
}

func declarationTypeNode(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindParameter:
		parameter := node.AsParameterDeclaration()
		if parameter == nil {
			return nil
		}
		return parameter.Type
	case ast.KindVariableDeclaration:
		declaration := node.AsVariableDeclaration()
		if declaration == nil {
			return nil
		}
		return declaration.Type
	case ast.KindPropertyDeclaration:
		declaration := node.AsPropertyDeclaration()
		if declaration == nil {
			return nil
		}
		return declaration.Type
	case ast.KindPropertySignature:
		signature := node.AsPropertySignatureDeclaration()
		if signature == nil {
			return nil
		}
		return signature.Type
	}
	return nil
}

func isNullishTypeNode(typeNode *ast.Node) bool {
	if typeNode == nil {
		return false
	}
	typeNode = ast.SkipParentheses(typeNode)
	if typeNode == nil {
		return false
	}
	if typeNode.Kind == ast.KindLiteralType {
		literalType := typeNode.AsLiteralTypeNode()
		if literalType == nil {
			return false
		}
		return isNullishTypeNode(literalType.Literal)
	}
	switch typeNode.Kind {
	case ast.KindNullKeyword, ast.KindUndefinedKeyword, ast.KindVoidKeyword:
		return true
	default:
		return false
	}
}

func literalTypeNodeTruthiness(typeNode *ast.Node) (bool, bool) {
	if typeNode == nil {
		return false, false
	}
	typeNode = ast.SkipParentheses(typeNode)
	if typeNode == nil {
		return false, false
	}
	if typeNode.Kind == ast.KindLiteralType {
		literalType := typeNode.AsLiteralTypeNode()
		if literalType == nil {
			return false, false
		}
		return literalTypeNodeTruthiness(literalType.Literal)
	}
	switch typeNode.Kind {
	case ast.KindTrueKeyword:
		return true, true
	case ast.KindFalseKeyword:
		return true, false
	case ast.KindStringLiteral:
		stringLiteral := typeNode.AsStringLiteral()
		if stringLiteral == nil {
			return false, false
		}
		return true, stringLiteral.Text != ""
	case ast.KindNoSubstitutionTemplateLiteral:
		templateLiteral := typeNode.AsNoSubstitutionTemplateLiteral()
		if templateLiteral == nil {
			return false, false
		}
		return true, templateLiteral.Text != ""
	case ast.KindNumericLiteral:
		value, err := strconv.ParseFloat(typeNode.Text(), 64)
		if err != nil {
			return false, false
		}
		return true, value != 0
	case ast.KindBigIntLiteral:
		text := strings.TrimSpace(typeNode.Text())
		return true, text != "0n"
	case ast.KindPrefixUnaryExpression:
		unary := typeNode.AsPrefixUnaryExpression()
		if unary == nil || unary.Operand == nil {
			return false, false
		}
		if unary.Operator == ast.KindMinusToken || unary.Operator == ast.KindPlusToken {
			if unary.Operand.Kind == ast.KindNumericLiteral {
				value, err := strconv.ParseFloat(unary.Operand.Text(), 64)
				if err != nil {
					return false, false
				}
				if unary.Operator == ast.KindMinusToken {
					value = -value
				}
				return true, value != 0
			}
			if unary.Operand.Kind == ast.KindBigIntLiteral {
				text := strings.TrimSpace(unary.Operand.Text())
				if unary.Operator == ast.KindMinusToken {
					return true, text != "0n"
				}
				return true, text != "0n"
			}
		}
	}
	return false, false
}

func isDefinitelyTruthyNullableLiteralUnionType(typeNode *ast.Node) bool {
	if typeNode == nil {
		return false
	}
	typeNode = ast.SkipParentheses(typeNode)
	if typeNode == nil || typeNode.Kind != ast.KindUnionType {
		return false
	}

	union := typeNode.AsUnionTypeNode()
	if union == nil || union.Types == nil {
		return false
	}

	hasNullish := false
	hasTruthyLiteral := false
	for _, part := range union.Types.Nodes {
		if isNullishTypeNode(part) {
			hasNullish = true
			continue
		}
		known, truthy := literalTypeNodeTruthiness(part)
		if !known || !truthy {
			return false
		}
		hasTruthyLiteral = true
	}

	return hasNullish && hasTruthyLiteral
}

func isDefinitelyTruthyLiteralTypeNode(typeNode *ast.Node) bool {
	known, truthy := literalTypeNodeTruthiness(typeNode)
	return known && truthy
}

func symbolHasTruthyNullableLiteralUnionDeclaration(symbol *ast.Symbol) bool {
	if symbol == nil {
		return false
	}
	for _, declaration := range symbol.Declarations {
		typeNode := declarationTypeNode(declaration)
		if isDefinitelyTruthyNullableLiteralUnionType(typeNode) {
			return true
		}
		if declaration != nil && declaration.QuestionToken() != nil && isDefinitelyTruthyLiteralTypeNode(typeNode) {
			return true
		}
	}
	return false
}

func expressionHasTruthyNullableLiteralUnionType(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}
	node = ast.SkipParentheses(node)
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindIdentifier:
		symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
		return symbolHasTruthyNullableLiteralUnionDeclaration(symbol)
	case ast.KindPropertyAccessExpression:
		access := node.AsPropertyAccessExpression()
		if access == nil || access.Name() == nil {
			return false
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(access.Name())
		return symbolHasTruthyNullableLiteralUnionDeclaration(symbol)
	case ast.KindElementAccessExpression:
		access := node.AsElementAccessExpression()
		if access == nil || access.ArgumentExpression == nil {
			return false
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(access.ArgumentExpression)
		return symbolHasTruthyNullableLiteralUnionDeclaration(symbol)
	}
	return false
}

func trimNodeTextInOwnSource(node *ast.Node) string {
	if node == nil {
		return ""
	}
	sourceFile := ast.GetSourceFileOfNode(node)
	if sourceFile == nil {
		return strings.TrimSpace(node.Text())
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	sourceText := sourceFile.Text()
	if trimmed.Pos() < 0 || trimmed.End() > len(sourceText) || trimmed.Pos() >= trimmed.End() {
		return strings.TrimSpace(node.Text())
	}
	return strings.TrimSpace(sourceText[trimmed.Pos():trimmed.End()])
}

func assertionPredicateArgumentIndex(signature *checker.Signature) (int, bool) {
	if signature == nil {
		return 0, false
	}
	declaration := checker.Signature_declaration(signature)
	if declaration == nil || declaration.Type() == nil {
		return 0, false
	}
	typeText := trimNodeTextInOwnSource(declaration.Type())
	if !strings.HasPrefix(typeText, "asserts ") {
		return 0, false
	}
	remainder := strings.TrimSpace(strings.TrimPrefix(typeText, "asserts "))
	if remainder == "" {
		return 0, false
	}
	if strings.Contains(remainder, " is ") {
		return 0, false
	}
	parameterName := remainder
	if parameterName == "" || parameterName == "this" {
		return 0, false
	}

	parameters := checker.Signature_parameters(signature)
	for index, parameter := range parameters {
		if parameter != nil && parameter.Name == parameterName {
			return index, true
		}
	}
	return 0, false
}

func checkAssertionPredicateCall(ctx rule.RuleContext, node *ast.Node, opts strictBooleanExpressionsOptions) {
	if ctx.TypeChecker == nil || node == nil {
		return
	}
	call := node.AsCallExpression()
	if call == nil || call.Arguments == nil || len(call.Arguments.Nodes) == 0 {
		return
	}
	for _, argument := range call.Arguments.Nodes {
		if argument != nil && argument.Kind == ast.KindSpreadElement {
			return
		}
	}

	signature := checker.Checker_getResolvedSignature(ctx.TypeChecker, node, nil, checker.CheckModeNormal)
	if signature == nil {
		return
	}
	argumentIndex, ok := assertionPredicateArgumentIndex(signature)
	if !ok || argumentIndex < 0 || argumentIndex >= len(call.Arguments.Nodes) {
		return
	}

	checkCondition(ctx, call.Arguments.Nodes[argumentIndex], opts)
}

func checkArrayPredicateCallback(ctx rule.RuleContext, node *ast.Node, opts strictBooleanExpressionsOptions) {
	call := node.AsCallExpression()
	if call == nil || call.Expression == nil || call.Arguments == nil || len(call.Arguments.Nodes) == 0 {
		return
	}

	methodName, receiver, ok := getCallMethodName(call.Expression)
	if !ok || !arrayPredicateMethodNames[methodName] || !isArrayLikeReceiver(ctx, receiver) {
		return
	}

	callback := ast.SkipParentheses(call.Arguments.Nodes[0])
	if callback == nil {
		return
	}
	predicateOpts := opts
	if !opts.AllowStringSet {
		predicateOpts.AllowString = false
	}
	if !opts.AllowNullableStringSet {
		predicateOpts.AllowNullableString = false
	}
	if !opts.AllowNullableObjectSet {
		predicateOpts.AllowNullableObject = false
	}
	if ast.HasSyntacticModifier(callback, ast.ModifierFlagsAsync) {
		ctx.ReportNode(callback, buildConditionErrorMessage("predicateCannotBeAsync"))
		return
	}

	switch callback.Kind {
	case ast.KindArrowFunction:
		arrow := callback.AsArrowFunction()
		if arrow == nil || arrow.Body == nil {
			return
		}
		bodyNode := arrow.Body.AsNode()
		if bodyNode == nil {
			return
		}
		if bodyNode.Kind != ast.KindBlock {
			checkCallbackFunctionReturnType(ctx, callback, predicateOpts)
			return
		}
		checkCallbackFunctionReturnType(ctx, callback, predicateOpts)
		return
	case ast.KindFunctionExpression:
		functionExpression := callback.AsFunctionExpression()
		if functionExpression == nil || functionExpression.Body == nil {
			return
		}
		checkCallbackFunctionReturnType(ctx, callback, predicateOpts)
		return
	}

	checkCallbackFunctionReturnType(ctx, callback, predicateOpts)
}

func isArrayPredicateCallbackNode(ctx rule.RuleContext, node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Kind != ast.KindCallExpression {
		return false
	}
	call := node.Parent.AsCallExpression()
	if call == nil || call.Expression == nil || call.Arguments == nil || len(call.Arguments.Nodes) == 0 {
		return false
	}
	if call.Arguments.Nodes[0] != node {
		return false
	}
	methodName, receiver, ok := getCallMethodName(call.Expression)
	if !ok || !arrayPredicateMethodNames[methodName] {
		return false
	}
	return isArrayLikeReceiver(ctx, receiver)
}

func isWithinArrayPredicateCallback(ctx rule.RuleContext, node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		if !ast.IsFunctionLike(current) {
			continue
		}
		return isArrayPredicateCallbackNode(ctx, current)
	}
	return false
}

func collectLogicalOperands(node *ast.Node, out *[]*ast.Node) {
	node = ast.SkipParentheses(node)
	if node == nil {
		return
	}
	if node.Kind != ast.KindBinaryExpression {
		*out = append(*out, node)
		return
	}
	binary := node.AsBinaryExpression()
	if binary == nil || (binary.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && binary.OperatorToken.Kind != ast.KindBarBarToken) {
		*out = append(*out, node)
		return
	}
	collectLogicalOperands(binary.Left, out)
	collectLogicalOperands(binary.Right, out)
}

func checkControlFlowLogicalExpression(ctx rule.RuleContext, expression *ast.Node, opts strictBooleanExpressionsOptions) {
	operands := []*ast.Node{}
	collectLogicalOperands(expression, &operands)
	if len(operands) < 2 {
		return
	}
	for _, operand := range operands[:len(operands)-1] {
		checkCondition(ctx, operand, opts)
	}
}

func isDirectConditionalContext(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	switch parent.Kind {
	case ast.KindIfStatement:
		statement := parent.AsIfStatement()
		return statement != nil && statement.Expression == node
	case ast.KindWhileStatement:
		statement := parent.AsWhileStatement()
		return statement != nil && statement.Expression == node
	case ast.KindDoStatement:
		statement := parent.AsDoStatement()
		return statement != nil && statement.Expression == node
	case ast.KindForStatement:
		statement := parent.AsForStatement()
		return statement != nil && statement.Condition == node
	case ast.KindConditionalExpression:
		expression := parent.AsConditionalExpression()
		return expression != nil && expression.Condition == node
	default:
		return false
	}
}

func checkCondition(ctx rule.RuleContext, cond *ast.Node, opts strictBooleanExpressionsOptions) {
	if cond == nil {
		return
	}
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
	if (messageId == "conditionErrorNullableString" || messageId == "conditionErrorNullableNumber" || messageId == "conditionErrorNullableBoolean" || messageId == "conditionErrorNullableEnum") && expressionHasTruthyNullableLiteralUnionType(ctx, cond) {
		return
	}
	if messageId == "conditionErrorOther" {
		if constraintType, found := genericTypeParameterConstraintForIdentifier(ctx, cond); found {
			if constraintType == nil {
				if opts.AllowAny {
					return
				}
				ctx.ReportNode(cond, buildConditionErrorMessage("conditionErrorAny"))
				return
			}
			constraintMessageId := conditionErrorMessageID(constraintType, opts)
			if constraintMessageId == "" {
				return
			}
			ctx.ReportNode(cond, buildConditionErrorMessage(constraintMessageId))
			return
		}
	}
	if messageId == "" {
		return
	}
	ctx.ReportNode(cond, buildConditionErrorMessage(messageId))
}

var StrictBooleanExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "strict-boolean-expressions",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseStrictBooleanExpressionsOptions(options)
		if ctx.Program != nil && !opts.AllowWithoutStrictNullChecks {
			compilerOptions := ctx.Program.Options()
			isStrictNullChecks := utils.IsStrictCompilerOptionEnabled(
				compilerOptions,
				compilerOptions.StrictNullChecks,
			)
			if !isStrictNullChecks {
				ctx.ReportNode(&ast.Node{}, buildConditionErrorMessage("noStrictNullCheck"))
			}
		}

		return rule.RuleListeners{
			ast.KindIfStatement: func(node *ast.Node) {
				if isWithinArrayPredicateCallback(ctx, node) {
					return
				}
				stmt := node.AsIfStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression, opts)
			},
			ast.KindWhileStatement: func(node *ast.Node) {
				if isWithinArrayPredicateCallback(ctx, node) {
					return
				}
				stmt := node.AsWhileStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression, opts)
			},
			ast.KindDoStatement: func(node *ast.Node) {
				if isWithinArrayPredicateCallback(ctx, node) {
					return
				}
				stmt := node.AsDoStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Expression, opts)
			},
			ast.KindForStatement: func(node *ast.Node) {
				if isWithinArrayPredicateCallback(ctx, node) {
					return
				}
				stmt := node.AsForStatement()
				if stmt == nil {
					return
				}
				checkCondition(ctx, stmt.Condition, opts)
			},
			ast.KindConditionalExpression: func(node *ast.Node) {
				if isWithinArrayPredicateCallback(ctx, node) {
					return
				}
				cond := node.AsConditionalExpression()
				if cond == nil {
					return
				}
				checkCondition(ctx, cond.Condition, opts)
			},
			ast.KindExpressionStatement: func(node *ast.Node) {
				statement := node.AsExpressionStatement()
				if statement == nil || statement.Expression == nil {
					return
				}
				expression := ast.SkipParentheses(statement.Expression)
				if expression == nil || expression.Kind != ast.KindBinaryExpression {
					return
				}
				binary := expression.AsBinaryExpression()
				if binary == nil || (binary.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && binary.OperatorToken.Kind != ast.KindBarBarToken) {
					return
				}
				checkControlFlowLogicalExpression(ctx, expression, opts)
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				declaration := node.AsVariableDeclaration()
				if declaration == nil || declaration.Initializer == nil {
					return
				}
				expression := ast.SkipParentheses(declaration.Initializer)
				if expression == nil || expression.Kind != ast.KindBinaryExpression {
					return
				}
				binary := expression.AsBinaryExpression()
				if binary == nil || (binary.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && binary.OperatorToken.Kind != ast.KindBarBarToken) {
					return
				}
				checkControlFlowLogicalExpression(ctx, expression, opts)
			},
			ast.KindReturnStatement: func(node *ast.Node) {
				returnStatement := node.AsReturnStatement()
				if returnStatement == nil || returnStatement.Expression == nil {
					return
				}
				expression := ast.SkipParentheses(returnStatement.Expression)
				if expression == nil || expression.Kind != ast.KindBinaryExpression {
					return
				}
				binary := expression.AsBinaryExpression()
				if binary == nil || (binary.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && binary.OperatorToken.Kind != ast.KindBarBarToken) {
					return
				}
				checkControlFlowLogicalExpression(ctx, expression, opts)
			},
			ast.KindCallExpression: func(node *ast.Node) {
				checkAssertionPredicateCall(ctx, node, opts)
				checkArrayPredicateCallback(ctx, node, opts)

				call := node.AsCallExpression()
				if call == nil || call.Arguments == nil {
					return
				}
				for _, argument := range call.Arguments.Nodes {
					expression := ast.SkipParentheses(argument)
					if expression == nil || expression.Kind != ast.KindBinaryExpression {
						continue
					}
					binary := expression.AsBinaryExpression()
					if binary == nil || (binary.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && binary.OperatorToken.Kind != ast.KindBarBarToken) {
						continue
					}
					checkControlFlowLogicalExpression(ctx, expression, opts)
				}
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				if isArrayPredicateCallbackNode(ctx, node) {
					return
				}
				arrow := node.AsArrowFunction()
				if arrow == nil || arrow.Body == nil {
					return
				}
				bodyNode := ast.SkipParentheses(arrow.Body.AsNode())
				if bodyNode == nil || bodyNode.Kind != ast.KindBinaryExpression {
					return
				}
				binary := bodyNode.AsBinaryExpression()
				if binary == nil || (binary.OperatorToken.Kind != ast.KindAmpersandAmpersandToken && binary.OperatorToken.Kind != ast.KindBarBarToken) {
					return
				}
				checkControlFlowLogicalExpression(ctx, bodyNode, opts)
			},
			ast.KindPrefixUnaryExpression: func(node *ast.Node) {
				unary := node.AsPrefixUnaryExpression()
				if unary == nil || unary.Operator != ast.KindExclamationToken || unary.Operand == nil {
					return
				}
				if isDirectConditionalContext(node) {
					return
				}
				operand := ast.SkipParentheses(unary.Operand)
				if operand == nil {
					return
				}
				checkCondition(ctx, operand, opts)
			},
		}
	},
})
