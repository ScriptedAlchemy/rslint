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
	nonNullishPrimitiveSeen := false
	allNonNullishPrimitivesDefinitelyTruthy := true

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
					if utils.IsTypeFlagSet(intersectionPart, checker.TypeFlagsPossiblyFalsy) {
						allNonNullishPrimitivesDefinitelyTruthy = false
					}
				} else {
					allNonNullishPrimitivesDefinitelyTruthy = false
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
			if utils.IsTypeFlagSet(part, checker.TypeFlagsPossiblyFalsy) {
				allNonNullishPrimitivesDefinitelyTruthy = false
			}
		} else {
			allNonNullishPrimitivesDefinitelyTruthy = false
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
	if hasNullish && nonNullishPrimitiveSeen && allNonNullishPrimitivesDefinitelyTruthy {
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
		return
	}

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
		messageId := conditionErrorMessageID(effectiveReturnType, opts)
		if messageId == "" {
			continue
		}
		ctx.ReportNode(callback, buildConditionErrorMessage(messageId))
		return
	}
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
			checkCondition(ctx, bodyNode, opts)
			return
		}
		returnExpressions := []*ast.Node{}
		collectReturnExpressionsSkippingNestedFunctions(bodyNode, false, &returnExpressions)
		for _, expression := range returnExpressions {
			checkCondition(ctx, expression, opts)
		}
		return
	case ast.KindFunctionExpression:
		functionExpression := callback.AsFunctionExpression()
		if functionExpression == nil || functionExpression.Body == nil {
			return
		}
		returnExpressions := []*ast.Node{}
		collectReturnExpressionsSkippingNestedFunctions(functionExpression.Body.AsNode(), false, &returnExpressions)
		for _, expression := range returnExpressions {
			checkCondition(ctx, expression, opts)
		}
		return
	}

	checkCallbackFunctionReturnType(ctx, callback, opts)
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
