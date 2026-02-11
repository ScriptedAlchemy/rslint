package prefer_optional_chain

import (
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildPreferOptionalChainMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferOptionalChain",
		Description: "Prefer using an optional chain expression instead, as it's more concise and easier to read.",
	}
}

type preferOptionalChainOptions struct {
	RequireNullish bool
	CheckAny       bool
	CheckUnknown   bool
	CheckBigInt    bool
	CheckBoolean   bool
	CheckNumber    bool
	CheckString    bool
}

func defaultPreferOptionalChainOptions() preferOptionalChainOptions {
	return preferOptionalChainOptions{
		RequireNullish: false,
		CheckAny:       true,
		CheckUnknown:   true,
		CheckBigInt:    true,
		CheckBoolean:   true,
		CheckNumber:    true,
		CheckString:    true,
	}
}

func parsePreferOptionalChainOptions(options any) preferOptionalChainOptions {
	parsed := defaultPreferOptionalChainOptions()
	optionList, ok := options.([]interface{})
	if !ok || len(optionList) == 0 {
		return parsed
	}
	optionMap, ok := optionList[0].(map[string]interface{})
	if !ok {
		return parsed
	}
	if value, ok := optionMap["requireNullish"].(bool); ok {
		parsed.RequireNullish = value
	}
	if value, ok := optionMap["checkAny"].(bool); ok {
		parsed.CheckAny = value
	}
	if value, ok := optionMap["checkUnknown"].(bool); ok {
		parsed.CheckUnknown = value
	}
	if value, ok := optionMap["checkBigInt"].(bool); ok {
		parsed.CheckBigInt = value
	}
	if value, ok := optionMap["checkBoolean"].(bool); ok {
		parsed.CheckBoolean = value
	}
	if value, ok := optionMap["checkNumber"].(bool); ok {
		parsed.CheckNumber = value
	}
	if value, ok := optionMap["checkString"].(bool); ok {
		parsed.CheckString = value
	}
	return parsed
}

func normalizeNodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	sourceText := sourceFile.Text()
	if trimmed.Pos() < 0 || trimmed.End() > len(sourceText) || trimmed.Pos() >= trimmed.End() {
		return ""
	}
	raw := sourceText[trimmed.Pos():trimmed.End()]
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
}

func isNullishLiteral(node *ast.Node) bool {
	if node == nil {
		return false
	}
	node = ast.SkipParentheses(node)
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindNullKeyword:
		return true
	case ast.KindIdentifier:
		identifier := node.AsIdentifier()
		return identifier != nil && identifier.Text == "undefined"
	default:
		return false
	}
}

type nullishComparison struct {
	Expression      *ast.Node
	Strict          bool
	ExpectNotEqual  bool
	ChecksNull      bool
	ChecksUndefined bool
}

func parseNullishComparison(node *ast.Node, expectNotEqual bool) (*nullishComparison, bool) {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return nil, false
	}
	binary := node.AsBinaryExpression()
	if binary == nil {
		return nil, false
	}
	switch binary.OperatorToken.Kind {
	case ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken:
		if !expectNotEqual {
			return nil, false
		}
		strict := binary.OperatorToken.Kind == ast.KindExclamationEqualsEqualsToken
		if isNullishLiteral(binary.Left) {
			return &nullishComparison{Expression: binary.Right, Strict: strict, ExpectNotEqual: true, ChecksNull: binary.Left.Kind == ast.KindNullKeyword, ChecksUndefined: !isNullishLiteral(binary.Left) || (binary.Left.Kind == ast.KindIdentifier && binary.Left.AsIdentifier().Text == "undefined")}, true
		}
		if isNullishLiteral(binary.Right) {
			return &nullishComparison{Expression: binary.Left, Strict: strict, ExpectNotEqual: true, ChecksNull: binary.Right.Kind == ast.KindNullKeyword, ChecksUndefined: !isNullishLiteral(binary.Right) || (binary.Right.Kind == ast.KindIdentifier && binary.Right.AsIdentifier().Text == "undefined")}, true
		}
	case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken:
		if expectNotEqual {
			return nil, false
		}
		strict := binary.OperatorToken.Kind == ast.KindEqualsEqualsEqualsToken
		if isNullishLiteral(binary.Left) {
			return &nullishComparison{Expression: binary.Right, Strict: strict, ExpectNotEqual: false, ChecksNull: binary.Left.Kind == ast.KindNullKeyword, ChecksUndefined: !isNullishLiteral(binary.Left) || (binary.Left.Kind == ast.KindIdentifier && binary.Left.AsIdentifier().Text == "undefined")}, true
		}
		if isNullishLiteral(binary.Right) {
			return &nullishComparison{Expression: binary.Left, Strict: strict, ExpectNotEqual: false, ChecksNull: binary.Right.Kind == ast.KindNullKeyword, ChecksUndefined: !isNullishLiteral(binary.Right) || (binary.Right.Kind == ast.KindIdentifier && binary.Right.AsIdentifier().Text == "undefined")}, true
		}
	default:
		return nil, false
	}
	return nil, false
}

func parseTypeofUndefinedComparison(node *ast.Node, expectNotEqual bool) (*ast.Node, bool) {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return nil, false
	}
	binary := node.AsBinaryExpression()
	if binary == nil {
		return nil, false
	}
	switch binary.OperatorToken.Kind {
	case ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken:
		if !expectNotEqual {
			return nil, false
		}
	case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken:
		if expectNotEqual {
			return nil, false
		}
	default:
		return nil, false
	}

	extractOperand := func(typeOfNode *ast.Node, valueNode *ast.Node) (*ast.Node, bool) {
		if valueNode == nil || valueNode.Kind != ast.KindStringLiteral {
			return nil, false
		}
		stringLiteral := valueNode.AsStringLiteral()
		if stringLiteral == nil || stringLiteral.Text != "undefined" {
			return nil, false
		}
		typeOfNode = ast.SkipParentheses(typeOfNode)
		if typeOfNode == nil || typeOfNode.Kind != ast.KindTypeOfExpression {
			return nil, false
		}
		typeOfExpression := typeOfNode.AsTypeOfExpression()
		if typeOfExpression == nil {
			return nil, false
		}
		return ast.SkipParentheses(typeOfExpression.Expression), true
	}

	if expression, ok := extractOperand(binary.Left, binary.Right); ok {
		return expression, true
	}
	return extractOperand(binary.Right, binary.Left)
}

func containsPrivatePropertyAccess(node *ast.Node) bool {
	found := false
	var walk func(*ast.Node)
	walk = func(current *ast.Node) {
		if current == nil || found {
			return
		}
		if current.Kind == ast.KindPropertyAccessExpression {
			access := current.AsPropertyAccessExpression()
			if access != nil && access.Name() != nil && access.Name().Kind == ast.KindPrivateIdentifier {
				found = true
				return
			}
		}
		current.ForEachChild(func(child *ast.Node) bool {
			walk(child)
			return found
		})
	}
	walk(node)
	return found
}

func isExpressionExtensionOf(sourceFile *ast.SourceFile, candidate *ast.Node, base *ast.Node) bool {
	if sourceFile == nil || candidate == nil || base == nil {
		return false
	}
	candidateText := normalizeNodeText(sourceFile, ast.SkipParentheses(candidate))
	baseText := normalizeNodeText(sourceFile, ast.SkipParentheses(base))
	candidateText = strings.ReplaceAll(candidateText, "!", "")
	baseText = strings.ReplaceAll(baseText, "!", "")
	candidateText = strings.ReplaceAll(candidateText, "?", "")
	baseText = strings.ReplaceAll(baseText, "?", "")
	if candidateText == "" || baseText == "" || candidateText == baseText {
		return false
	}
	if baseText == "this" {
		return false
	}
	return strings.HasPrefix(candidateText, baseText+".") ||
		strings.HasPrefix(candidateText, baseText+"?.") ||
		strings.HasPrefix(candidateText, baseText+"[") ||
		strings.HasPrefix(candidateText, baseText+"?.[") ||
		strings.HasPrefix(candidateText, baseText+"(") ||
		strings.HasPrefix(candidateText, baseText+"?.(") ||
		strings.HasPrefix(candidateText, baseText+"<")
}

func extractComparedExpression(node *ast.Node, expectNotEqual bool) (*nullishComparison, bool) {
	comparison, ok := parseNullishComparison(node, expectNotEqual)
	if !ok {
		return nil, false
	}
	comparison.Expression = ast.SkipParentheses(comparison.Expression)
	return comparison, true
}

func collectLogicalOperands(node *ast.Node, operator ast.Kind, out *[]*ast.Node) {
	node = ast.SkipParentheses(node)
	if node == nil || node.Kind != ast.KindBinaryExpression {
		*out = append(*out, node)
		return
	}
	binary := node.AsBinaryExpression()
	if binary == nil || binary.OperatorToken.Kind != operator {
		*out = append(*out, node)
		return
	}
	collectLogicalOperands(binary.Left, operator, out)
	collectLogicalOperands(binary.Right, operator, out)
}

func negatedOperand(node *ast.Node) (*ast.Node, bool) {
	node = ast.SkipParentheses(node)
	if node == nil || node.Kind != ast.KindPrefixUnaryExpression {
		return nil, false
	}
	unary := node.AsPrefixUnaryExpression()
	if unary == nil || unary.Operator != ast.KindExclamationToken {
		return nil, false
	}
	return ast.SkipParentheses(unary.Operand), true
}

func isEmptyObjectLiteral(node *ast.Node) bool {
	node = ast.SkipParentheses(node)
	if node == nil {
		return false
	}
	if node.Kind == ast.KindObjectLiteralExpression {
		objectLiteral := node.AsObjectLiteralExpression()
		return objectLiteral != nil && (objectLiteral.Properties == nil || len(objectLiteral.Properties.Nodes) == 0)
	}
	return false
}

func typeIncludesFlag(t *checker.Type, flag checker.TypeFlags) bool {
	if t == nil {
		return false
	}
	for _, part := range utils.UnionTypeParts(t) {
		if part != nil && checker.Type_flags(part)&flag != 0 {
			return true
		}
	}
	return checker.Type_flags(t)&flag != 0
}

func comparisonSupportsOptionalChain(ctx rule.RuleContext, comparison *nullishComparison) bool {
	if comparison == nil {
		return false
	}
	if !comparison.Strict || ctx.TypeChecker == nil || comparison.Expression == nil {
		return true
	}
	expressionType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, comparison.Expression)
	if expressionType == nil {
		return false
	}
	includesNull := typeIncludesFlag(expressionType, checker.TypeFlagsNull)
	includesUndefined := typeIncludesFlag(expressionType, checker.TypeFlagsUndefined|checker.TypeFlagsVoid)

	if comparison.ChecksNull && !comparison.ChecksUndefined {
		return !includesUndefined
	}
	if comparison.ChecksUndefined && !comparison.ChecksNull {
		return !includesNull
	}
	return true
}

func endsWithEmptyObjectFallback(node *ast.Node, operator ast.Kind) bool {
	node = ast.SkipParentheses(node)
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return false
	}
	binary := node.AsBinaryExpression()
	if binary == nil || binary.OperatorToken.Kind != operator {
		return false
	}
	if isEmptyObjectLiteral(binary.Right) {
		return true
	}
	return endsWithEmptyObjectFallback(binary.Right, operator)
}

func isDefinitelyNonNullishExpression(node *ast.Node) bool {
	node = ast.SkipParentheses(node)
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindObjectLiteralExpression,
		ast.KindArrayLiteralExpression,
		ast.KindNewExpression,
		ast.KindFunctionExpression,
		ast.KindArrowFunction,
		ast.KindClassExpression,
		ast.KindRegularExpressionLiteral,
		ast.KindStringLiteral,
		ast.KindNoSubstitutionTemplateLiteral,
		ast.KindTemplateExpression,
		ast.KindNumericLiteral,
		ast.KindBigIntLiteral,
		ast.KindTrueKeyword,
		ast.KindFalseKeyword,
		ast.KindThisKeyword:
		return true
	default:
		return false
	}
}

func containsDisallowedSideEffectExpression(node *ast.Node) bool {
	found := false
	var walk func(*ast.Node)
	walk = func(current *ast.Node) {
		if current == nil || found {
			return
		}
		switch current.Kind {
		case ast.KindPrefixUnaryExpression:
			unary := current.AsPrefixUnaryExpression()
			if unary != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken) {
				found = true
				return
			}
		case ast.KindPostfixUnaryExpression:
			unary := current.AsPostfixUnaryExpression()
			if unary != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken) {
				found = true
				return
			}
		case ast.KindYieldExpression:
			found = true
			return
		}
		current.ForEachChild(func(child *ast.Node) bool {
			walk(child)
			return found
		})
	}
	walk(node)
	return found
}

func rootExpressionKey(sourceFile *ast.SourceFile, node *ast.Node) string {
	node = ast.SkipParentheses(node)
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindPropertyAccessExpression:
		access := node.AsPropertyAccessExpression()
		if access != nil {
			return rootExpressionKey(sourceFile, access.Expression)
		}
	case ast.KindElementAccessExpression:
		access := node.AsElementAccessExpression()
		if access != nil {
			return rootExpressionKey(sourceFile, access.Expression)
		}
	case ast.KindCallExpression:
		callExpression := node.AsCallExpression()
		if callExpression != nil {
			return rootExpressionKey(sourceFile, callExpression.Expression)
		}
	case ast.KindNonNullExpression:
		nonNull := node.AsNonNullExpression()
		if nonNull != nil {
			return rootExpressionKey(sourceFile, nonNull.Expression)
		}
	case ast.KindAsExpression:
		asExpression := node.AsAsExpression()
		if asExpression != nil {
			return rootExpressionKey(sourceFile, asExpression.Expression)
		}
	case ast.KindTypeAssertionExpression:
		typeAssertion := node.AsTypeAssertion()
		if typeAssertion != nil {
			return rootExpressionKey(sourceFile, typeAssertion.Expression)
		}
	}
	return strings.ReplaceAll(normalizeNodeText(sourceFile, node), "!", "")
}

func expressionMayBeNullish(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return true
	}
	nodeType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
	if nodeType == nil {
		return true
	}
	parts := utils.UnionTypeParts(nodeType)
	if len(parts) == 0 {
		parts = []*checker.Type{nodeType}
	}
	for _, part := range parts {
		if part == nil {
			continue
		}
		flags := checker.Type_flags(part)
		if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsVoid|checker.TypeFlagsAny|checker.TypeFlagsUnknown) != 0 {
			return true
		}
	}
	return false
}

func expressionIsAny(ctx rule.RuleContext, node *ast.Node) bool {
	if ctx.TypeChecker == nil || node == nil {
		return false
	}
	nodeType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
	if nodeType == nil {
		return false
	}
	for _, part := range utils.UnionTypeParts(nodeType) {
		if part != nil && checker.Type_flags(part)&checker.TypeFlagsAny != 0 {
			return true
		}
	}
	return checker.Type_flags(nodeType)&checker.TypeFlagsAny != 0
}

func shouldAnalyzeExpression(ctx rule.RuleContext, node *ast.Node, opts preferOptionalChainOptions) bool {
	if node == nil {
		return false
	}
	if ctx.TypeChecker != nil {
		nodeType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
		if nodeType != nil {
			parts := utils.UnionTypeParts(nodeType)
			if len(parts) == 0 {
				parts = []*checker.Type{nodeType}
			}
			hasAny := false
			hasUnknown := false
			hasBigInt := false
			hasBoolean := false
			hasNumber := false
			hasString := false
			hasNonNullishFalsyLiteral := false
			for _, part := range parts {
				if part == nil {
					continue
				}
				flags := checker.Type_flags(part)
				hasAny = hasAny || flags&checker.TypeFlagsAny != 0
				hasUnknown = hasUnknown || flags&checker.TypeFlagsUnknown != 0
				hasBigInt = hasBigInt || flags&checker.TypeFlagsBigIntLike != 0
				hasBoolean = hasBoolean || flags&checker.TypeFlagsBooleanLike != 0
				hasNumber = hasNumber || flags&checker.TypeFlagsNumberLike != 0
				hasString = hasString || flags&checker.TypeFlagsStringLike != 0
				if ctx.TypeChecker != nil {
					typeText := ctx.TypeChecker.TypeToString(part)
					if typeText == "false" || typeText == "0" || typeText == "0n" || typeText == `""` || typeText == `''` {
						hasNonNullishFalsyLiteral = true
					}
				}
			}
			if !opts.CheckAny && hasAny {
				return false
			}
			if !opts.CheckUnknown && hasUnknown {
				return false
			}
			if !opts.CheckBigInt && hasBigInt {
				return false
			}
			if !opts.CheckBoolean && hasBoolean {
				return false
			}
			if !opts.CheckNumber && hasNumber {
				return false
			}
			if !opts.CheckString && hasString {
				return false
			}
			if hasNonNullishFalsyLiteral {
				return false
			}
		}
	}
	if !opts.CheckAny && expressionIsAny(ctx, node) {
		return false
	}
	if opts.RequireNullish && !expressionMayBeNullish(ctx, node) {
		return false
	}
	return true
}

func shouldAnalyzeFallbackExpression(ctx rule.RuleContext, node *ast.Node, opts preferOptionalChainOptions) bool {
	if node == nil {
		return false
	}
	if !opts.CheckAny && expressionIsAny(ctx, node) {
		return false
	}
	if !opts.CheckUnknown {
		if ctx.TypeChecker != nil {
			nodeType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, node)
			if nodeType != nil {
				for _, part := range utils.UnionTypeParts(nodeType) {
					if part != nil && checker.Type_flags(part)&checker.TypeFlagsUnknown != 0 {
						return false
					}
				}
				if checker.Type_flags(nodeType)&checker.TypeFlagsUnknown != 0 {
					return false
				}
			}
		}
	}
	if opts.RequireNullish && !expressionMayBeNullish(ctx, node) {
		return false
	}
	return true
}

func hasLogicalBinaryAncestorWithOperator(node *ast.Node, operator ast.Kind) bool {
	current := node.Parent
	for current != nil && current.Kind == ast.KindParenthesizedExpression {
		current = current.Parent
	}
	if current == nil || current.Kind != ast.KindBinaryExpression {
		return false
	}
	parentBinary := current.AsBinaryExpression()
	return parentBinary != nil && parentBinary.OperatorToken.Kind == operator
}

func andPairMatchRoot(ctx rule.RuleContext, sourceFile *ast.SourceFile, left *ast.Node, right *ast.Node, opts preferOptionalChainOptions) (string, bool) {
	if left == nil || right == nil || containsPrivatePropertyAccess(right) {
		return "", false
	}
	if _, leftNegated := negatedOperand(left); leftNegated {
		return "", false
	}
	if _, rightNegated := negatedOperand(right); rightNegated {
		return "", false
	}
	if leftComparison, leftIsComparison := parseNullishComparison(left, true); leftIsComparison {
		if !shouldAnalyzeExpression(ctx, leftComparison.Expression, opts) {
			return "", false
		}
		if !comparisonSupportsOptionalChain(ctx, leftComparison) {
			return "", false
		}
		if rightCompared, isComparison := extractComparedExpression(right, true); isComparison {
			if !comparisonSupportsOptionalChain(ctx, rightCompared) {
				return "", false
			}
			if isExpressionExtensionOf(sourceFile, rightCompared.Expression, leftComparison.Expression) {
				return rootExpressionKey(sourceFile, leftComparison.Expression), true
			}
		} else if isExpressionExtensionOf(sourceFile, right, leftComparison.Expression) {
			return rootExpressionKey(sourceFile, leftComparison.Expression), true
		}
		return "", false
	}
	if rightComparison, isRightComparison := extractComparedExpression(right, true); isRightComparison {
		if !shouldAnalyzeExpression(ctx, left, opts) {
			return "", false
		}
		if rightComparison.Strict || !comparisonSupportsOptionalChain(ctx, rightComparison) {
			return "", false
		}
		if isExpressionExtensionOf(sourceFile, rightComparison.Expression, left) {
			return rootExpressionKey(sourceFile, left), true
		}
	}
	if rightTypeofCompared, isRightTypeofCompared := parseTypeofUndefinedComparison(right, true); isRightTypeofCompared {
		if !shouldAnalyzeExpression(ctx, left, opts) {
			return "", false
		}
		if expressionMayBeNullish(ctx, left) && isExpressionExtensionOf(sourceFile, rightTypeofCompared, left) {
			return rootExpressionKey(sourceFile, left), true
		}
	}
	if leftTypeofCompared, isLeftTypeofCompared := parseTypeofUndefinedComparison(left, true); isLeftTypeofCompared {
		if !shouldAnalyzeExpression(ctx, leftTypeofCompared, opts) || !expressionMayBeNullish(ctx, leftTypeofCompared) {
			return "", false
		}
		if isExpressionExtensionOf(sourceFile, right, leftTypeofCompared) {
			return rootExpressionKey(sourceFile, leftTypeofCompared), true
		}
	}
	if !isDefinitelyNonNullishExpression(left) && right.Kind != ast.KindBinaryExpression && shouldAnalyzeExpression(ctx, left, opts) && isExpressionExtensionOf(sourceFile, right, left) {
		if containsDisallowedSideEffectExpression(left) {
			return "", false
		}
		rootKey := rootExpressionKey(sourceFile, left)
		leftText := strings.ReplaceAll(normalizeNodeText(sourceFile, left), "!", "")
		if strings.HasPrefix(rootKey, "new") && !strings.HasPrefix(leftText, "new.target") {
			return "", false
		}
		return rootKey, true
	}
	return "", false
}

func andChainMatchRuns(ctx rule.RuleContext, sourceFile *ast.SourceFile, operands []*ast.Node, opts preferOptionalChainOptions) int {
	count := 0
	lastRoot := ""
	for i := 0; i+1 < len(operands); i++ {
		left := ast.SkipParentheses(operands[i])
		right := ast.SkipParentheses(operands[i+1])
		matchRoot, matched := andPairMatchRoot(ctx, sourceFile, left, right, opts)
		if !matched {
			continue
		}
		if matchRoot == "" {
			matchRoot = normalizeNodeText(sourceFile, left)
		}
		if matchRoot != lastRoot {
			count++
			lastRoot = matchRoot
		}
	}
	return count
}

func shouldReportOrChain(ctx rule.RuleContext, sourceFile *ast.SourceFile, operands []*ast.Node) bool {
	for i := 0; i+1 < len(operands); i++ {
		left := ast.SkipParentheses(operands[i])
		right := ast.SkipParentheses(operands[i+1])
		if left == nil || right == nil || containsPrivatePropertyAccess(right) {
			continue
		}
		if leftNegated, ok := negatedOperand(left); ok {
			if rightNegated, ok := negatedOperand(right); ok {
				if isExpressionExtensionOf(sourceFile, rightNegated, leftNegated) {
					return true
				}
			}
		}
		if leftComparison, ok := parseNullishComparison(left, false); ok {
			if !comparisonSupportsOptionalChain(ctx, leftComparison) {
				continue
			}
			if rightCompared, isComparison := extractComparedExpression(right, false); isComparison {
				if !comparisonSupportsOptionalChain(ctx, rightCompared) {
					continue
				}
				if isExpressionExtensionOf(sourceFile, rightCompared.Expression, leftComparison.Expression) {
					return true
				}
			}
		}
	}
	return false
}

var PreferOptionalChainRule = rule.CreateRule(rule.Rule{
	Name: "prefer-optional-chain",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parsePreferOptionalChainOptions(options)
		return rule.RuleListeners{
			ast.KindBinaryExpression: func(node *ast.Node) {
				expr := node.AsBinaryExpression()
				if expr == nil {
					return
				}
				switch expr.OperatorToken.Kind {
				case ast.KindAmpersandAmpersandToken:
					if hasLogicalBinaryAncestorWithOperator(node, ast.KindAmpersandAmpersandToken) {
						return
					}
					if node.Parent != nil && node.Parent.Kind == ast.KindBinaryExpression {
						parent := node.Parent.AsBinaryExpression()
						if parent != nil && parent.OperatorToken.Kind == ast.KindAmpersandAmpersandToken {
							return
						}
					}
					operands := []*ast.Node{}
					collectLogicalOperands(node, ast.KindAmpersandAmpersandToken, &operands)
					matchRuns := andChainMatchRuns(ctx, ctx.SourceFile, operands, opts)
					for range matchRuns {
						ctx.ReportNode(node, buildPreferOptionalChainMessage())
					}
				case ast.KindBarBarToken:
					if hasLogicalBinaryAncestorWithOperator(node, ast.KindBarBarToken) {
						return
					}
					if node.Parent != nil && node.Parent.Kind == ast.KindBinaryExpression {
						parent := node.Parent.AsBinaryExpression()
						if parent != nil && parent.OperatorToken.Kind == ast.KindBarBarToken {
							return
						}
					}
					operands := []*ast.Node{}
					collectLogicalOperands(node, ast.KindBarBarToken, &operands)
					if shouldReportOrChain(ctx, ctx.SourceFile, operands) {
						ctx.ReportNode(node, buildPreferOptionalChainMessage())
					}
				}
			},
			ast.KindPropertyAccessExpression: func(node *ast.Node) {
				access := node.AsPropertyAccessExpression()
				if access == nil || access.Expression == nil {
					return
				}
				base := ast.SkipParentheses(access.Expression)
				if base == nil || base.Kind != ast.KindBinaryExpression {
					return
				}
				binary := base.AsBinaryExpression()
				if binary == nil {
					return
				}
				if access.QuestionDotToken != nil {
					return
				}
				if (binary.OperatorToken.Kind == ast.KindBarBarToken || binary.OperatorToken.Kind == ast.KindQuestionQuestionToken) &&
					endsWithEmptyObjectFallback(base, binary.OperatorToken.Kind) {
					if !shouldAnalyzeFallbackExpression(ctx, binary.Left, opts) {
						return
					}
					ctx.ReportNode(node, buildPreferOptionalChainMessage())
				}
			},
			ast.KindElementAccessExpression: func(node *ast.Node) {
				access := node.AsElementAccessExpression()
				if access == nil || access.Expression == nil {
					return
				}
				base := ast.SkipParentheses(access.Expression)
				if base == nil || base.Kind != ast.KindBinaryExpression {
					return
				}
				binary := base.AsBinaryExpression()
				if binary == nil {
					return
				}
				if access.QuestionDotToken != nil {
					return
				}
				if (binary.OperatorToken.Kind == ast.KindBarBarToken || binary.OperatorToken.Kind == ast.KindQuestionQuestionToken) &&
					endsWithEmptyObjectFallback(base, binary.OperatorToken.Kind) {
					if !shouldAnalyzeFallbackExpression(ctx, binary.Left, opts) {
						return
					}
					ctx.ReportNode(node, buildPreferOptionalChainMessage())
				}
			},
		}
	},
})
