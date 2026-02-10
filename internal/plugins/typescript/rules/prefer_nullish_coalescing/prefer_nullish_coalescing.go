package prefer_nullish_coalescing

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type PreferNullishCoalescingOptions struct {
	AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing *bool                          `json:"allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing"`
	IgnoreBooleanCoercion                                  *bool                          `json:"ignoreBooleanCoercion"`
	IgnoreConditionalTests                                 *bool                          `json:"ignoreConditionalTests"`
	IgnoreIfStatements                                     *bool                          `json:"ignoreIfStatements"`
	IgnoreMixedLogicalExpressions                          *bool                          `json:"ignoreMixedLogicalExpressions"`
	IgnorePrimitives                                       *PreferNullishPrimitivesOption `json:"ignorePrimitives"`
	IgnoreTernaryTests                                     *bool                          `json:"ignoreTernaryTests"`
}

type PreferNullishPrimitivesOption struct {
	Boolean *bool `json:"boolean"`
	String  *bool `json:"string"`
	Number  *bool `json:"number"`
	Bigint  *bool `json:"bigint"`
}

var propertyStringElementAccessPattern = regexp.MustCompile(`\[['"]([A-Za-z_$][A-Za-z0-9_$]*)['"]\]`)

func unwrapParenthesized(node *ast.Node) *ast.Node {
	current := node
	for current != nil && current.Kind == ast.KindParenthesizedExpression {
		paren := current.AsParenthesizedExpression()
		if paren == nil {
			return current
		}
		current = paren.Expression
	}
	return current
}

func parseOptions(options any) PreferNullishCoalescingOptions {
	opts := PreferNullishCoalescingOptions{
		AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing: utils.Ref(false),
		IgnoreBooleanCoercion:         utils.Ref(false),
		IgnoreConditionalTests:        utils.Ref(true),
		IgnoreIfStatements:            utils.Ref(false),
		IgnoreMixedLogicalExpressions: utils.Ref(false),
		IgnorePrimitives: &PreferNullishPrimitivesOption{
			Boolean: utils.Ref(false),
			String:  utils.Ref(false),
			Number:  utils.Ref(false),
			Bigint:  utils.Ref(false),
		},
		IgnoreTernaryTests: utils.Ref(false),
	}

	if options == nil {
		return opts
	}

	// Handle array format: [{ option: value }]
	if arr, ok := options.([]interface{}); ok {
		if len(arr) > 0 {
			if m, ok := arr[0].(map[string]interface{}); ok {
				parseOptionsFromMap(m, &opts)
			}
		}
		return opts
	}

	// Handle direct object format
	if m, ok := options.(map[string]interface{}); ok {
		parseOptionsFromMap(m, &opts)
	}

	return opts
}

func parseOptionsFromMap(m map[string]interface{}, opts *PreferNullishCoalescingOptions) {
	if v, ok := m["allowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing"].(bool); ok {
		opts.AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing = &v
	}
	if v, ok := m["ignoreBooleanCoercion"].(bool); ok {
		opts.IgnoreBooleanCoercion = &v
	}
	if v, ok := m["ignoreConditionalTests"].(bool); ok {
		opts.IgnoreConditionalTests = &v
	}
	if v, ok := m["ignoreIfStatements"].(bool); ok {
		opts.IgnoreIfStatements = &v
	}
	if v, ok := m["ignoreMixedLogicalExpressions"].(bool); ok {
		opts.IgnoreMixedLogicalExpressions = &v
	}
	if v, ok := m["ignoreTernaryTests"].(bool); ok {
		opts.IgnoreTernaryTests = &v
	}

	// Handle ignorePrimitives option
	if primitives, ok := m["ignorePrimitives"]; ok {
		if primitivesBool, ok := primitives.(bool); ok && primitivesBool {
			// If true, ignore all primitives
			opts.IgnorePrimitives.Boolean = utils.Ref(true)
			opts.IgnorePrimitives.String = utils.Ref(true)
			opts.IgnorePrimitives.Number = utils.Ref(true)
			opts.IgnorePrimitives.Bigint = utils.Ref(true)
		} else if primitivesMap, ok := primitives.(map[string]interface{}); ok {
			if v, ok := primitivesMap["boolean"].(bool); ok {
				opts.IgnorePrimitives.Boolean = &v
			}
			if v, ok := primitivesMap["string"].(bool); ok {
				opts.IgnorePrimitives.String = &v
			}
			if v, ok := primitivesMap["number"].(bool); ok {
				opts.IgnorePrimitives.Number = &v
			}
			if v, ok := primitivesMap["bigint"].(bool); ok {
				opts.IgnorePrimitives.Bigint = &v
			}
		}
	}
}

func buildNoStrictNullCheckMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noStrictNullCheck",
		Description: "This rule requires the `strictNullChecks` compiler option to be turned on to function correctly.",
	}
}

func buildPreferNullishOverOrMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferNullishOverOr",
		Description: "Prefer using nullish coalescing operator (`??`) instead of a logical or (`||`), as it is a safer operator.",
	}
}

func buildPreferNullishOverAssignmentMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferNullishOverAssignment",
		Description: "Prefer using nullish coalescing operator (`??=`) instead of an assignment expression, as it is simpler to read.",
	}
}

func buildPreferNullishOverTernaryMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferNullishOverTernary",
		Description: "Prefer using nullish coalescing operator (`??`) instead of a ternary expression, as it is simpler to read.",
	}
}

func buildSuggestNullishMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "suggestNullish",
		Description: "Fix to nullish coalescing operator (`??`).",
	}
}

// isNullableType checks if a type includes null or undefined
func isNullableType(t *checker.Type) bool {
	if utils.IsUnionType(t) {
		for _, unionType := range t.Types() {
			flags := checker.Type_flags(unionType)
			if flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined) != 0 {
				return true
			}
		}
	}
	flags := checker.Type_flags(t)
	return flags&(checker.TypeFlagsNull|checker.TypeFlagsUndefined) != 0
}

// isTypeEligibleForPreferNullish checks if a type is eligible for nullish coalescing conversion
func isTypeEligibleForPreferNullish(t *checker.Type, opts PreferNullishCoalescingOptions) bool {
	// Check for ignorable flags based on options
	var ignorableFlags checker.TypeFlags
	if opts.IgnorePrimitives.Boolean != nil && *opts.IgnorePrimitives.Boolean {
		ignorableFlags |= checker.TypeFlagsBooleanLike
	}
	if opts.IgnorePrimitives.String != nil && *opts.IgnorePrimitives.String {
		ignorableFlags |= checker.TypeFlagsStringLike
	}
	if opts.IgnorePrimitives.Number != nil && *opts.IgnorePrimitives.Number {
		ignorableFlags |= checker.TypeFlagsNumberLike
	}
	if opts.IgnorePrimitives.Bigint != nil && *opts.IgnorePrimitives.Bigint {
		ignorableFlags |= checker.TypeFlagsBigIntLike
	}

	flags := checker.Type_flags(t)
	if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown) != 0 {
		if utils.IsIntrinsicErrorType(t) {
			return false
		}
		return ignorableFlags == 0
	}

	if !isNullableType(t) {
		return false
	}

	if ignorableFlags == 0 {
		return true // Any types are eligible for conversion
	}

	// Check if any type constituents match the ignorable flags
	for _, unionType := range utils.UnionTypeParts(t) {
		for _, intersectionPart := range utils.IntersectionTypeParts(unionType) {
			typeFlags := checker.Type_flags(intersectionPart)
			if typeFlags&ignorableFlags != 0 {
				return false
			}
		}
	}

	return true
}

// isMemberAccessLike checks if a node is a member access-like expression
func isMemberAccessLike(node *ast.Node) bool {
	return node.Kind == ast.KindIdentifier ||
		node.Kind == ast.KindPropertyAccessExpression ||
		node.Kind == ast.KindElementAccessExpression
}

func normalizeOptionalMemberAccessText(text string) string {
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, "(", "")
	text = strings.ReplaceAll(text, ")", "")
	text = strings.ReplaceAll(text, "?.[", ".[")
	text = strings.ReplaceAll(text, "?.", ".")
	text = strings.ReplaceAll(text, ".[", "[")
	text = strings.ReplaceAll(text, "?", "")
	text = propertyStringElementAccessPattern.ReplaceAllString(text, ".$1")
	return text
}

func areNodesSemanticallySimilar(sourceFile *ast.SourceFile, a, b *ast.Node) bool {
	a = unwrapParenthesized(a)
	b = unwrapParenthesized(b)
	if areNodesTextuallyEqual(sourceFile, a, b) {
		return true
	}
	if sourceFile == nil || a == nil || b == nil {
		return false
	}
	aText := normalizeOptionalMemberAccessText(getNodeText(sourceFile, a))
	bText := normalizeOptionalMemberAccessText(getNodeText(sourceFile, b))
	return aText == bText
}

// isConditionalTest checks if a node is within a conditional test context
func isConditionalTest(node *ast.Node) bool {
	parent := node.Parent
	if parent == nil {
		return false
	}

	switch parent.Kind {
	case ast.KindParenthesizedExpression:
		return isConditionalTest(parent)
	case ast.KindBinaryExpression:
		return isConditionalTest(parent)
	case ast.KindConditionalExpression:
		condExpr := parent.AsConditionalExpression()
		if condExpr != nil && condExpr.Condition == node {
			return true
		}
		return isConditionalTest(parent)
	case ast.KindIfStatement:
		ifStmt := parent.AsIfStatement()
		if ifStmt != nil && ifStmt.Expression == node {
			return true
		}
	case ast.KindWhileStatement, ast.KindDoStatement, ast.KindForStatement:
		return true
	case ast.KindPrefixUnaryExpression:
		prefixExpr := parent.AsPrefixUnaryExpression()
		if prefixExpr != nil && prefixExpr.Operator == ast.KindExclamationToken {
			return isConditionalTest(parent)
		}
	}

	return false
}

func isUndefinedIdentifier(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == ast.KindUndefinedKeyword {
		return true
	}
	if node.Kind == ast.KindIdentifier {
		return node.AsIdentifier().Text == "undefined"
	}
	return false
}

func isNullLiteral(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == ast.KindNullKeyword
}

func isNullishNode(node *ast.Node) bool {
	return isNullLiteral(node) || isUndefinedIdentifier(node)
}

func extractNullishComparedNode(node *ast.Node) (*ast.Node, bool) {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return nil, false
	}

	binary := node.AsBinaryExpression()
	if binary == nil {
		return nil, false
	}

	switch binary.OperatorToken.Kind {
	case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken:
		if isNullishNode(binary.Right) {
			return binary.Left, true
		}
		if isNullishNode(binary.Left) {
			return binary.Right, true
		}
		return nil, false
	case ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken:
		if isNullishNode(binary.Right) {
			return binary.Left, true
		}
		if isNullishNode(binary.Left) {
			return binary.Right, true
		}
		return nil, false
	default:
		return nil, false
	}
}

type nullishComparisonKinds struct {
	hasNull      bool
	hasUndefined bool
}

func collectNullishComparisonKinds(sourceFile *ast.SourceFile, node *ast.Node, target *ast.Node) (nullishComparisonKinds, bool) {
	kinds := nullishComparisonKinds{}
	if node == nil || target == nil {
		return kinds, false
	}

	node = unwrapParenthesized(node)
	if node == nil {
		return kinds, false
	}

	if node.Kind == ast.KindBinaryExpression {
		binary := node.AsBinaryExpression()
		if binary == nil {
			return kinds, false
		}

		switch binary.OperatorToken.Kind {
		case ast.KindAmpersandAmpersandToken, ast.KindBarBarToken:
			leftKinds, leftValid := collectNullishComparisonKinds(sourceFile, binary.Left, target)
			rightKinds, rightValid := collectNullishComparisonKinds(sourceFile, binary.Right, target)
			if !leftValid || !rightValid {
				return kinds, false
			}
			return nullishComparisonKinds{
				hasNull:      leftKinds.hasNull || rightKinds.hasNull,
				hasUndefined: leftKinds.hasUndefined || rightKinds.hasUndefined,
			}, true
		case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken,
			ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken:
			comparedTarget, ok := extractNullishComparedNode(node)
			if !ok || !areNodesSemanticallySimilar(sourceFile, comparedTarget, target) {
				return kinds, false
			}

			if isNullLiteral(binary.Left) || isNullLiteral(binary.Right) {
				kinds.hasNull = true
			}
			if isUndefinedIdentifier(binary.Left) || isUndefinedIdentifier(binary.Right) {
				kinds.hasUndefined = true
			}

			// x == null or x != null matches both null and undefined.
			if (binary.OperatorToken.Kind == ast.KindEqualsEqualsToken || binary.OperatorToken.Kind == ast.KindExclamationEqualsToken) &&
				(isNullishNode(binary.Left) || isNullishNode(binary.Right)) {
				kinds.hasNull = true
				kinds.hasUndefined = true
			}

			return kinds, true
		}
	}

	return kinds, false
}

func typeMayContainFlag(t *checker.Type, flag checker.TypeFlags) bool {
	if t == nil {
		return false
	}
	for _, unionType := range utils.UnionTypeParts(t) {
		if checker.Type_flags(unionType)&flag != 0 {
			return true
		}
	}
	return false
}

func isNonNullishComparison(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return false
	}
	binary := node.AsBinaryExpression()
	if binary == nil {
		return false
	}
	switch binary.OperatorToken.Kind {
	case ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken:
		return (isNullishNode(binary.Right) && !isNullishNode(binary.Left)) ||
			(isNullishNode(binary.Left) && !isNullishNode(binary.Right))
	default:
		return false
	}
}

func isNullishComparison(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindBinaryExpression {
		return false
	}
	binary := node.AsBinaryExpression()
	if binary == nil {
		return false
	}
	switch binary.OperatorToken.Kind {
	case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken:
		return (isNullishNode(binary.Right) && !isNullishNode(binary.Left)) ||
			(isNullishNode(binary.Left) && !isNullishNode(binary.Right))
	default:
		return false
	}
}

func extractNullishTernaryInfo(sourceFile *ast.SourceFile, condition *ast.Node) (target *ast.Node, nonNullishWhenTrue bool, ok bool) {
	if condition == nil {
		return nil, false, false
	}

	condition = unwrapParenthesized(condition)
	if condition == nil {
		return nil, false, false
	}

	if isMemberAccessLike(condition) {
		return condition, true, true
	}

	if condition.Kind == ast.KindPrefixUnaryExpression {
		unary := condition.AsPrefixUnaryExpression()
		if unary != nil && unary.Operator == ast.KindExclamationToken {
			operand := unwrapParenthesized(unary.Operand)
			if isMemberAccessLike(operand) {
				return operand, false, true
			}
		}
	}

	if condition.Kind == ast.KindBinaryExpression {
		binary := condition.AsBinaryExpression()
		if binary == nil {
			return nil, false, false
		}

		switch binary.OperatorToken.Kind {
		case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken:
			target, ok := extractNullishComparedNode(condition)
			return target, false, ok
		case ast.KindExclamationEqualsToken, ast.KindExclamationEqualsEqualsToken:
			target, ok := extractNullishComparedNode(condition)
			return target, true, ok
		case ast.KindAmpersandAmpersandToken, ast.KindBarBarToken:
			leftTarget, leftNonNullish, leftOK := extractNullishTernaryInfo(sourceFile, binary.Left)
			rightTarget, rightNonNullish, rightOK := extractNullishTernaryInfo(sourceFile, binary.Right)
			if !leftOK || !rightOK || !areNodesSemanticallySimilar(sourceFile, leftTarget, rightTarget) {
				return nil, false, false
			}

			if binary.OperatorToken.Kind == ast.KindAmpersandAmpersandToken {
				if isNonNullishComparison(binary.Left) && isNonNullishComparison(binary.Right) {
					return leftTarget, true, true
				}
				if leftNonNullish && rightNonNullish {
					return leftTarget, true, true
				}
			}

			if binary.OperatorToken.Kind == ast.KindBarBarToken {
				if isNullishComparison(binary.Left) && isNullishComparison(binary.Right) {
					return leftTarget, false, true
				}
				if !leftNonNullish && !rightNonNullish {
					return leftTarget, false, true
				}
			}
		}
	}

	return nil, false, false
}

// isBooleanConstructorContext checks if a node is within a Boolean constructor context
func isBooleanConstructorContext(node *ast.Node) bool {
	parent := node.Parent
	if parent == nil {
		return false
	}

	if parent.Kind == ast.KindCallExpression {
		callExpr := parent.AsCallExpression()
		if callExpr != nil && callExpr.Expression.Kind == ast.KindIdentifier {
			identifier := callExpr.Expression.AsIdentifier()
			if identifier != nil && identifier.Text == "Boolean" {
				return true
			}
		}
	}

	// Check parent contexts recursively
	switch parent.Kind {
	case ast.KindParenthesizedExpression:
		return isBooleanConstructorContext(parent)
	case ast.KindBinaryExpression:
		binExpr := parent.AsBinaryExpression()
		if binExpr != nil && (binExpr.OperatorToken.Kind == ast.KindAmpersandAmpersandToken ||
			binExpr.OperatorToken.Kind == ast.KindBarBarToken ||
			binExpr.OperatorToken.Kind == ast.KindQuestionQuestionToken ||
			binExpr.OperatorToken.Kind == ast.KindCommaToken) {
			return isBooleanConstructorContext(parent)
		}
	case ast.KindConditionalExpression:
		return isBooleanConstructorContext(parent)
	}

	return false
}

// isMixedLogicalExpression checks if a logical expression is mixed with && operators
func isMixedLogicalExpression(node *ast.Node) bool {
	seen := make(map[*ast.Node]bool)
	queue := []*ast.Node{node}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == nil || seen[current] {
			continue
		}
		seen[current] = true

		if current.Kind == ast.KindBinaryExpression {
			binExpr := current.AsBinaryExpression()
			if binExpr != nil {
				if binExpr.OperatorToken.Kind == ast.KindAmpersandAmpersandToken {
					return true
				}
				if binExpr.OperatorToken.Kind == ast.KindBarBarToken {
					queue = append(queue, current.Parent, binExpr.Left, binExpr.Right)
				}
			}
		}
	}

	return false
}

func logicalOperatorRange(sourceFile *ast.SourceFile, binExpr *ast.BinaryExpression) core.TextRange {
	if sourceFile == nil || binExpr == nil || binExpr.Left == nil || binExpr.Right == nil {
		if binExpr != nil {
			return binExpr.OperatorToken.Loc
		}
		return core.NewTextRange(0, 0)
	}

	operatorText := "||"
	if binExpr.OperatorToken.Kind == ast.KindBarBarEqualsToken {
		operatorText = "||="
	}

	start := binExpr.Left.End()
	end := binExpr.Right.Pos()
	text := sourceFile.Text()
	if start < 0 || end > len(text) || start >= end {
		return binExpr.OperatorToken.Loc
	}
	segment := text[start:end]
	index := strings.Index(segment, operatorText)
	if index < 0 {
		return binExpr.OperatorToken.Loc
	}
	return core.NewTextRange(start+index, start+index+len(operatorText))
}

// getNodeText extracts the text corresponding to a node from the given source file.
//
// Safety mechanisms:
// - Checks if either sourceFile or node is nil, returning an empty string if so.
// - Retrieves the start and end positions of the node and ensures they are within the bounds of the source text.
// - If the start position is negative, the end position exceeds the length of the text, or start > end, returns an empty string.
// - Only returns the substring if all checks pass, preventing panics or out-of-bounds errors.
func getNodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	text := sourceFile.Text()
	nodeRange := utils.TrimNodeTextRange(sourceFile, node)
	start := nodeRange.Pos()
	end := nodeRange.End()
	if start < 0 || end > len(text) || start > end {
		return ""
	}
	return text[start:end]
}

// needsParentheses checks if an expression needs parentheses when used as the right operand of ??
func needsParentheses(node *ast.Node) bool {
	switch node.Kind {
	case ast.KindBinaryExpression:
		binExpr := node.AsBinaryExpression()
		if binExpr != nil {
			// Lower precedence operators need parentheses
			switch binExpr.OperatorToken.Kind {
			case ast.KindBarBarToken, ast.KindAmpersandAmpersandToken:
				return true
			}
		}
	case ast.KindConditionalExpression:
		return true
	}
	return false
}

// areNodesTextuallyEqual checks if two nodes have the same text content
func areNodesTextuallyEqual(sourceFile *ast.SourceFile, a, b *ast.Node) bool {
	if a == nil || b == nil {
		return false
	}
	if sourceFile == nil {
		return a.Pos() == b.Pos() && a.End() == b.End()
	}
	return strings.TrimSpace(getNodeText(sourceFile, a)) == strings.TrimSpace(getNodeText(sourceFile, b))
}

var PreferNullishCoalescingRule = rule.CreateRule(rule.Rule{
	Name: "prefer-nullish-coalescing",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		// Check for strict null checks
		compilerOptions := ctx.Program.Options()
		isStrictNullChecks := utils.IsStrictCompilerOptionEnabled(
			compilerOptions,
			compilerOptions.StrictNullChecks,
		)

		if !isStrictNullChecks && !*opts.AllowRuleToRunWithoutStrictNullChecksIKnowWhatIAmDoing {
			ctx.ReportRange(core.NewTextRange(0, 0), buildNoStrictNullCheckMessage())
			return rule.RuleListeners{}
		}

		return rule.RuleListeners{
			// Handle logical OR expressions: a || b
			ast.KindBinaryExpression: func(node *ast.Node) {
				binExpr := node.AsBinaryExpression()
				if binExpr == nil {
					return
				}

				// Handle logical OR expressions: a || b
				if binExpr.OperatorToken.Kind == ast.KindBarBarToken {
					// Check if left operand is eligible for nullish coalescing
					leftType := ctx.TypeChecker.GetTypeAtLocation(binExpr.Left)
					if !isTypeEligibleForPreferNullish(leftType, opts) {
						return
					}

					// Check various ignore conditions
					if *opts.IgnoreConditionalTests && isConditionalTest(node) {
						return
					}

					if *opts.IgnoreBooleanCoercion && isBooleanConstructorContext(node) {
						return
					}

					if *opts.IgnoreMixedLogicalExpressions && isMixedLogicalExpression(node) {
						return
					}

					// Create fix suggestion
					leftText := strings.TrimSpace(getNodeText(ctx.SourceFile, binExpr.Left))
					rightText := strings.TrimSpace(getNodeText(ctx.SourceFile, binExpr.Right))

					var fixedRightText string
					if needsParentheses(binExpr.Right) {
						fixedRightText = fmt.Sprintf("(%s)", rightText)
					} else {
						fixedRightText = rightText
					}

					replacement := fmt.Sprintf("%s ?? %s", leftText, fixedRightText)

					// Check if the entire expression needs parentheses
					if node.Parent != nil && node.Parent.Kind == ast.KindBinaryExpression {
						parentBinExpr := node.Parent.AsBinaryExpression()
						if parentBinExpr != nil && parentBinExpr.OperatorToken.Kind == ast.KindAmpersandAmpersandToken {
							replacement = fmt.Sprintf("(%s)", replacement)
						}
					}

					ctx.ReportRangeWithSuggestions(
						logicalOperatorRange(ctx.SourceFile, binExpr),
						buildPreferNullishOverOrMessage(),
						rule.RuleSuggestion{
							Message:  buildSuggestNullishMessage(),
							FixesArr: []rule.RuleFix{rule.RuleFixReplace(ctx.SourceFile, node, replacement)},
						},
					)
					return
				}

				// Handle logical OR assignment expressions: a ||= b
				if binExpr.OperatorToken.Kind == ast.KindBarBarEqualsToken {
					// Check if left operand is eligible for nullish coalescing
					leftType := ctx.TypeChecker.GetTypeAtLocation(binExpr.Left)
					if !isTypeEligibleForPreferNullish(leftType, opts) {
						return
					}

					// Check various ignore conditions
					if *opts.IgnoreConditionalTests && isConditionalTest(node) {
						return
					}

					if *opts.IgnoreBooleanCoercion && isBooleanConstructorContext(node) {
						return
					}

					// Create fix suggestion
					leftText := strings.TrimSpace(getNodeText(ctx.SourceFile, binExpr.Left))
					rightText := strings.TrimSpace(getNodeText(ctx.SourceFile, binExpr.Right))
					replacement := fmt.Sprintf("%s ??= %s", leftText, rightText)

					ctx.ReportRangeWithSuggestions(
						logicalOperatorRange(ctx.SourceFile, binExpr),
						buildPreferNullishOverOrMessage(),
						rule.RuleSuggestion{
							Message:  buildSuggestNullishMessage(),
							FixesArr: []rule.RuleFix{rule.RuleFixReplace(ctx.SourceFile, node, replacement)},
						},
					)
				}
			},

			// Handle ternary expressions: a ? a : b
			ast.KindConditionalExpression: func(node *ast.Node) {
				if *opts.IgnoreTernaryTests {
					return
				}

				condExpr := node.AsConditionalExpression()
				if condExpr == nil {
					return
				}

				targetNode, nonNullishWhenTrue, ok := extractNullishTernaryInfo(ctx.SourceFile, condExpr.Condition)
				if !ok || targetNode == nil {
					return
				}

				nonNullishBranch := condExpr.WhenTrue
				nullishBranch := condExpr.WhenFalse
				if !nonNullishWhenTrue {
					nonNullishBranch = condExpr.WhenFalse
					nullishBranch = condExpr.WhenTrue
				}

				if !areNodesSemanticallySimilar(ctx.SourceFile, targetNode, nonNullishBranch) {
					return
				}

				conditionType := ctx.TypeChecker.GetTypeAtLocation(targetNode)
				kinds, hasNullishComparisons := collectNullishComparisonKinds(ctx.SourceFile, condExpr.Condition, targetNode)
				completeNullish := hasNullishComparisons && kinds.hasNull && kinds.hasUndefined
				if !completeNullish {
					if hasNullishComparisons {
						flags := checker.Type_flags(conditionType)
						if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown) != 0 {
							return
						}
						if kinds.hasUndefined && typeMayContainFlag(conditionType, checker.TypeFlagsNull) {
							return
						}
						if kinds.hasNull && typeMayContainFlag(conditionType, checker.TypeFlagsUndefined) {
							return
						}
					} else if !isTypeEligibleForPreferNullish(conditionType, opts) {
						return
					}
				}

				// Check various ignore conditions
				if *opts.IgnoreConditionalTests && isConditionalTest(node) {
					return
				}

				if *opts.IgnoreBooleanCoercion && isBooleanConstructorContext(node) {
					return
				}

				// Create fix suggestion
				conditionText := strings.TrimSpace(getNodeText(ctx.SourceFile, targetNode))
				alternateText := strings.TrimSpace(getNodeText(ctx.SourceFile, nullishBranch))

				var fixedAlternateText string
				if needsParentheses(nullishBranch) {
					fixedAlternateText = fmt.Sprintf("(%s)", alternateText)
				} else {
					fixedAlternateText = alternateText
				}

				replacement := fmt.Sprintf("%s ?? %s", conditionText, fixedAlternateText)

				ctx.ReportNodeWithSuggestions(node, buildPreferNullishOverTernaryMessage(),
					rule.RuleSuggestion{
						Message:  buildSuggestNullishMessage(),
						FixesArr: []rule.RuleFix{rule.RuleFixReplace(ctx.SourceFile, node, replacement)},
					},
				)
			},

			// Handle if statements: if (!a) a = b;
			ast.KindIfStatement: func(node *ast.Node) {
				if *opts.IgnoreIfStatements {
					return
				}

				ifStmt := node.AsIfStatement()
				if ifStmt == nil || ifStmt.ElseStatement != nil {
					return
				}

				// Check if the if statement body is a simple assignment
				var assignmentExpr *ast.BinaryExpression
				switch ifStmt.ThenStatement.Kind {
				case ast.KindBlock:
					block := ifStmt.ThenStatement.AsBlock()
					if block == nil || block.Statements == nil {
						return
					}
					for _, stmt := range block.Statements.Nodes {
						if stmt == nil {
							continue
						}
						if stmt.Kind == ast.KindEmptyStatement || stmt.Kind == ast.KindNotEmittedStatement {
							continue
						}
						if stmt.Kind != ast.KindExpressionStatement {
							return
						}
						exprStmt := stmt.AsExpressionStatement()
						if exprStmt == nil || exprStmt.Expression == nil {
							return
						}
						expr := unwrapParenthesized(exprStmt.Expression)
						if expr == nil || expr.Kind != ast.KindBinaryExpression {
							return
						}
						binExpr := expr.AsBinaryExpression()
						if binExpr != nil && (binExpr.OperatorToken.Kind == ast.KindEqualsToken ||
							binExpr.OperatorToken.Kind == ast.KindQuestionQuestionEqualsToken ||
							binExpr.OperatorToken.Kind == ast.KindBarBarEqualsToken) {
							if assignmentExpr != nil {
								return
							}
							assignmentExpr = binExpr
						} else {
							return
						}
					}
					if assignmentExpr == nil {
						return
					}
				case ast.KindExpressionStatement:
					exprStmt := ifStmt.ThenStatement.AsExpressionStatement()
					if exprStmt != nil && exprStmt.Expression != nil {
						expr := unwrapParenthesized(exprStmt.Expression)
						if expr == nil || expr.Kind != ast.KindBinaryExpression {
							return
						}
						binExpr := expr.AsBinaryExpression()
						if binExpr != nil && (binExpr.OperatorToken.Kind == ast.KindEqualsToken ||
							binExpr.OperatorToken.Kind == ast.KindQuestionQuestionEqualsToken ||
							binExpr.OperatorToken.Kind == ast.KindBarBarEqualsToken) {
							assignmentExpr = binExpr
						}
					}
				}

				if assignmentExpr == nil {
					return
				}
				assignmentLeft := unwrapParenthesized(assignmentExpr.Left)
				if assignmentLeft == nil || !isMemberAccessLike(assignmentLeft) {
					return
				}

				conditionTarget, nonNullishWhenTrue, ok := extractNullishTernaryInfo(ctx.SourceFile, ifStmt.Expression)
				if !ok || conditionTarget == nil || nonNullishWhenTrue {
					return
				}

				if !areNodesSemanticallySimilar(ctx.SourceFile, conditionTarget, assignmentLeft) {
					return
				}

				leftType := ctx.TypeChecker.GetTypeAtLocation(assignmentLeft)
				kinds, hasNullishComparisons := collectNullishComparisonKinds(ctx.SourceFile, ifStmt.Expression, conditionTarget)
				completeNullish := hasNullishComparisons && kinds.hasNull && kinds.hasUndefined
				if !completeNullish {
					if hasNullishComparisons {
						flags := checker.Type_flags(leftType)
						if flags&(checker.TypeFlagsAny|checker.TypeFlagsUnknown) != 0 {
							return
						}
						if kinds.hasUndefined && typeMayContainFlag(leftType, checker.TypeFlagsNull) {
							return
						}
						if kinds.hasNull && typeMayContainFlag(leftType, checker.TypeFlagsUndefined) {
							return
						}
					} else if !isTypeEligibleForPreferNullish(leftType, opts) {
						return
					}
				}

				// Create fix suggestion
				leftText := strings.TrimSpace(getNodeText(ctx.SourceFile, assignmentLeft))
				rightText := strings.TrimSpace(getNodeText(ctx.SourceFile, assignmentExpr.Right))
				replacement := fmt.Sprintf("%s ??= %s;", leftText, rightText)

				ctx.ReportNodeWithSuggestions(node, buildPreferNullishOverAssignmentMessage(),
					rule.RuleSuggestion{
						Message:  buildSuggestNullishMessage(),
						FixesArr: []rule.RuleFix{rule.RuleFixReplace(ctx.SourceFile, node, replacement)},
					},
				)
			},
		}
	},
})
