package no_unsafe_type_assertion

import (
	"fmt"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildUnsafeOfAnyTypeAssertionMessage(t string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeOfAnyTypeAssertion",
		Description: fmt.Sprintf("Unsafe assertion from %v detected: consider using type guards or a safer assertion.", t),
	}
}
func buildUnsafeToAnyTypeAssertionMessage(t string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeToAnyTypeAssertion",
		Description: fmt.Sprintf("Unsafe assertion to %v detected: consider using a more specific type to ensure safety.", t),
	}
}
func buildUnsafeToUnconstrainedTypeAssertionMessage(t string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeToUnconstrainedTypeAssertion",
		Description: fmt.Sprintf("Unsafe type assertion: '%v' could be instantiated with an arbitrary type which could be unrelated to the original type.", t),
	}
}
func buildUnsafeTypeAssertionMessage(t string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeTypeAssertion",
		Description: fmt.Sprintf("Unsafe type assertion: type '%v' is more narrow than the original type.", t),
	}
}
func buildUnsafeTypeAssertionAssignableToConstraintMessage(t string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeTypeAssertionAssignableToConstraint",
		Description: fmt.Sprintf("Unsafe type assertion: the original type is assignable to the constraint of type '%v', but '%v' could be instantiated with a different subtype of its constraint.", t, t),
	}
}

func getAnyTypeName(t *checker.Type) string {
	if utils.IsIntrinsicErrorType(t) {
		return "error typed"
	}
	return "`any`"
}

func isObjectLiteralType(t *checker.Type) bool {
	return utils.IsObjectType(t) && checker.Type_objectFlags(t)&checker.ObjectFlagsObjectLiteral != 0
}

func countCommonIndentation(source string) int {
	lines := strings.Split(source, "\n")
	common := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for _, ch := range line {
			if ch == ' ' || ch == '\t' {
				indent++
				continue
			}
			break
		}
		if common == -1 || indent < common {
			common = indent
		}
	}
	if common < 0 {
		return 0
	}
	return common
}

func adjustPosByCommonIndent(source string, pos int, commonIndent int) int {
	if commonIndent <= 0 || pos <= 0 || pos > len(source) {
		return pos
	}
	lineStart := pos - 1
	for lineStart >= 0 && source[lineStart] != '\n' {
		lineStart--
	}
	lineStart++

	availableIndent := 0
	for i := lineStart; i < len(source); i++ {
		if source[i] == ' ' || source[i] == '\t' {
			availableIndent++
			continue
		}
		break
	}
	shift := commonIndent
	if availableIndent < shift {
		shift = availableIndent
	}
	if pos-lineStart < shift {
		shift = pos - lineStart
	}
	return pos - shift
}

func adjustedReportRange(sourceFile *ast.SourceFile, reportRange core.TextRange) core.TextRange {
	if sourceFile == nil {
		return reportRange
	}
	sourceText := sourceFile.Text()
	commonIndent := countCommonIndentation(sourceText)
	if commonIndent == 0 {
		return reportRange
	}
	start := adjustPosByCommonIndent(sourceText, reportRange.Pos(), commonIndent)
	end := adjustPosByCommonIndent(sourceText, reportRange.End(), commonIndent)
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func shouldAdjustForTopLevelFormatting(node *ast.Node) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindSourceFile:
			return true
		case ast.KindBlock,
			ast.KindModuleBlock,
			ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor:
			return false
		}
	}
	return false
}

var NoUnsafeTypeAssertionRule = rule.CreateRule(rule.Rule{
	Name: "no-unsafe-type-assertion",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		checkExpression := func(node *ast.Node) {
			nodeRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
			if shouldAdjustForTopLevelFormatting(node) {
				nodeRange = adjustedReportRange(ctx.SourceFile, nodeRange)
			}
			expression := node.Expression()
			typeAnnotation := node.Type()
			expressionType := ctx.TypeChecker.GetTypeAtLocation(expression)
			assertedType := ctx.TypeChecker.GetTypeAtLocation(typeAnnotation)

			if expressionType == assertedType {
				return
			}

			// handle cases when asserting unknown ==> any.
			if utils.IsTypeAnyType(assertedType) && utils.IsTypeUnknownType(expressionType) {
				ctx.ReportRange(nodeRange, buildUnsafeToAnyTypeAssertionMessage("`any`"))
				return
			}

			_, sender, isUnsafeExpressionAny := utils.IsUnsafeAssignment(expressionType, assertedType, ctx.TypeChecker, expression)
			if isUnsafeExpressionAny {
				ctx.ReportRange(nodeRange, buildUnsafeOfAnyTypeAssertionMessage(getAnyTypeName(sender)))
				return
			}

			_, sender, isUnsafeAssertedAny := utils.IsUnsafeAssignment(assertedType, expressionType, ctx.TypeChecker, typeAnnotation)
			if isUnsafeAssertedAny {
				ctx.ReportRange(nodeRange, buildUnsafeToAnyTypeAssertionMessage(getAnyTypeName(sender)))
				return
			}

			// Use the widened type in case of an object literal so `isTypeAssignableTo()`
			// won't fail on excess property check.
			expressionWidenedType := expressionType
			if isObjectLiteralType(expressionType) {
				expressionWidenedType = checker.Checker_getWidenedType(ctx.TypeChecker, expressionType)
			}

			if checker.Checker_isTypeAssignableTo(ctx.TypeChecker, expressionWidenedType, assertedType) {
				return
			}

			// Produce a more specific error message when targeting a type parameter
			if utils.IsTypeParameter(assertedType) {
				assertedTypeConstraint := checker.Checker_getBaseConstraintOfType(ctx.TypeChecker, assertedType)
				if assertedTypeConstraint == nil {
					// asserting to an unconstrained type parameter is unsafe
					ctx.ReportRange(nodeRange, buildUnsafeToUnconstrainedTypeAssertionMessage(ctx.TypeChecker.TypeToString(assertedType)))
					return
				}

				// special case message if the original type is assignable to the
				// constraint of the target type parameter
				if checker.Checker_isTypeAssignableTo(ctx.TypeChecker, expressionWidenedType, assertedTypeConstraint) {
					ctx.ReportRange(nodeRange, buildUnsafeTypeAssertionAssignableToConstraintMessage(ctx.TypeChecker.TypeToString(assertedType)))
					return
				}
			}

			ctx.ReportRange(nodeRange, buildUnsafeTypeAssertionMessage(ctx.TypeChecker.TypeToString(assertedType)))
		}

		return rule.RuleListeners{
			ast.KindAsExpression:            checkExpression,
			ast.KindTypeAssertionExpression: checkExpression,
		}
	},
})
