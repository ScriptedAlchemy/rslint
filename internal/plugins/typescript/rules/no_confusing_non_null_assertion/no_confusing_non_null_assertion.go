package no_confusing_non_null_assertion

import (
	"fmt"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildConfusingEqualMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "confusingEqual",
		Description: "Non-null assertions in equality comparisons are confusing.",
	}
}

func buildConfusingAssignMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "confusingAssign",
		Description: "Non-null assertions in assignments are confusing.",
	}
}

func buildConfusingOperatorMessage(operator string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "confusingOperator",
		Description: fmt.Sprintf("Non-null assertions with the %s operator are confusing.", operator),
	}
}

func buildNotNeedInEqualTestMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "notNeedInEqualTest",
		Description: "Remove the non-null assertion from the equality comparison.",
	}
}

func buildNotNeedInAssignMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "notNeedInAssign",
		Description: "Remove the non-null assertion from the assignment target.",
	}
}

func buildNotNeedInOperatorMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "notNeedInOperator",
		Description: "Remove the non-null assertion from the left-hand side.",
	}
}

func buildWrapLeftMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "wrapUpLeft",
		Description: "Wrap the left-hand side in parentheses to make the assertion explicit.",
	}
}

func unwrapParentheses(node *ast.Node) *ast.Node {
	for node != nil && node.Kind == ast.KindParenthesizedExpression {
		node = node.AsParenthesizedExpression().Expression
	}
	return node
}

func trailingNonNullExpression(node *ast.Node) *ast.Node {
	node = unwrapParentheses(node)
	if node == nil {
		return nil
	}

	switch node.Kind {
	case ast.KindNonNullExpression:
		return node
	case ast.KindBinaryExpression:
		binary := node.AsBinaryExpression()
		if binary == nil {
			return nil
		}
		return trailingNonNullExpression(binary.Right)
	case ast.KindConditionalExpression:
		cond := node.AsConditionalExpression()
		if cond == nil {
			return nil
		}
		return trailingNonNullExpression(cond.WhenFalse)
	case ast.KindCommaListExpression:
		children := node.Children()
		if children != nil && len(children.Nodes) > 0 {
			return trailingNonNullExpression(children.Nodes[len(children.Nodes)-1])
		}
	}

	return nil
}

func buildRemoveNonNullFix(ctx rule.RuleContext, nonNullExpr *ast.Node) rule.RuleFix {
	expression := nonNullExpr.AsNonNullExpression().Expression
	scan := scanner.GetScannerForSourceFile(ctx.SourceFile, expression.End())
	return rule.RuleFixRemoveRange(scan.TokenRange())
}

func buildWrapLeftFixes(ctx rule.RuleContext, left *ast.Node) []rule.RuleFix {
	return []rule.RuleFix{
		rule.RuleFixInsertBefore(ctx.SourceFile, left, "("),
		rule.RuleFixInsertAfter(left, ")"),
	}
}

var NoConfusingNonNullAssertionRule = rule.CreateRule(rule.Rule{
	Name: "no-confusing-non-null-assertion",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindBinaryExpression: func(node *ast.Node) {
				binary := node.AsBinaryExpression()
				if binary == nil {
					return
				}

				operator := binary.OperatorToken.Kind
				switch operator {
				case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken, ast.KindEqualsToken, ast.KindInKeyword, ast.KindInstanceOfKeyword:
				default:
					return
				}

				left := binary.Left
				if left == nil || left.Kind == ast.KindParenthesizedExpression {
					return
				}

				trailingNonNull := trailingNonNullExpression(left)
				if trailingNonNull == nil {
					return
				}

				directNonNull := unwrapParentheses(left)
				isDirect := directNonNull != nil && directNonNull.Kind == ast.KindNonNullExpression

				switch operator {
				case ast.KindEqualsEqualsToken, ast.KindEqualsEqualsEqualsToken:
					if isDirect {
						ctx.ReportNodeWithSuggestions(left, buildConfusingEqualMessage(), rule.RuleSuggestion{
							Message:  buildNotNeedInEqualTestMessage(),
							FixesArr: []rule.RuleFix{buildRemoveNonNullFix(ctx, trailingNonNull)},
						})
						return
					}
					ctx.ReportNodeWithSuggestions(left, buildConfusingEqualMessage(), rule.RuleSuggestion{
						Message:  buildWrapLeftMessage(),
						FixesArr: buildWrapLeftFixes(ctx, left),
					})
				case ast.KindEqualsToken:
					if isDirect {
						ctx.ReportNodeWithSuggestions(left, buildConfusingAssignMessage(), rule.RuleSuggestion{
							Message:  buildNotNeedInAssignMessage(),
							FixesArr: []rule.RuleFix{buildRemoveNonNullFix(ctx, trailingNonNull)},
						})
						return
					}
					ctx.ReportNodeWithSuggestions(left, buildConfusingAssignMessage(), rule.RuleSuggestion{
						Message:  buildWrapLeftMessage(),
						FixesArr: buildWrapLeftFixes(ctx, left),
					})
				case ast.KindInKeyword:
					suggestions := []rule.RuleSuggestion{}
					if isDirect {
						suggestions = append(suggestions, rule.RuleSuggestion{
							Message:  buildNotNeedInOperatorMessage(),
							FixesArr: []rule.RuleFix{buildRemoveNonNullFix(ctx, trailingNonNull)},
						})
					}
					suggestions = append(suggestions, rule.RuleSuggestion{
						Message:  buildWrapLeftMessage(),
						FixesArr: buildWrapLeftFixes(ctx, left),
					})
					ctx.ReportNodeWithSuggestions(left, buildConfusingOperatorMessage("in"), suggestions...)
				case ast.KindInstanceOfKeyword:
					suggestions := []rule.RuleSuggestion{}
					if isDirect {
						suggestions = append(suggestions, rule.RuleSuggestion{
							Message:  buildNotNeedInOperatorMessage(),
							FixesArr: []rule.RuleFix{buildRemoveNonNullFix(ctx, trailingNonNull)},
						})
					}
					suggestions = append(suggestions, rule.RuleSuggestion{
						Message:  buildWrapLeftMessage(),
						FixesArr: buildWrapLeftFixes(ctx, left),
					})
					ctx.ReportNodeWithSuggestions(left, buildConfusingOperatorMessage("instanceof"), suggestions...)
				}
			},
		}
	},
})
