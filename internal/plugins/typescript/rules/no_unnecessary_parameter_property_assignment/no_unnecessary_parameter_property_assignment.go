package no_unnecessary_parameter_property_assignment

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryAssignMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryAssign",
		Description: "This assignment is unnecessary because it matches a parameter property initialization.",
	}
}

func unwrapRightExpression(expr *ast.Node) *ast.Node {
	for expr != nil {
		switch expr.Kind {
		case ast.KindParenthesizedExpression:
			expr = expr.AsParenthesizedExpression().Expression
		case ast.KindAsExpression:
			expr = expr.AsAsExpression().Expression
		case ast.KindTypeAssertionExpression:
			expr = expr.AsTypeAssertion().Expression
		case ast.KindNonNullExpression:
			expr = expr.AsNonNullExpression().Expression
		case ast.KindSatisfiesExpression:
			expr = expr.AsSatisfiesExpression().Expression
		default:
			return expr
		}
	}
	return nil
}

func isParameterPropertyNode(paramNode *ast.Node) bool {
	if paramNode == nil || paramNode.Kind != ast.KindParameter {
		return false
	}
	flags := ast.GetCombinedModifierFlags(paramNode)
	return flags&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0
}

func getAssignmentTargetName(node *ast.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	switch node.Kind {
	case ast.KindPropertyAccessExpression:
		access := node.AsPropertyAccessExpression()
		if access == nil || access.Expression == nil || access.Expression.Kind != ast.KindThisKeyword || access.Name() == nil || access.Name().Kind != ast.KindIdentifier {
			return "", false
		}
		return access.Name().AsIdentifier().Text, true
	case ast.KindElementAccessExpression:
		access := node.AsElementAccessExpression()
		if access == nil || access.Expression == nil || access.Expression.Kind != ast.KindThisKeyword || access.ArgumentExpression == nil {
			return "", false
		}
		arg := access.ArgumentExpression
		if arg.Kind == ast.KindStringLiteral {
			return arg.AsStringLiteral().Text, true
		}
		return "", false
	default:
		return "", false
	}
}

func isFunctionLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindMethodDeclaration, ast.KindGetAccessor, ast.KindSetAccessor:
		return true
	default:
		return false
	}
}

func isLogicalOrSimpleAssignOperator(kind ast.Kind) bool {
	return kind == ast.KindEqualsToken ||
		kind == ast.KindAmpersandAmpersandEqualsToken ||
		kind == ast.KindBarBarEqualsToken ||
		kind == ast.KindQuestionQuestionEqualsToken
}

func symbolsMatch(ctx rule.RuleContext, a *ast.Node, b *ast.Node) bool {
	if ctx.TypeChecker == nil || a == nil || b == nil {
		return false
	}
	leftSym := ctx.TypeChecker.GetSymbolAtLocation(a)
	rightSym := ctx.TypeChecker.GetSymbolAtLocation(b)
	return leftSym != nil && rightSym != nil && leftSym == rightSym
}

var NoUnnecessaryParameterPropertyAssignmentRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-parameter-property-assignment",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		return rule.RuleListeners{
			ast.KindConstructor: func(node *ast.Node) {
				constructor := node.AsConstructorDeclaration()
				if constructor == nil || constructor.Body == nil || constructor.Parameters == nil {
					return
				}

				parameterProps := map[string]*ast.Node{}
				for _, p := range constructor.Parameters.Nodes {
					if !isParameterPropertyNode(p) {
						continue
					}
					param := p.AsParameterDeclaration()
					if param == nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
						continue
					}
					name := param.Name().AsIdentifier().Text
					parameterProps[name] = param.Name()
				}
				if len(parameterProps) == 0 {
					return
				}

				var visitNode func(current *ast.Node, allowFunctionBody bool)
				visitNode = func(current *ast.Node, allowFunctionBody bool) {
					if current == nil {
						return
					}
					if isFunctionLike(current) && !allowFunctionBody {
						return
					}

					if current.Kind == ast.KindBinaryExpression {
						bin := current.AsBinaryExpression()
						if bin != nil && isLogicalOrSimpleAssignOperator(bin.OperatorToken.Kind) {
							targetName, ok := getAssignmentTargetName(bin.Left)
							if ok {
								paramNameNode, isParamProp := parameterProps[targetName]
								if isParamProp {
									right := unwrapRightExpression(bin.Right)
									if right != nil && right.Kind == ast.KindIdentifier && right.AsIdentifier().Text == targetName {
										if symbolsMatch(ctx, paramNameNode, right) || ctx.TypeChecker == nil {
											ctx.ReportNode(current, buildUnnecessaryAssignMessage())
										}
									}
								}
							}
						}
					}

					if current.Kind == ast.KindCallExpression {
						call := current.AsCallExpression()
						if call != nil {
							callee := unwrapRightExpression(call.Expression)
							if isFunctionLike(callee) {
								visitNode(callee, true)
							}
							if call.Arguments != nil {
								for _, arg := range call.Arguments.Nodes {
									visitNode(arg, false)
								}
							}
							return
						}
					}

					current.ForEachChild(func(child *ast.Node) bool {
						visitNode(child, false)
						return false
					})
				}

				for _, stmt := range constructor.Body.Statements() {
					visitNode(stmt, false)
				}
			},
		}
	},
})
