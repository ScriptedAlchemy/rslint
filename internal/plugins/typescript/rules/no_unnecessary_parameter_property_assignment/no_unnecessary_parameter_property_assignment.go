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
	param := paramNode.AsParameterDeclaration()
	if param == nil || param.Modifiers() == nil {
		return false
	}
	for _, mod := range param.Modifiers().Nodes {
		if mod.Kind == ast.KindPublicKeyword || mod.Kind == ast.KindPrivateKeyword || mod.Kind == ast.KindProtectedKeyword || mod.Kind == ast.KindReadonlyKeyword {
			return true
		}
	}
	return false
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

func rhsReferencesParameterProperty(ctx rule.RuleContext, rhs *ast.Node, parameterDecl *ast.Node) bool {
	if rhs == nil || parameterDecl == nil {
		return false
	}
	if ctx.TypeChecker == nil {
		return true
	}
	symbol := ctx.TypeChecker.GetSymbolAtLocation(rhs)
	if symbol == nil {
		return false
	}
	for _, decl := range symbol.Declarations {
		if decl == parameterDecl {
			return true
		}
	}
	return false
}

func classMemberNodes(classNode *ast.Node) []*ast.Node {
	if classNode == nil {
		return nil
	}
	switch classNode.Kind {
	case ast.KindClassDeclaration:
		classDecl := classNode.AsClassDeclaration()
		if classDecl != nil && classDecl.Members != nil {
			return classDecl.Members.Nodes
		}
	case ast.KindClassExpression:
		classExpr := classNode.AsClassExpression()
		if classExpr != nil && classExpr.Members != nil {
			return classExpr.Members.Nodes
		}
	}
	return nil
}

func visitEagerlyExecutedNode(
	node *ast.Node,
	allowFunctionBody bool,
	onBinary func(*ast.BinaryExpression),
	onMutation func(string),
) {
	if node == nil {
		return
	}
	if isFunctionLike(node) && !allowFunctionBody {
		return
	}
	if (node.Kind == ast.KindClassDeclaration || node.Kind == ast.KindClassExpression) && !allowFunctionBody {
		return
	}

	switch node.Kind {
	case ast.KindBinaryExpression:
		bin := node.AsBinaryExpression()
		if bin != nil {
			if onBinary != nil {
				onBinary(bin)
			}
			if onMutation != nil && ast.IsAssignmentOperator(bin.OperatorToken.Kind) {
				if name, ok := getAssignmentTargetName(bin.Left); ok {
					onMutation(name)
				}
			}
		}
	case ast.KindPrefixUnaryExpression:
		unary := node.AsPrefixUnaryExpression()
		if unary != nil && onMutation != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken || unary.Operator == ast.KindDeleteKeyword) {
			if name, ok := getAssignmentTargetName(unary.Operand); ok {
				onMutation(name)
			}
		}
	case ast.KindPostfixUnaryExpression:
		unary := node.AsPostfixUnaryExpression()
		if unary != nil && onMutation != nil && (unary.Operator == ast.KindPlusPlusToken || unary.Operator == ast.KindMinusMinusToken) {
			if name, ok := getAssignmentTargetName(unary.Operand); ok {
				onMutation(name)
			}
		}
	case ast.KindDeleteExpression:
		del := node.AsDeleteExpression()
		if del != nil && onMutation != nil {
			if name, ok := getAssignmentTargetName(del.Expression); ok {
				onMutation(name)
			}
		}
	case ast.KindCallExpression:
		call := node.AsCallExpression()
		if call != nil {
			callee := unwrapRightExpression(call.Expression)
			if isFunctionLike(callee) {
				visitEagerlyExecutedNode(callee, true, onBinary, onMutation)
			}
			if call.Arguments != nil {
				for _, arg := range call.Arguments.Nodes {
					visitEagerlyExecutedNode(arg, false, onBinary, onMutation)
				}
			}
			return
		}
	}

	node.ForEachChild(func(child *ast.Node) bool {
		visitEagerlyExecutedNode(child, false, onBinary, onMutation)
		return false
	})
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
					parameterProps[name] = p
				}
				if len(parameterProps) == 0 {
					return
				}

				mutated := map[string]bool{}

				// Instance field initializers run before constructor body and can
				// make the direct re-assignment necessary.
				for _, member := range classMemberNodes(node.Parent) {
					if member == nil || member.Kind != ast.KindPropertyDeclaration || ast.HasSyntacticModifier(member, ast.ModifierFlagsStatic) {
						continue
					}
					prop := member.AsPropertyDeclaration()
					if prop == nil || prop.Initializer == nil {
						continue
					}
					visitEagerlyExecutedNode(prop.Initializer, false, nil, func(name string) {
						if _, ok := parameterProps[name]; ok {
							mutated[name] = true
						}
					})
				}

				for _, stmt := range constructor.Body.Statements() {
					visitEagerlyExecutedNode(stmt, false, func(bin *ast.BinaryExpression) {
						if bin == nil || !isLogicalOrSimpleAssignOperator(bin.OperatorToken.Kind) {
							return
						}
						targetName, ok := getAssignmentTargetName(bin.Left)
						if !ok {
							return
						}
						paramDeclNode, isParamProp := parameterProps[targetName]
						if !isParamProp {
							return
						}
						right := unwrapRightExpression(bin.Right)
						if right == nil || right.Kind != ast.KindIdentifier || right.AsIdentifier().Text != targetName {
							return
						}
						if !rhsReferencesParameterProperty(ctx, right, paramDeclNode) {
							return
						}
						if mutated[targetName] {
							return
						}
						ctx.ReportNode(bin.AsNode(), buildUnnecessaryAssignMessage())
					}, func(name string) {
						if _, ok := parameterProps[name]; ok {
							mutated[name] = true
						}
					})
				}
			},
		}
	},
})
