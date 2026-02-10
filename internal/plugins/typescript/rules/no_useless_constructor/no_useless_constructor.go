package no_useless_constructor

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildNoUselessConstructorMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noUselessConstructor",
		Description: "Useless constructor.",
	}
}

func hasExtendsClause(classLike *ast.Node) bool {
	if classLike == nil {
		return false
	}
	clauses := utils.GetHeritageClauses(classLike)
	if clauses == nil {
		return false
	}
	for _, clauseNode := range clauses.Nodes {
		clause := clauseNode.AsHeritageClause()
		if clause != nil && clause.Token == ast.KindExtendsKeyword && clause.Types != nil && len(clause.Types.Nodes) > 0 {
			return true
		}
	}
	return false
}

func hasParameterPropertiesOrDecorators(params []*ast.Node) bool {
	for _, p := range params {
		param := p.AsParameterDeclaration()
		if param == nil {
			continue
		}
		if ast.GetCombinedModifierFlags(p)&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0 {
			return true
		}
		if param.Modifiers() != nil {
			for _, m := range param.Modifiers().Nodes {
				if m.Kind == ast.KindDecorator {
					return true
				}
			}
		}
	}
	return false
}

func isSuperCallStatement(stmt *ast.Node) *ast.CallExpression {
	if stmt == nil || stmt.Kind != ast.KindExpressionStatement {
		return nil
	}
	exprStmt := stmt.AsExpressionStatement()
	if exprStmt == nil || exprStmt.Expression == nil {
		return nil
	}
	expr := ast.SkipParentheses(exprStmt.Expression)
	if expr == nil || expr.Kind != ast.KindCallExpression {
		return nil
	}
	call := expr.AsCallExpression()
	if call == nil || call.Expression == nil {
		return nil
	}
	callee := ast.SkipParentheses(call.Expression)
	if callee == nil || callee.Kind != ast.KindSuperKeyword {
		return nil
	}
	return call
}

func parameterInfo(paramNode *ast.Node) (name string, isRest bool, simple bool) {
	param := paramNode.AsParameterDeclaration()
	if param == nil {
		return "", false, false
	}
	isRest = param.DotDotDotToken != nil
	if param.Initializer != nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
		return "", isRest, false
	}
	return param.Name().AsIdentifier().Text, isRest, true
}

func isSpreadArguments(arg *ast.Node) bool {
	if arg == nil || arg.Kind != ast.KindSpreadElement {
		return false
	}
	spread := arg.AsSpreadElement()
	if spread == nil || spread.Expression == nil {
		return false
	}
	expr := ast.SkipParentheses(spread.Expression)
	return expr != nil && expr.Kind == ast.KindIdentifier && expr.AsIdentifier().Text == "arguments"
}

func isUselessDerivedConstructor(params []*ast.Node, call *ast.CallExpression) bool {
	if call == nil || call.Arguments == nil {
		return false
	}
	args := call.Arguments.Nodes

	// super(...arguments) is only useless when all params are simple identifiers.
	if len(args) == 1 && isSpreadArguments(args[0]) {
		for _, p := range params {
			_, _, simple := parameterInfo(p)
			if !simple {
				return false
			}
		}
		return true
	}

	if len(params) != len(args) {
		return false
	}

	for i, p := range params {
		name, isRest, simple := parameterInfo(p)
		if !simple {
			return false
		}
		arg := ast.SkipParentheses(args[i])
		if isRest {
			if arg == nil || arg.Kind != ast.KindSpreadElement {
				return false
			}
			spread := arg.AsSpreadElement()
			if spread == nil || spread.Expression == nil {
				return false
			}
			spreadExpr := ast.SkipParentheses(spread.Expression)
			if spreadExpr == nil || spreadExpr.Kind != ast.KindIdentifier || spreadExpr.AsIdentifier().Text != name {
				return false
			}
			continue
		}
		if arg == nil || arg.Kind != ast.KindIdentifier || arg.AsIdentifier().Text != name {
			return false
		}
	}
	return true
}

var NoUselessConstructorRule = rule.CreateRule(rule.Rule{
	Name: "no-useless-constructor",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		return rule.RuleListeners{
			ast.KindConstructor: func(node *ast.Node) {
				constructor := node.AsConstructorDeclaration()
				if constructor == nil || constructor.Body == nil {
					return
				}

				// Keep non-public constructors: they can intentionally restrict instantiation.
				if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) || ast.HasSyntacticModifier(node, ast.ModifierFlagsProtected) {
					return
				}

				params := []*ast.Node{}
				if constructor.Parameters != nil {
					params = constructor.Parameters.Nodes
				}
				if hasParameterPropertiesOrDecorators(params) {
					return
				}

				stmts := constructor.Body.Statements()
				classNode := node.Parent
				if !hasExtendsClause(classNode) {
					if len(stmts) == 0 {
						ctx.ReportNode(node, buildNoUselessConstructorMessage())
					}
					return
				}

				if len(stmts) != 1 {
					return
				}
				superCall := isSuperCallStatement(stmts[0])
				if !isUselessDerivedConstructor(params, superCall) {
					return
				}
				ctx.ReportNode(node, buildNoUselessConstructorMessage())
			},
		}
	},
})
