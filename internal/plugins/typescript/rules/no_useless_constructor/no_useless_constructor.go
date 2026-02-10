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

func buildRemoveConstructorMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "removeConstructor",
		Description: "Remove unnecessary constructor.",
	}
}

func hasModifier(node *ast.Node, flags ast.ModifierFlags) bool {
	return ast.GetCombinedModifierFlags(node)&flags != 0
}

func hasParameterPropertyOrDecorator(params []*ast.Node) bool {
	for _, p := range params {
		if p == nil || !ast.IsParameter(p) {
			continue
		}
		if hasModifier(p, ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly|ast.ModifierFlagsDecorator) {
			return true
		}
	}
	return false
}

func isSimpleIdentifierParameter(param *ast.Node) (string, bool, bool) {
	if param == nil || !ast.IsParameter(param) {
		return "", false, false
	}
	p := param.AsParameterDeclaration()
	if p == nil || p.Name() == nil || !ast.IsIdentifier(p.Name()) {
		return "", false, false
	}
	if p.Initializer != nil {
		return "", false, false
	}
	name := p.Name().AsIdentifier().Text
	return name, p.DotDotDotToken != nil, true
}

func isUselessForwardingSuper(constructor *ast.ConstructorDeclaration) bool {
	if constructor == nil || constructor.Body == nil {
		return false
	}

	statements := constructor.Body.Statements()
	if len(statements) != 1 {
		return false
	}
	if statements[0].Kind != ast.KindExpressionStatement {
		return false
	}
	exprStmt := statements[0].AsExpressionStatement()
	if exprStmt == nil || exprStmt.Expression == nil || exprStmt.Expression.Kind != ast.KindCallExpression {
		return false
	}
	call := exprStmt.Expression.AsCallExpression()
	if call == nil || call.Expression == nil || call.Expression.Kind != ast.KindSuperKeyword {
		return false
	}

	params := constructor.Parameters.Nodes
	args := []*ast.Node{}
	if call.Arguments != nil {
		args = call.Arguments.Nodes
	}

	// constructor(a, b, ...c) { super(...arguments); }
	if len(args) == 1 && args[0].Kind == ast.KindSpreadElement {
		spread := args[0].AsSpreadElement()
		if spread != nil && spread.Expression != nil && spread.Expression.Kind == ast.KindIdentifier && spread.Expression.AsIdentifier().Text == "arguments" {
			// only considered useless when all parameters are simple identifiers
			for _, param := range params {
				_, _, ok := isSimpleIdentifierParameter(param)
				if !ok {
					return false
				}
			}
			return true
		}
	}

	if len(args) != len(params) {
		return false
	}

	for i, param := range params {
		name, isRest, ok := isSimpleIdentifierParameter(param)
		if !ok {
			return false
		}
		arg := args[i]
		if isRest {
			if i != len(params)-1 || arg.Kind != ast.KindSpreadElement {
				return false
			}
			spread := arg.AsSpreadElement()
			if spread == nil || spread.Expression == nil || spread.Expression.Kind != ast.KindIdentifier || spread.Expression.AsIdentifier().Text != name {
				return false
			}
			continue
		}
		if arg.Kind != ast.KindIdentifier || arg.AsIdentifier().Text != name {
			return false
		}
	}

	return true
}

func hasSuperClass(classNode *ast.Node) bool {
	if classNode == nil {
		return false
	}
	clauses := utils.GetHeritageClauses(classNode)
	if clauses == nil {
		return false
	}
	for _, clause := range clauses.Nodes {
		h := clause.AsHeritageClause()
		if h != nil && h.Token == ast.KindExtendsKeyword && h.Types != nil && len(h.Types.Nodes) > 0 {
			return true
		}
	}
	return false
}

var NoUselessConstructorRule = rule.CreateRule(rule.Rule{
	Name: "no-useless-constructor",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindConstructor: func(node *ast.Node) {
				constructor := node.AsConstructorDeclaration()
				if constructor == nil || constructor.Body == nil {
					return
				}

				if hasModifier(node, ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected) {
					return
				}

				parent := node.Parent
				derived := hasSuperClass(parent)

				// public constructor in derived class is not reported
				if derived && hasModifier(node, ast.ModifierFlagsPublic) {
					return
				}

				params := constructor.Parameters.Nodes
				if hasParameterPropertyOrDecorator(params) {
					return
				}

				useless := false
				if derived {
					useless = isUselessForwardingSuper(constructor)
				} else {
					useless = len(constructor.Body.Statements()) == 0
				}

				if !useless {
					return
				}

				ctx.ReportNode(node, buildNoUselessConstructorMessage())
			},
		}
	},
})
