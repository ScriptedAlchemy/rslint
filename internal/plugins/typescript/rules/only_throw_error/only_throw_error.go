package only_throw_error

import (
	"encoding/json"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type OnlyThrowErrorOptions struct {
	Allow                []utils.TypeOrValueSpecifier `json:"allow"`
	AllowInline          []string                     `json:"allowInline"`
	AllowRethrowing      *bool                        `json:"allowRethrowing"`
	AllowThrowingAny     *bool                        `json:"allowThrowingAny"`
	AllowThrowingUnknown *bool                        `json:"allowThrowingUnknown"`
}

func parseOptions(options any) OnlyThrowErrorOptions {
	opts := OnlyThrowErrorOptions{
		Allow:       []utils.TypeOrValueSpecifier{},
		AllowInline: []string{},
	}

	applyJSON := func(raw any) {
		if raw == nil {
			return
		}
		rawJSON, err := json.Marshal(raw)
		if err != nil {
			return
		}
		_ = json.Unmarshal(rawJSON, &opts)
	}

	switch raw := options.(type) {
	case OnlyThrowErrorOptions:
		opts = raw
	case *OnlyThrowErrorOptions:
		if raw != nil {
			opts = *raw
		}
	case map[string]interface{}:
		applyJSON(raw)
	case []interface{}:
		if len(raw) > 0 {
			applyJSON(raw[0])
		}
	}

	if opts.Allow == nil {
		opts.Allow = []utils.TypeOrValueSpecifier{}
	}
	if opts.AllowInline == nil {
		opts.AllowInline = []string{}
	}
	if opts.AllowRethrowing == nil {
		opts.AllowRethrowing = utils.Ref(true)
	}
	if opts.AllowThrowingAny == nil {
		opts.AllowThrowingAny = utils.Ref(true)
	}
	if opts.AllowThrowingUnknown == nil {
		opts.AllowThrowingUnknown = utils.Ref(true)
	}

	return opts
}

func buildObjectMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "object",
		Description: "Expected an error object to be thrown.",
	}
}
func buildUndefMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "undef",
		Description: "Do not throw undefined.",
	}
}

var OnlyThrowErrorRule = rule.CreateRule(rule.Rule{
	Name: "only-throw-error",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		containsNode := func(target *ast.Node, needle *ast.Node) bool {
			if target == nil || needle == nil {
				return false
			}
			for current := needle; current != nil; current = current.Parent {
				if current == target {
					return true
				}
			}
			return false
		}

		unwrapToCallExpression := func(node *ast.Node) *ast.CallExpression {
			current := node
			for current != nil && ast.IsParenthesizedExpression(current) {
				current = current.Parent
			}
			if current == nil || !ast.IsCallExpression(current) {
				return nil
			}
			return current.AsCallExpression()
		}

		getHandlerByMethod := func(callExpr *ast.CallExpression, methodName string) *ast.Node {
			if callExpr == nil {
				return nil
			}
			args := callExpr.Arguments.Nodes
			switch methodName {
			case "catch":
				if len(args) == 0 || ast.IsSpreadElement(args[0]) {
					return nil
				}
				return args[0]
			case "then":
				if len(args) < 2 || ast.IsSpreadElement(args[0]) || ast.IsSpreadElement(args[1]) {
					return nil
				}
				return args[1]
			default:
				return nil
			}
		}

		isRethrownError := func(node *ast.Node) bool {
			if node == nil || !ast.IsIdentifier(node) {
				return false
			}
			symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
			if symbol == nil {
				return false
			}

			declaration := symbol.ValueDeclaration
			if declaration == nil && len(symbol.Declarations) > 0 {
				declaration = symbol.Declarations[0]
			}
			if declaration == nil {
				return false
			}

			// try/catch rethrow
			for current := declaration; current != nil; current = current.Parent {
				if current.Kind != ast.KindCatchClause {
					continue
				}
				catchClause := current.AsCatchClause()
				if catchClause == nil || catchClause.VariableDeclaration == nil {
					return false
				}
				return containsNode(catchClause.VariableDeclaration, declaration)
			}

			paramNode := declaration
			if ast.IsIdentifier(declaration) && declaration.Parent != nil && ast.IsParameter(declaration.Parent) {
				paramNode = declaration.Parent
			}
			if !ast.IsParameter(paramNode) {
				return false
			}
			paramDecl := paramNode.AsParameterDeclaration()
			if paramDecl == nil || paramDecl.DotDotDotToken != nil || paramDecl.Name() == nil || !ast.IsIdentifier(paramDecl.Name()) {
				return false
			}
			if paramDecl.Name().AsIdentifier().Text != node.AsIdentifier().Text {
				return false
			}

			callback := paramNode.Parent
			if callback == nil || (!ast.IsFunctionExpression(callback) && !ast.IsArrowFunction(callback)) {
				return false
			}
			params := callback.Parameters()
			if len(params) == 0 || params[0] != paramNode {
				return false
			}

			callExpr := unwrapToCallExpression(callback.Parent)
			if callExpr == nil {
				return false
			}
			callee := ast.SkipParentheses(callExpr.Expression)
			if !ast.IsAccessExpression(callee) {
				return false
			}
			methodName, ok := checker.Checker_getAccessedPropertyName(ctx.TypeChecker, callee)
			if !ok {
				return false
			}
			onRejected := getHandlerByMethod(callExpr, methodName)
			if onRejected != callback {
				return false
			}

			return utils.IsThenableType(ctx.TypeChecker, callee.Expression(), nil)
		}

		return rule.RuleListeners{
			ast.KindThrowStatement: func(node *ast.Node) {
				expr := node.Expression()
				// TODO(port): why do we ignore await and yield here??
				// if (
				//   node.type === AST_NODE_TYPES.AwaitExpression ||
				//   node.type === AST_NODE_TYPES.YieldExpression
				// ) {
				//   return;
				// }
				if *opts.AllowRethrowing && isRethrownError(expr) {
					return
				}

				t := ctx.TypeChecker.GetTypeAtLocation(expr)

				if utils.TypeMatchesSomeSpecifier(t, opts.Allow, opts.AllowInline, ctx.Program) {
					return
				}

				if utils.IsTypeFlagSet(t, checker.TypeFlagsUndefined) {
					ctx.ReportNode(expr, buildUndefMessage())
					return
				}

				if *opts.AllowThrowingAny && utils.IsTypeAnyType(t) {
					return
				}

				if *opts.AllowThrowingUnknown && utils.IsTypeUnknownType(t) {
					return
				}

				if utils.IsErrorLike(ctx.Program, ctx.TypeChecker, t) {
					return
				}

				ctx.ReportNode(expr, buildObjectMessage())
			},
		}
	},
})
