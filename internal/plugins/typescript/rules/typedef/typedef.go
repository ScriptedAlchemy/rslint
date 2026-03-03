package typedef

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type TypedefOptions struct {
	ArrayDestructuring                bool `json:"arrayDestructuring"`
	ArrowParameter                    bool `json:"arrowParameter"`
	MemberVariableDeclaration         bool `json:"memberVariableDeclaration"`
	ObjectDestructuring               bool `json:"objectDestructuring"`
	Parameter                         bool `json:"parameter"`
	PropertyDeclaration               bool `json:"propertyDeclaration"`
	VariableDeclaration               bool `json:"variableDeclaration"`
	VariableDeclarationIgnoreFunction bool `json:"variableDeclarationIgnoreFunction"`
}

func parseOptions(options any) TypedefOptions {
	opts := TypedefOptions{
		ArrayDestructuring:                false,
		ArrowParameter:                    false,
		MemberVariableDeclaration:         false,
		ObjectDestructuring:               false,
		VariableDeclaration:               true,
		Parameter:                         false,
		PropertyDeclaration:               false,
		VariableDeclarationIgnoreFunction: false,
	}
	// upstream defaults all toggles to false
	opts.VariableDeclaration = false

	if options == nil {
		return opts
	}
	var optsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		optsMap, _ = arr[0].(map[string]interface{})
	} else {
		optsMap, _ = options.(map[string]interface{})
	}
	if optsMap == nil {
		return opts
	}
	if v, ok := optsMap["arrayDestructuring"].(bool); ok {
		opts.ArrayDestructuring = v
	}
	if v, ok := optsMap["arrowParameter"].(bool); ok {
		opts.ArrowParameter = v
	}
	if v, ok := optsMap["memberVariableDeclaration"].(bool); ok {
		opts.MemberVariableDeclaration = v
	}
	if v, ok := optsMap["objectDestructuring"].(bool); ok {
		opts.ObjectDestructuring = v
	}
	if v, ok := optsMap["variableDeclaration"].(bool); ok {
		opts.VariableDeclaration = v
	}
	if v, ok := optsMap["parameter"].(bool); ok {
		opts.Parameter = v
	}
	if v, ok := optsMap["propertyDeclaration"].(bool); ok {
		opts.PropertyDeclaration = v
	}
	if v, ok := optsMap["variableDeclarationIgnoreFunction"].(bool); ok {
		opts.VariableDeclarationIgnoreFunction = v
	}
	return opts
}

func buildExpectedTypedefMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "expectedTypedef",
		Description: "Expected a type annotation.",
	}
}

func buildExpectedTypedefNamedMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "expectedTypedefNamed",
		Description: "Expected " + name + " to have a type annotation.",
	}
}

func nodeName(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindIdentifier {
		return ""
	}
	return node.AsIdentifier().Text
}

func report(ctx rule.RuleContext, location *ast.Node, name string) {
	if name != "" {
		ctx.ReportNode(location, buildExpectedTypedefNamedMessage(name))
		return
	}
	ctx.ReportNode(location, buildExpectedTypedefMessage())
}

func isForOfStatementContext(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindVariableDeclaration, ast.KindVariableDeclarationList, ast.KindObjectBindingPattern, ast.KindArrayBindingPattern, ast.KindBindingElement:
			current = current.Parent
		case ast.KindForOfStatement:
			return true
		default:
			return false
		}
	}
	return false
}

func isForInOrForOfDeclaration(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindVariableDeclaration, ast.KindVariableDeclarationList:
			current = current.Parent
		case ast.KindForOfStatement, ast.KindForInStatement:
			return true
		default:
			return false
		}
	}
	return false
}

func isCatchClauseDeclaration(node *ast.Node) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindCatchClause {
			return true
		}
		if current.Kind == ast.KindSourceFile {
			return false
		}
	}
	return false
}

func isParameterPropertyNode(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return ast.HasSyntacticModifier(node, ast.ModifierFlagsPublic) ||
		ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) ||
		ast.HasSyntacticModifier(node, ast.ModifierFlagsProtected) ||
		ast.HasSyntacticModifier(node, ast.ModifierFlagsReadonly)
}

func isVariableDeclarationIgnoreFunction(node *ast.Node, opts TypedefOptions) bool {
	if !opts.VariableDeclarationIgnoreFunction || node == nil {
		return false
	}
	return node.Kind == ast.KindArrowFunction || node.Kind == ast.KindFunctionExpression
}

func isAncestorHasTypeAnnotation(node *ast.Node) bool {
	ancestor := node.Parent
	for ancestor != nil {
		if ancestor.Kind == ast.KindArrayBindingPattern || ancestor.Kind == ast.KindObjectBindingPattern {
			if ancestor.Type() != nil {
				return true
			}
		}
		if ancestor.Kind == ast.KindVariableDeclaration || ancestor.Kind == ast.KindParameter || ancestor.Kind == ast.KindBindingElement {
			if ancestor.Type() != nil {
				return true
			}
		}
		ancestor = ancestor.Parent
	}
	return false
}

func checkParameters(ctx rule.RuleContext, params *ast.NodeList) {
	if params == nil {
		return
	}
	for _, paramNode := range params.Nodes {
		if paramNode == nil || paramNode.Kind != ast.KindParameter {
			continue
		}
		param := paramNode.AsParameterDeclaration()
		if param == nil {
			continue
		}

		annotationTarget := param.Name()
		if annotationTarget == nil {
			continue
		}
		// parameters with initializer are still represented as ParameterDeclaration;
		// a missing param.Type means untyped regardless of default value.
		if param.Type != nil {
			continue
		}

		name := ""
		if annotationTarget.Kind == ast.KindIdentifier &&
			param.Initializer == nil &&
			param.DotDotDotToken == nil &&
			!isParameterPropertyNode(paramNode) {
			name = annotationTarget.AsIdentifier().Text
		}
		report(ctx, paramNode, name)
	}
}

var TypedefRule = rule.CreateRule(rule.Rule{
	Name: "typedef",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindArrayBindingPattern: func(node *ast.Node) {
				if !opts.ArrayDestructuring || node == nil {
					return
				}
				if isForOfStatementContext(node) || isAncestorHasTypeAnnotation(node) {
					return
				}
				report(ctx, node, "")
			},
			ast.KindObjectBindingPattern: func(node *ast.Node) {
				if !opts.ObjectDestructuring || node == nil {
					return
				}
				if isForOfStatementContext(node) || isAncestorHasTypeAnnotation(node) {
					return
				}
				report(ctx, node, "")
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				if !opts.ArrowParameter {
					return
				}
				arrow := node.AsArrowFunction()
				if arrow == nil {
					return
				}
				checkParameters(ctx, arrow.Parameters)
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				if !opts.MemberVariableDeclaration {
					return
				}
				property := node.AsPropertyDeclaration()
				if property == nil {
					return
				}
				if property.Initializer != nil && isVariableDeclarationIgnoreFunction(property.Initializer, opts) {
					return
				}
				if property.Type != nil {
					return
				}
				report(ctx, node, nodeName(property.Name()))
			},
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				if !opts.Parameter {
					return
				}
				fn := node.AsFunctionDeclaration()
				if fn == nil {
					return
				}
				checkParameters(ctx, fn.Parameters)
			},
			ast.KindFunctionExpression: func(node *ast.Node) {
				if !opts.Parameter {
					return
				}
				fn := node.AsFunctionExpression()
				if fn == nil {
					return
				}
				checkParameters(ctx, fn.Parameters)
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				if !opts.Parameter {
					return
				}
				method := node.AsMethodDeclaration()
				if method == nil {
					return
				}
				checkParameters(ctx, method.Parameters)
			},
			ast.KindConstructor: func(node *ast.Node) {
				if !opts.Parameter {
					return
				}
				constructor := node.AsConstructorDeclaration()
				if constructor == nil {
					return
				}
				checkParameters(ctx, constructor.Parameters)
			},
			ast.KindPropertySignature: func(node *ast.Node) {
				if !opts.PropertyDeclaration {
					return
				}
				property := node.AsPropertySignatureDeclaration()
				if property == nil || property.Type != nil {
					return
				}
				report(ctx, node, nodeName(property.Name()))
			},
			ast.KindIndexSignature: func(node *ast.Node) {
				if !opts.PropertyDeclaration {
					return
				}
				signature := node.AsIndexSignatureDeclaration()
				if signature == nil || signature.Type != nil {
					return
				}
				report(ctx, node, "")
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				if !opts.VariableDeclaration {
					return
				}
				decl := node.AsVariableDeclaration()
				if decl == nil || decl.Name() == nil || decl.Type != nil {
					return
				}
				if decl.Name().Kind == ast.KindArrayBindingPattern && !opts.ArrayDestructuring {
					return
				}
				if decl.Name().Kind == ast.KindObjectBindingPattern && !opts.ObjectDestructuring {
					return
				}
				if decl.Initializer != nil && isVariableDeclarationIgnoreFunction(decl.Initializer, opts) {
					return
				}
				if isCatchClauseDeclaration(node) {
					return
				}
				if isForInOrForOfDeclaration(node) {
					return
				}
				report(ctx, node, nodeName(decl.Name()))
			},
		}
	},
})
