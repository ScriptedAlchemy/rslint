package typedef

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type TypedefOptions struct {
	VariableDeclaration bool `json:"variableDeclaration"`
	Parameter           bool `json:"parameter"`
	PropertyDeclaration bool `json:"propertyDeclaration"`
}

func parseOptions(options any) TypedefOptions {
	opts := TypedefOptions{
		VariableDeclaration: true,
		Parameter:           false,
		PropertyDeclaration: false,
	}
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
	if v, ok := optsMap["variableDeclaration"].(bool); ok {
		opts.VariableDeclaration = v
	}
	if v, ok := optsMap["parameter"].(bool); ok {
		opts.Parameter = v
	}
	if v, ok := optsMap["propertyDeclaration"].(bool); ok {
		opts.PropertyDeclaration = v
	}
	return opts
}

func buildExpectedTypedefMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "expectedTypedef",
		Description: "Expected " + name + " to have a type annotation.",
	}
}

var TypedefRule = rule.CreateRule(rule.Rule{
	Name: "typedef",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindVariableDeclaration: func(node *ast.Node) {
				if !opts.VariableDeclaration {
					return
				}
				decl := node.AsVariableDeclaration()
				if decl == nil || decl.Type != nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
					return
				}
				ctx.ReportNode(node, buildExpectedTypedefMessage(decl.Name().AsIdentifier().Text))
			},
			ast.KindParameter: func(node *ast.Node) {
				if !opts.Parameter {
					return
				}
				param := node.AsParameterDeclaration()
				if param == nil || param.Type != nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
					return
				}
				ctx.ReportNode(node, buildExpectedTypedefMessage(param.Name().AsIdentifier().Text))
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				if !opts.PropertyDeclaration {
					return
				}
				property := node.AsPropertyDeclaration()
				if property == nil || property.Type != nil || property.Name() == nil || property.Name().Kind != ast.KindIdentifier {
					return
				}
				ctx.ReportNode(node, buildExpectedTypedefMessage(property.Name().AsIdentifier().Text))
			},
		}
	},
})
