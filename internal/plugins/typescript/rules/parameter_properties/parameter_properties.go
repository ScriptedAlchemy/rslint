package parameter_properties

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type ParameterPropertiesOptions struct {
	Allow  []string `json:"allow"`
	Prefer string   `json:"prefer"`
}

func parseOptions(options any) ParameterPropertiesOptions {
	opts := ParameterPropertiesOptions{
		Allow:  []string{},
		Prefer: "class-property",
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
	if v, ok := optsMap["prefer"].(string); ok {
		opts.Prefer = v
	}
	if v, ok := optsMap["allow"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				opts.Allow = append(opts.Allow, s)
			}
		}
	}
	return opts
}

func hasParamPropertyModifiers(param *ast.Node) bool {
	if param == nil {
		return false
	}
	flags := ast.GetCombinedModifierFlags(param)
	return flags&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0
}

func buildPreferClassPropertyMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferClassProperty",
		Description: "Property " + name + " should be declared as a class property.",
	}
}

func buildPreferParameterPropertyMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferParameterProperty",
		Description: "Property " + name + " should be declared as a parameter property.",
	}
}

var ParameterPropertiesRule = rule.CreateRule(rule.Rule{
	Name: "parameter-properties",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindParameter: func(node *ast.Node) {
				if opts.Prefer != "class-property" {
					return
				}
				if !hasParamPropertyModifiers(node) {
					return
				}
				param := node.AsParameterDeclaration()
				if param == nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
					return
				}
				ctx.ReportNode(node, buildPreferClassPropertyMessage(param.Name().AsIdentifier().Text))
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				if opts.Prefer != "parameter-property" {
					return
				}
				property := node.AsPropertyDeclaration()
				if property == nil || property.Name() == nil || property.Name().Kind != ast.KindIdentifier {
					return
				}
				// Heuristic: class property without initializer is likely ctor-assigned.
				if property.Initializer != nil {
					return
				}
				ctx.ReportNode(node, buildPreferParameterPropertyMessage(property.Name().AsIdentifier().Text))
			},
		}
	},
})
