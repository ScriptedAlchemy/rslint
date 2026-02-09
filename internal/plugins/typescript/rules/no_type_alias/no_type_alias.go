package no_type_alias

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type NoTypeAliasOptions struct {
	AllowAliases string `json:"allowAliases"`
}

func parseOptions(options any) NoTypeAliasOptions {
	opts := NoTypeAliasOptions{
		AllowAliases: "never",
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
	if v, ok := optsMap["allowAliases"].(string); ok {
		opts.AllowAliases = v
	}
	return opts
}

func buildNoTypeAliasMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noTypeAlias",
		Description: "Type alias are not allowed.",
	}
}

var NoTypeAliasRule = rule.CreateRule(rule.Rule{
	Name: "no-type-alias",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				if opts.AllowAliases == "always" {
					return
				}
				ctx.ReportNode(node, buildNoTypeAliasMessage())
			},
		}
	},
})
