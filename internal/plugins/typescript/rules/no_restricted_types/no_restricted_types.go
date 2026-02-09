package no_restricted_types

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type restrictedType struct {
	Name    string
	Message string
}

func buildBannedTypeMessage(name, customMessage string) rule.RuleMessage {
	description := "Don't use `" + name + "` as a type."
	if customMessage != "" {
		description += " " + customMessage
	}
	return rule.RuleMessage{
		Id:          "bannedTypeMessage",
		Description: description,
	}
}

func parseOptions(options any) []restrictedType {
	restricted := []restrictedType{}
	if options == nil {
		return restricted
	}
	var entries []interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if firstMap, ok := arr[0].(map[string]interface{}); ok {
			if types, ok := firstMap["types"].(map[string]interface{}); ok {
				for name, raw := range types {
					rt := restrictedType{Name: name}
					if rawMap, ok := raw.(map[string]interface{}); ok {
						if msg, ok := rawMap["message"].(string); ok {
							rt.Message = msg
						}
					}
					restricted = append(restricted, rt)
				}
				return restricted
			}
		}
		entries = arr
	}
	for _, entry := range entries {
		if s, ok := entry.(string); ok {
			restricted = append(restricted, restrictedType{Name: s})
		}
	}
	return restricted
}

var NoRestrictedTypesRule = rule.CreateRule(rule.Rule{
	Name: "no-restricted-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		restricted := parseOptions(options)
		return rule.RuleListeners{
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil || typeRef.TypeName.Kind != ast.KindIdentifier {
					return
				}
				name := typeRef.TypeName.AsIdentifier().Text
				for _, restrictedType := range restricted {
					if restrictedType.Name == name {
						ctx.ReportNode(node, buildBannedTypeMessage(name, restrictedType.Message))
						return
					}
				}
			},
		}
	},
})
