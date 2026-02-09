package no_restricted_types

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

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

type bannedTypeConfig struct {
	Enabled bool
	Message string
	FixWith string
}

func removeSpaces(input string) string {
	return strings.Join(strings.Fields(input), "")
}

func normalizeCustomMessage(message string) string {
	if message == "" {
		return ""
	}
	return " " + message
}

func parseOptions(options any) map[string]bannedTypeConfig {
	restricted := map[string]bannedTypeConfig{}
	if options == nil {
		return restricted
	}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if firstMap, ok := arr[0].(map[string]interface{}); ok && firstMap != nil {
			if rawTypes, ok := firstMap["types"].(map[string]interface{}); ok {
				for rawName, rawConfig := range rawTypes {
					name := removeSpaces(rawName)
					config := bannedTypeConfig{Enabled: true}

					switch v := rawConfig.(type) {
					case bool:
						config.Enabled = v
					case string:
						config.Message = normalizeCustomMessage(v)
					case map[string]interface{}:
						if msg, ok := v["message"].(string); ok {
							config.Message = normalizeCustomMessage(msg)
						}
						if fixWith, ok := v["fixWith"].(string); ok {
							config.FixWith = fixWith
						}
					case nil:
						config.Enabled = false
					default:
						config.Enabled = false
					}

					if config.Enabled {
						restricted[name] = config
					} else {
						delete(restricted, name)
					}
				}
			}
		} else {
			for _, item := range arr {
				if name, ok := item.(string); ok {
					restricted[removeSpaces(name)] = bannedTypeConfig{Enabled: true}
				}
			}
		}
	}
	return restricted
}

func nodeText(ctx rule.RuleContext, node *ast.Node) string {
	if ctx.SourceFile == nil || node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return ctx.SourceFile.Text()[r.Pos():r.End()]
}

func normalizedNodeText(ctx rule.RuleContext, node *ast.Node) string {
	return removeSpaces(nodeText(ctx, node))
}

func reportIfBanned(ctx rule.RuleContext, node *ast.Node, name string, banned map[string]bannedTypeConfig) bool {
	if node == nil || name == "" {
		return false
	}
	config, ok := banned[name]
	if !ok || !config.Enabled {
		return false
	}
	message := buildBannedTypeMessage(name, config.Message)
	if config.FixWith != "" {
		ctx.ReportNodeWithFixes(node, message, rule.RuleFixReplace(ctx.SourceFile, node, config.FixWith))
	} else {
		ctx.ReportNode(node, message)
	}
	return true
}

var NoRestrictedTypesRule = rule.CreateRule(rule.Rule{
	Name: "no-restricted-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		restricted := parseOptions(options)
		listeners := rule.RuleListeners{
			ast.KindBigIntKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "bigint", restricted)
			},
			ast.KindBooleanKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "boolean", restricted)
			},
			ast.KindNeverKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "never", restricted)
			},
			ast.KindNullKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "null", restricted)
			},
			ast.KindNumberKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "number", restricted)
			},
			ast.KindObjectKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "object", restricted)
			},
			ast.KindStringKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "string", restricted)
			},
			ast.KindSymbolKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "symbol", restricted)
			},
			ast.KindUndefinedKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "undefined", restricted)
			},
			ast.KindUnknownKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "unknown", restricted)
			},
			ast.KindVoidKeyword: func(node *ast.Node) {
				reportIfBanned(ctx, node, "void", restricted)
			},
			ast.KindTupleType: func(node *ast.Node) {
				tuple := node.AsTupleTypeNode()
				if tuple == nil || tuple.Elements == nil || len(tuple.Elements.Nodes) != 0 {
					return
				}
				reportIfBanned(ctx, node, "[]", restricted)
			},
			ast.KindTypeLiteral: func(node *ast.Node) {
				typeLiteral := node.AsTypeLiteralNode()
				if typeLiteral == nil || typeLiteral.Members == nil || len(typeLiteral.Members.Nodes) != 0 {
					return
				}
				reportIfBanned(ctx, node, "{}", restricted)
			},
			ast.KindExpressionWithTypeArguments: func(node *ast.Node) {
				reportIfBanned(ctx, node, normalizedNodeText(ctx, node), restricted)
			},
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil {
					return
				}
				reportIfBanned(ctx, typeRef.TypeName, normalizedNodeText(ctx, typeRef.TypeName), restricted)
				if typeRef.TypeArguments != nil && len(typeRef.TypeArguments.Nodes) > 0 {
					reportIfBanned(ctx, node, normalizedNodeText(ctx, node), restricted)
				}
			},
		}
		return listeners
	},
})
