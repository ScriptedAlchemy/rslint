package no_restricted_types

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type restrictedTypeConfig struct {
	message string
	fixWith string
	hasFix  bool
}

func normalizeTypeKey(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func parseRestrictedTypes(options any) map[string]restrictedTypeConfig {
	restricted := map[string]restrictedTypeConfig{}
	if options == nil {
		return restricted
	}

	var optsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			optsMap = first
		}
	} else if direct, ok := options.(map[string]interface{}); ok {
		optsMap = direct
	}
	if optsMap == nil {
		return restricted
	}

	typesMap, ok := optsMap["types"].(map[string]interface{})
	if !ok {
		return restricted
	}

	for rawName, rawCfg := range typesMap {
		name := normalizeTypeKey(rawName)
		if name == "" {
			continue
		}

		switch cfg := rawCfg.(type) {
		case bool:
			if cfg {
				restricted[name] = restrictedTypeConfig{}
			}
		case string:
			restricted[name] = restrictedTypeConfig{message: cfg}
		case map[string]interface{}:
			item := restrictedTypeConfig{}
			if msg, ok := cfg["message"].(string); ok {
				item.message = msg
			}
			if fixWith, ok := cfg["fixWith"].(string); ok && fixWith != "" {
				item.fixWith = fixWith
				item.hasFix = true
			}
			restricted[name] = item
		}
	}
	return restricted
}

func nodeText(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return ctx.SourceFile.Text()[r.Pos():r.End()]
}

func reportRestrictedType(ctx rule.RuleContext, restricted map[string]restrictedTypeConfig, node *ast.Node) {
	if node == nil {
		return
	}
	rawText := nodeText(ctx, node)
	if rawText == "" {
		return
	}
	cfg, ok := restricted[normalizeTypeKey(rawText)]
	if !ok {
		return
	}

	message := "Don't use `" + strings.TrimSpace(rawText) + "` as a type."
	if cfg.message != "" {
		message = message + " " + cfg.message
	}
	msg := rule.RuleMessage{
		Id:          "bannedTypeMessage",
		Description: message,
	}

	if cfg.hasFix {
		ctx.ReportNodeWithFixes(node, msg, rule.RuleFixReplace(ctx.SourceFile, node, cfg.fixWith))
		return
	}
	ctx.ReportNode(node, msg)
}

func isEmptyTypeLiteral(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindTypeLiteral {
		return false
	}
	typeLiteral := node.AsTypeLiteralNode()
	return typeLiteral != nil && typeLiteral.Members != nil && len(typeLiteral.Members.Nodes) == 0
}

func isEmptyTupleType(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindTupleType {
		return false
	}
	tuple := node.AsTupleTypeNode()
	return tuple != nil && tuple.Elements != nil && len(tuple.Elements.Nodes) == 0
}

var NoRestrictedTypesRule = rule.CreateRule(rule.Rule{
	Name: "no-restricted-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		restricted := parseRestrictedTypes(options)
		if len(restricted) == 0 {
			return rule.RuleListeners{}
		}

		checkNode := func(node *ast.Node) {
			reportRestrictedType(ctx, restricted, node)
		}

		return rule.RuleListeners{
			ast.KindTypeReference:               checkNode,
			ast.KindExpressionWithTypeArguments: checkNode,

			ast.KindBigIntKeyword:    checkNode,
			ast.KindBooleanKeyword:   checkNode,
			ast.KindNeverKeyword:     checkNode,
			ast.KindNullKeyword:      checkNode,
			ast.KindNumberKeyword:    checkNode,
			ast.KindObjectKeyword:    checkNode,
			ast.KindStringKeyword:    checkNode,
			ast.KindSymbolKeyword:    checkNode,
			ast.KindUndefinedKeyword: checkNode,
			ast.KindUnknownKeyword:   checkNode,
			ast.KindVoidKeyword:      checkNode,

			ast.KindTypeLiteral: func(node *ast.Node) {
				if !isEmptyTypeLiteral(node) {
					return
				}
				checkNode(node)
			},
			ast.KindTupleType: func(node *ast.Node) {
				if !isEmptyTupleType(node) {
					return
				}
				checkNode(node)
			},
		}
	},
})
