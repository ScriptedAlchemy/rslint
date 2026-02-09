package no_magic_numbers

import (
	"fmt"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type NoMagicNumbersOptions struct {
	Ignore                        []string `json:"ignore"`
	IgnoreEnums                   bool     `json:"ignoreEnums"`
	IgnoreNumericLiteralTypes     bool     `json:"ignoreNumericLiteralTypes"`
	IgnoreReadonlyClassProperties bool     `json:"ignoreReadonlyClassProperties"`
	IgnoreTypeIndexes             bool     `json:"ignoreTypeIndexes"`
}

func parseOptions(options any) NoMagicNumbersOptions {
	opts := NoMagicNumbersOptions{
		Ignore:                        []string{},
		IgnoreEnums:                   false,
		IgnoreNumericLiteralTypes:     false,
		IgnoreReadonlyClassProperties: false,
		IgnoreTypeIndexes:             false,
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
	if ignore, ok := optsMap["ignore"].([]interface{}); ok {
		for _, item := range ignore {
			switch v := item.(type) {
			case string:
				opts.Ignore = append(opts.Ignore, v)
			case float64, int:
				opts.Ignore = append(opts.Ignore, fmt.Sprintf("%v", v))
			}
		}
	}
	if v, ok := optsMap["ignoreEnums"].(bool); ok {
		opts.IgnoreEnums = v
	}
	if v, ok := optsMap["ignoreNumericLiteralTypes"].(bool); ok {
		opts.IgnoreNumericLiteralTypes = v
	}
	if v, ok := optsMap["ignoreReadonlyClassProperties"].(bool); ok {
		opts.IgnoreReadonlyClassProperties = v
	}
	if v, ok := optsMap["ignoreTypeIndexes"].(bool); ok {
		opts.IgnoreTypeIndexes = v
	}
	return opts
}

func buildNoMagicMessage(raw string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noMagic",
		Description: "No magic number: " + raw + ".",
	}
}

func isIgnoredLiteral(raw string, opts NoMagicNumbersOptions) bool {
	for _, v := range opts.Ignore {
		if v == raw {
			return true
		}
	}
	return false
}

func literalRawText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	start, end := node.Pos(), node.End()
	if start < 0 || end > len(sourceFile.Text()) || start >= end {
		return ""
	}
	return strings.TrimSpace(sourceFile.Text()[start:end])
}

var NoMagicNumbersRule = rule.CreateRule(rule.Rule{
	Name: "no-magic-numbers",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindNumericLiteral: func(node *ast.Node) {
				raw := literalRawText(ctx.SourceFile, node)
				if raw == "" {
					raw = node.AsNumericLiteral().Text
				}

				parent := node.Parent
				if parent != nil {
					if opts.IgnoreEnums && parent.Kind == ast.KindEnumMember {
						return
					}
					if opts.IgnoreNumericLiteralTypes && parent.Kind == ast.KindLiteralType {
						return
					}
					if opts.IgnoreTypeIndexes && parent.Kind == ast.KindIndexedAccessType {
						return
					}
					if opts.IgnoreReadonlyClassProperties && parent.Kind == ast.KindPropertyDeclaration {
						if ast.HasSyntacticModifier(parent, ast.ModifierFlagsReadonly) {
							return
						}
					}
				}

				if isIgnoredLiteral(raw, opts) {
					return
				}
				ctx.ReportNode(node, buildNoMagicMessage(raw))
			},
		}
	},
})
