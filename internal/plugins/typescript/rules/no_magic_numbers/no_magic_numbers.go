package no_magic_numbers

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type NoMagicNumbersOptions struct {
	Ignore                        []string `json:"ignore"`
	EnforceConst                  bool     `json:"enforceConst"`
	IgnoreEnums                   bool     `json:"ignoreEnums"`
	IgnoreNumericLiteralTypes     bool     `json:"ignoreNumericLiteralTypes"`
	IgnoreReadonlyClassProperties bool     `json:"ignoreReadonlyClassProperties"`
	IgnoreTypeIndexes             bool     `json:"ignoreTypeIndexes"`
	ignoredValues                 map[string]bool
}

func parseOptions(options any) NoMagicNumbersOptions {
	opts := NoMagicNumbersOptions{
		Ignore:                        []string{},
		EnforceConst:                  false,
		IgnoreEnums:                   false,
		IgnoreNumericLiteralTypes:     false,
		IgnoreReadonlyClassProperties: false,
		IgnoreTypeIndexes:             false,
		ignoredValues:                 map[string]bool{},
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
	if v, ok := optsMap["enforceConst"].(bool); ok {
		opts.EnforceConst = v
	}
	if ignore, ok := optsMap["ignore"].([]interface{}); ok {
		for _, item := range ignore {
			switch v := item.(type) {
			case string:
				opts.Ignore = append(opts.Ignore, v)
				if normalized, ok := normalizeIgnoreValue(v); ok {
					opts.ignoredValues[normalized] = true
				}
			case float64, int:
				opts.Ignore = append(opts.Ignore, fmt.Sprintf("%v", v))
				if normalized, ok := normalizeIgnoreValue(v); ok {
					opts.ignoredValues[normalized] = true
				}
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
	if normalized, ok := normalizeIgnoreValue(raw); ok && opts.ignoredValues[normalized] {
		return true
	}
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

func normalizeIgnoreValue(value any) (string, bool) {
	switch v := value.(type) {
	case float64:
		return "num:" + strconv.FormatFloat(v, 'g', -1, 64), true
	case int:
		return "num:" + strconv.Itoa(v), true
	case string:
		raw := strings.TrimSpace(v)
		if raw == "" {
			return "", false
		}
		if strings.HasSuffix(raw, "n") {
			bi := new(big.Int)
			if _, ok := bi.SetString(strings.TrimSuffix(raw, "n"), 0); ok {
				return "big:" + bi.String(), true
			}
			return "", false
		}
		if number, err := strconv.ParseFloat(raw, 64); err == nil {
			return "num:" + strconv.FormatFloat(number, 'g', -1, 64), true
		}
		if integer, err := strconv.ParseInt(raw, 0, 64); err == nil {
			return "num:" + strconv.FormatFloat(float64(integer), 'g', -1, 64), true
		}
	}
	return "", false
}

func getLiteralContextNode(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	if node.Parent != nil &&
		node.Parent.Kind == ast.KindPrefixUnaryExpression &&
		node.Parent.AsPrefixUnaryExpression() != nil &&
		node.Parent.AsPrefixUnaryExpression().Operand == node {
		operator := node.Parent.AsPrefixUnaryExpression().Operator
		if operator == ast.KindMinusToken {
			return node.Parent
		}
	}
	return node
}

func getLiteralContainerNode(node *ast.Node) *ast.Node {
	contextNode := node
	if node != nil &&
		node.Parent != nil &&
		node.Parent.Kind == ast.KindPrefixUnaryExpression &&
		node.Parent.AsPrefixUnaryExpression() != nil &&
		node.Parent.AsPrefixUnaryExpression().Operand == node {
		operator := node.Parent.AsPrefixUnaryExpression().Operator
		if operator == ast.KindMinusToken || operator == ast.KindPlusToken {
			contextNode = node.Parent
		}
	}
	if contextNode == nil {
		return nil
	}
	return contextNode.Parent
}

func isConstVariableInitializer(container *ast.Node) bool {
	if container == nil || container.Kind != ast.KindVariableDeclaration || container.Parent == nil || container.Parent.Kind != ast.KindVariableDeclarationList {
		return false
	}
	return container.Parent.AsVariableDeclarationList().Flags&ast.NodeFlagsConst != 0
}

func isNumericLiteralType(container *ast.Node) bool {
	if container == nil || container.Kind != ast.KindLiteralType || container.Parent == nil {
		return false
	}
	grandparent := container.Parent
	if grandparent.Kind == ast.KindTypeAliasDeclaration {
		return true
	}
	return grandparent.Kind == ast.KindUnionType && grandparent.Parent != nil && grandparent.Parent.Kind == ast.KindTypeAliasDeclaration
}

func isTypeIndexLiteral(container *ast.Node) bool {
	if container == nil {
		return false
	}
	current := container
	for current.Parent != nil &&
		(current.Parent.Kind == ast.KindUnionType ||
			current.Parent.Kind == ast.KindIntersectionType ||
			current.Parent.Kind == ast.KindParenthesizedType) {
		current = current.Parent
	}
	return current.Parent != nil && current.Parent.Kind == ast.KindIndexedAccessType
}

func reportNodeAndRaw(ctx rule.RuleContext, node *ast.Node) (*ast.Node, string) {
	if node == nil {
		return nil, ""
	}
	reportNode := getLiteralContextNode(node)
	raw := literalRawText(ctx.SourceFile, node)
	if raw == "" {
		switch node.Kind {
		case ast.KindNumericLiteral:
			if lit := node.AsNumericLiteral(); lit != nil {
				raw = lit.Text
			}
		case ast.KindBigIntLiteral:
			if lit := node.AsBigIntLiteral(); lit != nil {
				raw = lit.Text
			}
		}
	}
	if reportNode != nil && reportNode != node {
		if unary := reportNode.AsPrefixUnaryExpression(); unary != nil && unary.Operator == ast.KindMinusToken {
			prefix := "-"
			raw = prefix + raw
		}
	}
	return reportNode, raw
}

var NoMagicNumbersRule = rule.CreateRule(rule.Rule{
	Name: "no-magic-numbers",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		checkLiteral := func(node *ast.Node) {
			if node == nil {
				return
			}

			container := getLiteralContainerNode(node)
			if !opts.EnforceConst && isConstVariableInitializer(container) {
				return
			}
			if opts.IgnoreEnums && container != nil && container.Kind == ast.KindEnumMember {
				return
			}
			if opts.IgnoreNumericLiteralTypes && isNumericLiteralType(container) {
				return
			}
			if opts.IgnoreTypeIndexes && isTypeIndexLiteral(container) {
				return
			}
			if opts.IgnoreReadonlyClassProperties && container != nil && container.Kind == ast.KindPropertyDeclaration && ast.HasSyntacticModifier(container, ast.ModifierFlagsReadonly) {
				return
			}

			reportNode, raw := reportNodeAndRaw(ctx, node)
			if raw == "" || reportNode == nil {
				return
			}
			if isIgnoredLiteral(raw, opts) {
				return
			}
			ctx.ReportNode(reportNode, buildNoMagicMessage(raw))
		}

		return rule.RuleListeners{
			ast.KindNumericLiteral: checkLiteral,
			ast.KindBigIntLiteral:  checkLiteral,
		}
	},
})
