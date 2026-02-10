package no_magic_numbers

import (
	"strconv"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type noMagicNumbersOptions struct {
	ignore                        []interface{}
	ignoreEnums                   bool
	ignoreNumericLiteralTypes     bool
	ignoreReadonlyClassProperties bool
	ignoreTypeIndexes             bool
}

type candidateLiteral struct {
	node      *ast.Node
	raw       string
	isBigInt  bool
	number    float64
	bigIntRaw string
}

func parseNoMagicNumbersOptions(options any) noMagicNumbersOptions {
	parsed := noMagicNumbersOptions{
		ignore:                        nil,
		ignoreEnums:                   false,
		ignoreNumericLiteralTypes:     false,
		ignoreReadonlyClassProperties: false,
		ignoreTypeIndexes:             false,
	}
	if options == nil {
		return parsed
	}

	var optionMap map[string]interface{}
	switch typed := options.(type) {
	case []interface{}:
		if len(typed) > 0 {
			optionMap, _ = typed[0].(map[string]interface{})
		}
	case map[string]interface{}:
		optionMap = typed
	}
	if optionMap == nil {
		return parsed
	}

	if ignore, ok := optionMap["ignore"].([]interface{}); ok {
		parsed.ignore = ignore
	}
	if ignoreEnums, ok := optionMap["ignoreEnums"].(bool); ok {
		parsed.ignoreEnums = ignoreEnums
	}
	if ignoreNumericLiteralTypes, ok := optionMap["ignoreNumericLiteralTypes"].(bool); ok {
		parsed.ignoreNumericLiteralTypes = ignoreNumericLiteralTypes
	}
	if ignoreReadonlyClassProperties, ok := optionMap["ignoreReadonlyClassProperties"].(bool); ok {
		parsed.ignoreReadonlyClassProperties = ignoreReadonlyClassProperties
	}
	if ignoreTypeIndexes, ok := optionMap["ignoreTypeIndexes"].(bool); ok {
		parsed.ignoreTypeIndexes = ignoreTypeIndexes
	}
	return parsed
}

func parseNumberLiteral(text string) (float64, bool) {
	clean := strings.ReplaceAll(strings.TrimSpace(text), "_", "")
	if clean == "" {
		return 0, false
	}
	if strings.ContainsAny(clean, ".eE") {
		v, err := strconv.ParseFloat(clean, 64)
		return v, err == nil
	}
	negative := strings.HasPrefix(clean, "-")
	unsigned := strings.TrimPrefix(strings.TrimPrefix(clean, "-"), "+")
	integer, err := strconv.ParseInt(unsigned, 0, 64)
	if err == nil {
		value := float64(integer)
		if negative {
			value = -value
		}
		return value, true
	}
	v, err := strconv.ParseFloat(clean, 64)
	return v, err == nil
}

func isIgnoredLiteral(candidate candidateLiteral, ignoreList []interface{}) bool {
	if len(ignoreList) == 0 {
		return false
	}
	for _, ignored := range ignoreList {
		if candidate.isBigInt {
			ignoredString, ok := ignored.(string)
			if ok && strings.TrimSpace(ignoredString) == candidate.bigIntRaw {
				return true
			}
			continue
		}

		ignoredNumber, ok := ignored.(float64)
		if !ok {
			continue
		}
		if candidate.number == ignoredNumber {
			return true
		}
	}
	return false
}

func isInsideEnumInitializer(node *ast.Node) bool {
	child := node
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Kind == ast.KindEnumMember {
			enumMember := parent.AsEnumMember()
			if enumMember != nil && enumMember.Initializer == child {
				return true
			}
		}
		child = parent
	}
	return false
}

func isInsideReadonlyClassPropertyInitializer(node *ast.Node) bool {
	child := node
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Kind == ast.KindPropertyDeclaration {
			property := parent.AsPropertyDeclaration()
			if property != nil && property.Initializer == child && ast.HasSyntacticModifier(parent, ast.ModifierFlagsReadonly) {
				return true
			}
		}
		child = parent
	}
	return false
}

func isInsideIndexedAccessTypeIndex(node *ast.Node) bool {
	child := node
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Kind == ast.KindIndexedAccessType {
			indexedAccessType := parent.AsIndexedAccessTypeNode()
			if indexedAccessType != nil && indexedAccessType.IndexType == child {
				return true
			}
		}
		child = parent
	}
	return false
}

func isInsideTypeAliasType(node *ast.Node) bool {
	child := node
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Kind == ast.KindTypeAliasDeclaration {
			typeAlias := parent.AsTypeAliasDeclaration()
			if typeAlias != nil && typeAlias.Type == child {
				return true
			}
		}
		child = parent
	}
	return false
}

func isInsideLiteralType(node *ast.Node) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindLiteralType {
			return true
		}
	}
	return false
}

func buildNoMagicMessage(raw string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noMagic",
		Description: "Magic number: " + raw,
	}
}

func getPrefixUnaryCandidate(node *ast.Node) (candidateLiteral, bool) {
	if node == nil || node.Kind != ast.KindPrefixUnaryExpression {
		return candidateLiteral{}, false
	}
	expr := node.AsPrefixUnaryExpression()
	if expr == nil || expr.Operand == nil {
		return candidateLiteral{}, false
	}
	operand := expr.Operand
	switch expr.Operator {
	case ast.KindPlusToken:
		if operand.Kind == ast.KindNumericLiteral {
			number, ok := parseNumberLiteral(operand.AsNumericLiteral().Text)
			if !ok {
				return candidateLiteral{}, false
			}
			return candidateLiteral{
				node:   operand,
				raw:    operand.AsNumericLiteral().Text,
				number: number,
			}, true
		}
	case ast.KindMinusToken:
		if operand.Kind == ast.KindNumericLiteral {
			number, ok := parseNumberLiteral(operand.AsNumericLiteral().Text)
			if !ok {
				return candidateLiteral{}, false
			}
			return candidateLiteral{
				node:   node,
				raw:    "-" + operand.AsNumericLiteral().Text,
				number: -number,
			}, true
		}
		if operand.Kind == ast.KindBigIntLiteral {
			raw := "-" + operand.Text()
			return candidateLiteral{
				node:      node,
				raw:       raw,
				isBigInt:  true,
				bigIntRaw: raw,
			}, true
		}
	}
	return candidateLiteral{}, false
}

func getLiteralCandidate(node *ast.Node) (candidateLiteral, bool) {
	if node == nil {
		return candidateLiteral{}, false
	}
	if node.Parent != nil && node.Parent.Kind == ast.KindPrefixUnaryExpression {
		parentUnary := node.Parent.AsPrefixUnaryExpression()
		if parentUnary != nil && (parentUnary.Operator == ast.KindPlusToken || parentUnary.Operator == ast.KindMinusToken) {
			return candidateLiteral{}, false
		}
	}
	switch node.Kind {
	case ast.KindNumericLiteral:
		number, ok := parseNumberLiteral(node.AsNumericLiteral().Text)
		if !ok {
			return candidateLiteral{}, false
		}
		return candidateLiteral{
			node:   node,
			raw:    node.AsNumericLiteral().Text,
			number: number,
		}, true
	case ast.KindBigIntLiteral:
		return candidateLiteral{
			node:      node,
			raw:       node.Text(),
			isBigInt:  true,
			bigIntRaw: node.Text(),
		}, true
	default:
		return candidateLiteral{}, false
	}
}

func shouldIgnoreCandidate(candidate candidateLiteral, options noMagicNumbersOptions) bool {
	if isIgnoredLiteral(candidate, options.ignore) {
		return true
	}
	if options.ignoreEnums && isInsideEnumInitializer(candidate.node) {
		return true
	}
	if options.ignoreReadonlyClassProperties && isInsideReadonlyClassPropertyInitializer(candidate.node) {
		return true
	}
	if options.ignoreTypeIndexes && isInsideIndexedAccessTypeIndex(candidate.node) {
		return true
	}
	if options.ignoreNumericLiteralTypes && isInsideTypeAliasType(candidate.node) {
		return true
	}
	return false
}

var NoMagicNumbersRule = rule.CreateRule(rule.Rule{
	Name: "no-magic-numbers",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		parsedOptions := parseNoMagicNumbersOptions(options)

		reportCandidate := func(candidate candidateLiteral) {
			relevantContext :=
				isInsideLiteralType(candidate.node) ||
					isInsideEnumInitializer(candidate.node) ||
					isInsideReadonlyClassPropertyInitializer(candidate.node)
			if !relevantContext {
				return
			}
			if shouldIgnoreCandidate(candidate, parsedOptions) {
				return
			}
			ctx.ReportNode(candidate.node, buildNoMagicMessage(candidate.raw))
		}

		return rule.RuleListeners{
			ast.KindPrefixUnaryExpression: func(node *ast.Node) {
				candidate, ok := getPrefixUnaryCandidate(node)
				if !ok {
					return
				}
				reportCandidate(candidate)
			},
			ast.KindNumericLiteral: func(node *ast.Node) {
				candidate, ok := getLiteralCandidate(node)
				if !ok {
					return
				}
				reportCandidate(candidate)
			},
			ast.KindBigIntLiteral: func(node *ast.Node) {
				candidate, ok := getLiteralCandidate(node)
				if !ok {
					return
				}
				reportCandidate(candidate)
			},
		}
	},
})
