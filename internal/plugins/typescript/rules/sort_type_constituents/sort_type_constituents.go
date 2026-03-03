package sort_type_constituents

import (
	"math"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

func buildNotSortedMessage(typeName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "notSorted",
		Description: typeName + " type constituents must be sorted.",
	}
}

func buildNotSortedNamedMessage(typeName string, name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "notSortedNamed",
		Description: typeName + " type " + name + " constituents must be sorted.",
	}
}

func buildSuggestFixMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "suggestFix",
		Description: "Sort constituents of type (removes all comments).",
	}
}

type group string

const (
	groupConditional  group = "conditional"
	groupFunction     group = "function"
	groupImport       group = "import"
	groupIntersection group = "intersection"
	groupKeyword      group = "keyword"
	groupNullish      group = "nullish"
	groupLiteral      group = "literal"
	groupNamed        group = "named"
	groupObject       group = "object"
	groupOperator     group = "operator"
	groupTuple        group = "tuple"
	groupUnion        group = "union"
)

type sortTypeConstituentsOptions struct {
	CaseSensitive      bool
	CheckIntersections bool
	CheckUnions        bool
	GroupOrder         []group
}

func defaultOptions() sortTypeConstituentsOptions {
	return sortTypeConstituentsOptions{
		CaseSensitive:      false,
		CheckIntersections: true,
		CheckUnions:        true,
		GroupOrder: []group{
			groupNamed,
			groupKeyword,
			groupOperator,
			groupLiteral,
			groupFunction,
			groupImport,
			groupConditional,
			groupObject,
			groupTuple,
			groupIntersection,
			groupUnion,
			groupNullish,
		},
	}
}

func parseOptions(options any) sortTypeConstituentsOptions {
	opts := defaultOptions()
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
	if v, ok := optsMap["caseSensitive"].(bool); ok {
		opts.CaseSensitive = v
	}
	if v, ok := optsMap["checkIntersections"].(bool); ok {
		opts.CheckIntersections = v
	}
	if v, ok := optsMap["checkUnions"].(bool); ok {
		opts.CheckUnions = v
	}
	if v, ok := optsMap["groupOrder"].([]interface{}); ok && len(v) > 0 {
		parsed := make([]group, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			parsed = append(parsed, group(s))
		}
		if len(parsed) > 0 {
			opts.GroupOrder = parsed
		}
	}
	return opts
}

func nodeText(ctx rule.RuleContext, node *ast.Node) string {
	if ctx.SourceFile == nil || node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return strings.TrimSpace(ctx.SourceFile.Text()[r.Pos():r.End()])
}

func unwrapParenthesizedType(node *ast.Node) *ast.Node {
	for node != nil && node.Kind == ast.KindParenthesizedType {
		node = node.AsParenthesizedTypeNode().Type
	}
	return node
}

func getGroup(node *ast.Node) group {
	node = unwrapParenthesizedType(node)
	if node == nil {
		return groupNamed
	}
	switch node.Kind {
	case ast.KindConditionalType:
		return groupConditional
	case ast.KindConstructorType, ast.KindFunctionType:
		return groupFunction
	case ast.KindImportType:
		return groupImport
	case ast.KindIntersectionType:
		return groupIntersection
	case ast.KindAnyKeyword, ast.KindBigIntKeyword, ast.KindBooleanKeyword,
		ast.KindNeverKeyword, ast.KindNumberKeyword, ast.KindObjectKeyword,
		ast.KindStringKeyword, ast.KindSymbolKeyword, ast.KindThisType,
		ast.KindUnknownKeyword, ast.KindIntrinsicKeyword:
		return groupKeyword
	case ast.KindNullKeyword, ast.KindUndefinedKeyword, ast.KindVoidKeyword:
		return groupNullish
	case ast.KindLiteralType:
		literalType := node.AsLiteralTypeNode()
		if literalType != nil && literalType.Literal != nil {
			switch literalType.Literal.Kind {
			case ast.KindNullKeyword, ast.KindUndefinedKeyword, ast.KindVoidKeyword:
				return groupNullish
			}
		}
		return groupLiteral
	case ast.KindTemplateLiteralType:
		return groupLiteral
	case ast.KindArrayType, ast.KindIndexedAccessType, ast.KindInferType, ast.KindTypeReference, ast.KindQualifiedName:
		return groupNamed
	case ast.KindMappedType, ast.KindTypeLiteral:
		return groupObject
	case ast.KindTypeOperator, ast.KindTypeQuery:
		return groupOperator
	case ast.KindTupleType:
		return groupTuple
	case ast.KindUnionType:
		return groupUnion
	default:
		return groupNamed
	}
}

func groupOrderIndex(groupOrder []group, g group) int {
	for i, value := range groupOrder {
		if value == g {
			return i
		}
	}
	return math.MaxInt32
}

func compareText(a, b string, caseSensitive bool) int {
	if caseSensitive {
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}

	insensitiveCollator := collate.New(language.English, collate.Numeric, collate.IgnoreCase)
	cmp := insensitiveCollator.CompareString(a, b)
	if cmp != 0 {
		return cmp
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func typeNodeRequiresParentheses(node *ast.Node, text string) bool {
	node = unwrapParenthesizedType(node)
	if node == nil {
		return false
	}
	return node.Kind == ast.KindFunctionType ||
		node.Kind == ast.KindConstructorType ||
		node.Kind == ast.KindConditionalType ||
		(node.Kind == ast.KindUnionType && strings.HasPrefix(text, "|")) ||
		(node.Kind == ast.KindIntersectionType && strings.HasPrefix(text, "&"))
}

type constituentInfo struct {
	node       *ast.Node
	groupIndex int
	text       string
}

func hasCommentsAroundTypes(ctx rule.RuleContext, types []*ast.Node) bool {
	if ctx.SourceFile == nil || len(types) == 0 {
		return false
	}
	for i, typeNode := range types {
		if typeNode == nil {
			continue
		}
		typeRange := utils.TrimNodeTextRange(ctx.SourceFile, typeNode)
		start := typeRange.Pos()
		end := typeRange.End()
		if i > 0 {
			prev := utils.TrimNodeTextRange(ctx.SourceFile, types[i-1])
			start = prev.End()
		}
		if i < len(types)-1 {
			next := utils.TrimNodeTextRange(ctx.SourceFile, types[i+1])
			end = next.Pos()
		}
		if start < end && utils.HasCommentsInRange(ctx.SourceFile, core.NewTextRange(start, end)) {
			return true
		}
	}
	return false
}

func sortedTypeText(node *ast.Node, sorted []constituentInfo) string {
	separator := " | "
	if node != nil && node.Kind == ast.KindIntersectionType {
		separator = " & "
	}
	parts := make([]string, 0, len(sorted))
	for _, item := range sorted {
		text := item.text
		inner := unwrapParenthesizedType(item.node)
		if typeNodeRequiresParentheses(item.node, text) || (node != nil && node.Kind == ast.KindIntersectionType && inner != nil && inner.Kind == ast.KindUnionType) {
			if !strings.HasPrefix(text, "(") || !strings.HasSuffix(text, ")") {
				text = "(" + text + ")"
			}
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, separator)
}

func checkConstituents(ctx rule.RuleContext, node *ast.Node, types []*ast.Node, opts sortTypeConstituentsOptions) {
	if node == nil || len(types) < 2 {
		return
	}

	sourceOrder := make([]constituentInfo, 0, len(types))
	for _, typeNode := range types {
		sourceOrder = append(sourceOrder, constituentInfo{
			node:       typeNode,
			groupIndex: groupOrderIndex(opts.GroupOrder, getGroup(typeNode)),
			text:       nodeText(ctx, typeNode),
		})
	}

	sorted := append([]constituentInfo{}, sourceOrder...)
	for i := range len(sorted) - 1 {
		for j := i + 1; j < len(sorted); j++ {
			left := sorted[i]
			right := sorted[j]
			swap := false
			if left.groupIndex > right.groupIndex {
				swap = true
			} else if left.groupIndex == right.groupIndex && compareText(left.text, right.text, opts.CaseSensitive) > 0 {
				swap = true
			}
			if swap {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	needsReport := false
	for i := range sourceOrder {
		if sourceOrder[i].node != sorted[i].node {
			needsReport = true
			break
		}
	}
	if !needsReport {
		return
	}

	typeName := "Union"
	if node.Kind == ast.KindIntersectionType {
		typeName = "Intersection"
	}

	msg := buildNotSortedMessage(typeName)
	if node.Parent != nil && node.Parent.Kind == ast.KindTypeAliasDeclaration {
		aliasDecl := node.Parent.AsTypeAliasDeclaration()
		if aliasDecl != nil && aliasDecl.Name() != nil {
			msg = buildNotSortedNamedMessage(typeName, aliasDecl.Name().Text())
		}
	}

	fixedText := sortedTypeText(node, sorted)
	fix := rule.RuleFixReplaceRange(utils.TrimNodeTextRange(ctx.SourceFile, node), fixedText)
	if hasCommentsAroundTypes(ctx, types) {
		ctx.ReportNodeWithSuggestions(node, msg, rule.RuleSuggestion{
			Message:  buildSuggestFixMessage(),
			FixesArr: []rule.RuleFix{fix},
		})
		return
	}
	ctx.ReportNodeWithFixes(node, msg, fix)
}

var SortTypeConstituentsRule = rule.CreateRule(rule.Rule{
	Name: "sort-type-constituents",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindUnionType: func(node *ast.Node) {
				if !opts.CheckUnions {
					return
				}
				unionType := node.AsUnionTypeNode()
				if unionType == nil || unionType.Types == nil {
					return
				}
				checkConstituents(ctx, node, unionType.Types.Nodes, opts)
			},
			ast.KindIntersectionType: func(node *ast.Node) {
				if !opts.CheckIntersections {
					return
				}
				intersectionType := node.AsIntersectionTypeNode()
				if intersectionType == nil || intersectionType.Types == nil {
					return
				}
				checkConstituents(ctx, node, intersectionType.Types.Nodes, opts)
			},
		}
	},
})
