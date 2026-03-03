package method_signature_style

import (
	"sort"
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type MethodSignatureStyle string

const (
	StyleProperty MethodSignatureStyle = "property"
	StyleMethod   MethodSignatureStyle = "method"
)

func parseStyle(options any) MethodSignatureStyle {
	style := StyleProperty
	if options == nil {
		return style
	}

	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok && (s == string(StyleProperty) || s == string(StyleMethod)) {
			return MethodSignatureStyle(s)
		}
	}

	if s, ok := options.(string); ok && (s == string(StyleProperty) || s == string(StyleMethod)) {
		return MethodSignatureStyle(s)
	}

	return style
}

func buildErrorMethodMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "errorMethod",
		Description: "Shorthand method signature is forbidden. Use a function property instead.",
	}
}

func buildErrorPropertyMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "errorProperty",
		Description: "Function property signature is forbidden. Use a method shorthand instead.",
	}
}

func isFunctionTypeLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionType:
		return true
	case ast.KindParenthesizedType:
		parenthesized := node.AsParenthesizedTypeNode()
		return parenthesized != nil && isFunctionTypeLike(parenthesized.Type)
	case ast.KindIntersectionType:
		intersection := node.AsIntersectionTypeNode()
		if intersection == nil || intersection.Types == nil || len(intersection.Types.Nodes) == 0 {
			return false
		}
		for _, t := range intersection.Types.Nodes {
			if !isFunctionTypeLike(t) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func nodeText(source string, start int, end int) string {
	if start < 0 || end > len(source) || start > end {
		return ""
	}
	return source[start:end]
}

func findFirstToken(node *ast.Node, kind ast.Kind, predicate func(token *ast.Node) bool, sourceFile *ast.SourceFile) *ast.Node {
	var matched *ast.Node
	utils.ForEachToken(node, func(token *ast.Node) {
		if matched != nil || token == nil || token.Kind != kind {
			return
		}
		if predicate == nil || predicate(token) {
			matched = token
		}
	}, sourceFile)
	return matched
}

func findLastToken(node *ast.Node, kind ast.Kind, predicate func(token *ast.Node) bool, sourceFile *ast.SourceFile) *ast.Node {
	var matched *ast.Node
	utils.ForEachToken(node, func(token *ast.Node) {
		if token == nil || token.Kind != kind {
			return
		}
		if predicate == nil || predicate(token) {
			matched = token
		}
	}, sourceFile)
	return matched
}

func tokenRange(sourceFile *ast.SourceFile, token *ast.Node) core.TextRange {
	return utils.TrimNodeTextRange(sourceFile, token)
}

func delimiterForNode(source string, node *ast.Node, sourceFile *ast.SourceFile) string {
	if node == nil || sourceFile == nil {
		return ""
	}
	nodeRange := utils.TrimNodeTextRange(sourceFile, node)
	i := nodeRange.End() - 1
	for i >= nodeRange.Pos() && unicode.IsSpace(rune(source[i])) {
		i--
	}
	if i < nodeRange.Pos() {
		return ""
	}
	switch source[i] {
	case ';':
		return ";"
	case ',':
		return ","
	default:
		return ""
	}
}

func returnTypeText(source string, node *ast.Node, sourceFile *ast.SourceFile) string {
	if node == nil || sourceFile == nil {
		return "any"
	}
	typeNode := node.Type()
	if typeNode == nil {
		return "any"
	}
	typeRange := utils.TrimNodeTextRange(sourceFile, typeNode)
	text := strings.TrimSpace(nodeText(source, typeRange.Pos(), typeRange.End()))
	if text == "" {
		return "any"
	}
	return text
}

func memberKey(node *ast.Node, source string, sourceFile *ast.SourceFile) string {
	if node == nil || node.Name() == nil || sourceFile == nil {
		return ""
	}
	nameRange := utils.TrimNodeTextRange(sourceFile, node.Name())
	key := strings.TrimSpace(nodeText(source, nameRange.Pos(), nameRange.End()))
	if key == "" {
		return ""
	}
	if node.QuestionToken() != nil {
		key += "?"
	}
	if ast.HasSyntacticModifier(node, ast.ModifierFlagsReadonly) {
		key = "readonly " + key
	}
	return key
}

func functionLikeParamsText(node *ast.Node, prefixStart int, source string, sourceFile *ast.SourceFile) (string, bool) {
	if node == nil || sourceFile == nil {
		return "", false
	}

	parameters := node.Parameters()
	var openParen *ast.Node
	var closeParen *ast.Node

	if len(parameters) == 0 {
		openParen = findFirstToken(node, ast.KindOpenParenToken, nil, sourceFile)
		if openParen == nil {
			return "", false
		}
		openRange := tokenRange(sourceFile, openParen)
		closeParen = findFirstToken(node, ast.KindCloseParenToken, func(token *ast.Node) bool {
			return tokenRange(sourceFile, token).Pos() >= openRange.End()
		}, sourceFile)
		if closeParen == nil {
			return "", false
		}
	} else {
		firstParam := parameters[0]
		lastParam := parameters[len(parameters)-1]
		if firstParam == nil || lastParam == nil {
			return "", false
		}
		openParen = findLastToken(node, ast.KindOpenParenToken, func(token *ast.Node) bool {
			return tokenRange(sourceFile, token).End() <= firstParam.Pos()
		}, sourceFile)
		closeParen = findFirstToken(node, ast.KindCloseParenToken, func(token *ast.Node) bool {
			return tokenRange(sourceFile, token).Pos() >= lastParam.End()
		}, sourceFile)
		if openParen == nil || closeParen == nil {
			return "", false
		}
	}

	openRange := tokenRange(sourceFile, openParen)
	closeRange := tokenRange(sourceFile, closeParen)
	paramsStart := openRange.Pos()
	if prefixStart >= 0 && prefixStart < openRange.Pos() {
		i := prefixStart
		for i < openRange.Pos() && unicode.IsSpace(rune(source[i])) {
			i++
		}
		if i < openRange.Pos() {
			paramsStart = i
		}
	}
	return nodeText(source, paramsStart, closeRange.End()), true
}

func methodParamsText(methodNode *ast.Node, source string, sourceFile *ast.SourceFile) (string, bool) {
	if methodNode == nil || methodNode.Name() == nil || sourceFile == nil {
		return "", false
	}
	nameRange := utils.TrimNodeTextRange(sourceFile, methodNode.Name())
	keyEnd := nameRange.End()
	if methodNode.QuestionToken() != nil {
		questionRange := utils.TrimNodeTextRange(sourceFile, methodNode.QuestionToken())
		keyEnd = questionRange.End()
	}
	return functionLikeParamsText(methodNode, keyEnd, source, sourceFile)
}

func propertyTypeNode(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	property := node.AsPropertySignatureDeclaration()
	if property == nil || property.Type == nil {
		return nil
	}
	if isFunctionTypeLike(property.Type) {
		return property.Type
	}
	return nil
}

func unwrapParenthesizedType(node *ast.Node) *ast.Node {
	for node != nil && node.Kind == ast.KindParenthesizedType {
		parenthesized := node.AsParenthesizedTypeNode()
		if parenthesized == nil {
			return nil
		}
		node = parenthesized.Type
	}
	return node
}

func isInsideModuleDeclaration(node *ast.Node) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindModuleDeclaration {
			return true
		}
	}
	return false
}

func containsThisType(node *ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	var walk func(*ast.Node)
	walk = func(current *ast.Node) {
		if current == nil || found {
			return
		}
		if current.Kind == ast.KindThisType {
			found = true
			return
		}
		current.ForEachChild(func(child *ast.Node) bool {
			walk(child)
			return found
		})
	}
	walk(node)
	return found
}

func parentMembers(node *ast.Node) []*ast.Node {
	if node == nil || node.Parent == nil {
		return nil
	}
	switch node.Parent.Kind {
	case ast.KindInterfaceDeclaration:
		decl := node.Parent.AsInterfaceDeclaration()
		if decl == nil || decl.Members == nil {
			return nil
		}
		return decl.Members.Nodes
	case ast.KindTypeLiteral:
		literal := node.Parent.AsTypeLiteralNode()
		if literal == nil || literal.Members == nil {
			return nil
		}
		return literal.Members.Nodes
	default:
		return nil
	}
}

func removalRangeForMember(source string, node *ast.Node, sourceFile *ast.SourceFile) core.TextRange {
	nodeRange := utils.TrimNodeTextRange(sourceFile, node)
	start := nodeRange.Pos()
	for start > 0 && (source[start-1] == ' ' || source[start-1] == '\t') {
		start--
	}
	end := nodeRange.End()
	for end < len(source) && (source[end] == ' ' || source[end] == '\t') {
		end++
	}
	if end < len(source) && source[end] == '\r' {
		end++
	}
	if end < len(source) && source[end] == '\n' {
		end++
	}
	return nodeRange.WithPos(start).WithEnd(end)
}

var MethodSignatureStyleRule = rule.CreateRule(rule.Rule{
	Name: "method-signature-style",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		style := parseStyle(options)
		sourceFile := ctx.SourceFile
		sourceText := ""
		if sourceFile != nil {
			sourceText = sourceFile.Text()
		}

		return rule.RuleListeners{
			ast.KindMethodSignature: func(node *ast.Node) {
				if style != StyleProperty {
					return
				}

				msg := buildErrorMethodMessage()
				if sourceFile == nil || node == nil {
					ctx.ReportNode(node, msg)
					return
				}

				key := memberKey(node, sourceText, sourceFile)
				paramsText, hasParams := methodParamsText(node, sourceText, sourceFile)
				returnType := returnTypeText(sourceText, node, sourceFile)
				delimiter := delimiterForNode(sourceText, node, sourceFile)

				reportWithoutFix := func() {
					ctx.ReportNode(node, msg)
				}

				if key == "" || !hasParams {
					reportWithoutFix()
					return
				}
				if containsThisType(node.Type()) {
					reportWithoutFix()
					return
				}
				if isInsideModuleDeclaration(node) {
					reportWithoutFix()
					return
				}

				siblings := parentMembers(node)
				duplicates := make([]*ast.Node, 0)
				for _, sibling := range siblings {
					if sibling == nil || sibling == node || sibling.Kind != ast.KindMethodSignature {
						continue
					}
					if memberKey(sibling, sourceText, sourceFile) == key {
						duplicates = append(duplicates, sibling)
					}
				}

				if len(duplicates) == 0 {
					replacement := key + ": " + paramsText + " => " + returnType + delimiter
					ctx.ReportNodeWithFixes(
						node,
						msg,
						rule.RuleFixReplaceRange(utils.TrimNodeTextRange(sourceFile, node), replacement),
					)
					return
				}

				group := append([]*ast.Node{node}, duplicates...)
				sort.Slice(group, func(i, j int) bool {
					return group[i].Pos() < group[j].Pos()
				})

				// Only one overload should carry the compound fix to avoid overlapping fixes.
				if group[0] != node {
					reportWithoutFix()
					return
				}

				parts := make([]string, 0, len(group))
				for _, overload := range group {
					overloadParams, ok := methodParamsText(overload, sourceText, sourceFile)
					overloadReturnType := returnTypeText(sourceText, overload, sourceFile)
					if !ok || overloadParams == "" {
						reportWithoutFix()
						return
					}
					parts = append(parts, "("+overloadParams+" => "+overloadReturnType+")")
				}

				fixes := make([]rule.RuleFix, 0, 1+len(group)-1)
				fixes = append(fixes, rule.RuleFixReplaceRange(
					utils.TrimNodeTextRange(sourceFile, node),
					key+": "+strings.Join(parts, " & ")+delimiter,
				))
				for i := 1; i < len(group); i++ {
					fixes = append(fixes, rule.RuleFixRemoveRange(removalRangeForMember(sourceText, group[i], sourceFile)))
				}
				ctx.ReportNodeWithFixes(node, msg, fixes...)
			},
			ast.KindPropertySignature: func(node *ast.Node) {
				if style != StyleMethod {
					return
				}

				typeNode := propertyTypeNode(node)
				if typeNode == nil {
					return
				}

				msg := buildErrorPropertyMessage()
				if sourceFile == nil {
					ctx.ReportNode(node, msg)
					return
				}
				key := memberKey(node, sourceText, sourceFile)
				if key == "" {
					ctx.ReportNode(node, msg)
					return
				}

				functionTypeNode := unwrapParenthesizedType(typeNode)
				if functionTypeNode == nil || functionTypeNode.Kind != ast.KindFunctionType {
					ctx.ReportNode(node, msg)
					return
				}
				functionTypeRange := utils.TrimNodeTextRange(sourceFile, functionTypeNode)
				paramsText, ok := functionLikeParamsText(functionTypeNode, functionTypeRange.Pos(), sourceText, sourceFile)
				if !ok || paramsText == "" {
					ctx.ReportNode(node, msg)
					return
				}
				returnType := returnTypeText(sourceText, functionTypeNode, sourceFile)
				delimiter := delimiterForNode(sourceText, node, sourceFile)
				replacement := key + paramsText + ": " + returnType + delimiter
				ctx.ReportNodeWithFixes(
					node,
					msg,
					rule.RuleFixReplaceRange(utils.TrimNodeTextRange(sourceFile, node), replacement),
				)
			},
		}
	},
})
