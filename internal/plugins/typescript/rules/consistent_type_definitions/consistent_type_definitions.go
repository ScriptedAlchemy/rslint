package consistent_type_definitions

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type DefinitionStyle string

const (
	DefinitionStyleInterface DefinitionStyle = "interface"
	DefinitionStyleType      DefinitionStyle = "type"
)

type ConsistentTypeDefinitionsOptions struct {
	Style DefinitionStyle `json:"style"`
}

// ConsistentTypeDefinitionsRule enforces consistent type definitions
var ConsistentTypeDefinitionsRule = rule.CreateRule(rule.Rule{
	Name: "consistent-type-definitions",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := ConsistentTypeDefinitionsOptions{
		Style: DefinitionStyleInterface,
	}

	// Parse options
	if options != nil {
		if optArray, isArray := options.([]interface{}); isArray && len(optArray) > 0 {
			if str, ok := optArray[0].(string); ok {
				opts.Style = DefinitionStyle(str)
			}
		} else if str, ok := options.(string); ok {
			opts.Style = DefinitionStyle(str)
		}
	}

	// Helper to check if a type is an object type literal (without index signatures or mapped types)
	isObjectTypeLiteral := func(typeNode *ast.Node) bool {
		if typeNode == nil {
			return false
		}
		if typeNode.Kind != ast.KindTypeLiteral {
			return false
		}

		// Check if type literal contains index signatures or mapped types
		typeLiteral := typeNode.AsTypeLiteralNode()
		if typeLiteral == nil || typeLiteral.Members == nil {
			return true
		}

		// If any member is an index signature, this is not a simple object type
		for _, member := range typeLiteral.Members.Nodes {
			if member.Kind == ast.KindIndexSignature {
				return false
			}
		}

		return true
	}

	// Helper to check if a type alias is a simple object type (not a union, intersection, etc.)
	isSimpleObjectType := func(typeNode *ast.Node) bool {
		if typeNode == nil {
			return false
		}

		// Unwrap parenthesized types recursively.
		for typeNode != nil && typeNode.Kind == ast.KindParenthesizedType {
			parenthesized := typeNode.AsParenthesizedTypeNode()
			if parenthesized == nil {
				return false
			}
			typeNode = parenthesized.Type
		}

		return isObjectTypeLiteral(typeNode)
	}

	// Helper to check if interface is in a globally-scoped module
	isInGlobalModule := func(node *ast.Node) bool {
		current := node.Parent
		for current != nil {
			if current.Kind == ast.KindModuleDeclaration {
				moduleDecl := current.AsModuleDeclaration()
				if moduleDecl != nil && moduleDecl.Name() != nil {
					// Check if module name is 'global'
					if ast.IsIdentifier(moduleDecl.Name()) {
						ident := moduleDecl.Name().AsIdentifier()
						if ident != nil && ident.Text == "global" && utils.IncludesModifier(moduleDecl, ast.KindDeclareKeyword) {
							return true
						}
					}
				}
			}
			current = current.Parent
		}
		return false
	}

	unwrapParenthesizedType := func(typeNode *ast.Node) *ast.Node {
		for typeNode != nil && typeNode.Kind == ast.KindParenthesizedType {
			parenthesized := typeNode.AsParenthesizedTypeNode()
			if parenthesized == nil {
				return nil
			}
			typeNode = parenthesized.Type
		}
		return typeNode
	}

	findTokenInNode := func(node *ast.Node, kind ast.Kind, predicate func(token *ast.Node) bool) *ast.Node {
		var matched *ast.Node
		utils.ForEachToken(node, func(token *ast.Node) {
			if matched != nil || token == nil || token.Kind != kind {
				return
			}
			if predicate == nil || predicate(token) {
				matched = token
			}
		}, ctx.SourceFile)
		return matched
	}

	findLastTokenInNode := func(node *ast.Node, kind ast.Kind) *ast.Node {
		var matched *ast.Node
		utils.ForEachToken(node, func(token *ast.Node) {
			if token != nil && token.Kind == kind {
				matched = token
			}
		}, ctx.SourceFile)
		return matched
	}

	nodeText := func(text string, start int, end int) string {
		if start < 0 || end > len(text) || start > end {
			return ""
		}
		return text[start:end]
	}

	normalizeSpaces := regexp.MustCompile(`\s+`)
	removeDefaultKeyword := regexp.MustCompile(`\bdefault\b\s*`)
	removeExportKeyword := regexp.MustCompile(`\bexport\b\s*`)

	trimmedTextRange := func(node *ast.Node) (int, int, bool) {
		if node == nil || ctx.SourceFile == nil {
			return 0, 0, false
		}
		trimmed := utils.TrimNodeTextRange(ctx.SourceFile, node)
		return trimmed.Pos(), trimmed.End(), true
	}

	buildInterfaceFromTypeAliasFixes := func(node *ast.Node, typeAlias *ast.TypeAliasDeclaration) []rule.RuleFix {
		if node == nil || typeAlias == nil || typeAlias.Name() == nil || typeAlias.Type == nil || ctx.SourceFile == nil {
			return nil
		}
		typeLiteral := unwrapParenthesizedType(typeAlias.Type)
		if typeLiteral == nil {
			return nil
		}

		typeLiteralStart, typeLiteralEnd, ok := trimmedTextRange(typeLiteral)
		if !ok {
			return nil
		}
		_, trimmedNameEnd, ok := trimmedTextRange(typeAlias.Name())
		if !ok {
			return nil
		}
		typeKeyword := findTokenInNode(node, ast.KindTypeKeyword, func(token *ast.Node) bool {
			return token.Pos() < typeAlias.Name().Pos()
		})
		equalsToken := findLastTokenInNode(node, ast.KindEqualsToken)
		if equalsToken != nil && (equalsToken.Pos() < typeAlias.Name().End() || equalsToken.End() > typeAlias.Type.Pos()) {
			equalsToken = nil
			utils.ForEachToken(node, func(token *ast.Node) {
				if token == nil || token.Kind != ast.KindEqualsToken {
					return
				}
				if token.Pos() < typeAlias.Name().End() || token.End() > typeAlias.Type.Pos() {
					return
				}
				equalsToken = token
			}, ctx.SourceFile)
		}
		if equalsToken == nil {
			equalsToken = findTokenInNode(node, ast.KindEqualsToken, func(token *ast.Node) bool {
				return typeAlias.Name().End() <= token.Pos() && token.End() <= typeAlias.Type.Pos()
			})
		}
		if equalsToken != nil && equalsToken.Pos() < typeAlias.Name().End() {
			equalsToken = nil
		}
		if equalsToken != nil && equalsToken.End() > typeLiteralStart {
			equalsToken = nil
		}
		if equalsToken == nil {
			return nil
		}

		equalsTokenRange := utils.TrimNodeTextRange(ctx.SourceFile, equalsToken)
		sourceText := ctx.SourceFile.Text()
		equalsReplacementStart := equalsTokenRange.Pos()
		for equalsReplacementStart > trimmedNameEnd {
			ch := sourceText[equalsReplacementStart-1]
			if ch != ' ' && ch != '\t' {
				break
			}
			equalsReplacementStart--
		}

		trimmedNodeRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
		fixes := []rule.RuleFix{
			rule.RuleFixReplaceRange(utils.TrimNodeTextRange(ctx.SourceFile, typeKeyword), "interface"),
			rule.RuleFixReplaceRange(equalsTokenRange.WithPos(equalsReplacementStart).WithEnd(typeLiteralStart), " "),
		}
		if typeLiteralEnd < trimmedNodeRange.End() {
			fixes = append(fixes, rule.RuleFixRemoveRange(typeLiteral.Loc.WithPos(typeLiteralEnd).WithEnd(trimmedNodeRange.End())))
		}
		return fixes
	}

	buildTypeFromInterfaceFixes := func(node *ast.Node, interfaceDecl *ast.InterfaceDeclaration) []rule.RuleFix {
		if node == nil || interfaceDecl == nil || interfaceDecl.Name() == nil || ctx.SourceFile == nil {
			return nil
		}
		sourceText := ctx.SourceFile.Text()
		nodeRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
		interfaceKeyword := findTokenInNode(node, ast.KindInterfaceKeyword, func(token *ast.Node) bool {
			return token.Pos() < interfaceDecl.Name().Pos()
		})
		openBrace := findTokenInNode(node, ast.KindOpenBraceToken, func(token *ast.Node) bool {
			return token.Pos() >= interfaceDecl.Name().End()
		})
		closeBrace := findLastTokenInNode(node, ast.KindCloseBraceToken)
		if interfaceKeyword == nil || openBrace == nil || closeBrace == nil {
			return nil
		}

		nameStart, nameEnd, ok := trimmedTextRange(interfaceDecl.Name())
		if !ok {
			return nil
		}
		name := nodeText(sourceText, nameStart, nameEnd)
		if name == "" {
			return nil
		}

		openBraceRange := utils.TrimNodeTextRange(ctx.SourceFile, openBrace)
		extendsKeyword := findTokenInNode(node, ast.KindExtendsKeyword, func(token *ast.Node) bool {
			return token.Pos() >= nameEnd && token.Pos() < openBraceRange.Pos()
		})
		nameAndTypeParamsEnd := openBraceRange.Pos()
		if extendsKeyword != nil {
			nameAndTypeParamsEnd = extendsKeyword.Pos()
		}
		nameAndTypeParams := strings.TrimSpace(nodeText(sourceText, nameStart, nameAndTypeParamsEnd))
		if nameAndTypeParams == "" {
			return nil
		}

		keywordRange := utils.TrimNodeTextRange(ctx.SourceFile, interfaceKeyword)
		prefix := nodeText(sourceText, nodeRange.Pos(), keywordRange.Pos())
		if prefix == "" && nodeRange.Pos() != keywordRange.Pos() {
			return nil
		}
		if prefix != "" && !unicode.IsSpace(rune(prefix[len(prefix)-1])) {
			prefix += " "
		}

		hasDefaultExportModifier := false
		if modifiers := node.Modifiers(); modifiers != nil {
			for _, modifier := range modifiers.Nodes {
				if modifier != nil && modifier.Kind == ast.KindDefaultKeyword {
					hasDefaultExportModifier = true
					break
				}
			}
		}
		if hasDefaultExportModifier {
			prefix = normalizeSpaces.ReplaceAllString(prefix, " ")
			prefix = removeDefaultKeyword.ReplaceAllString(prefix, "")
			prefix = removeExportKeyword.ReplaceAllString(prefix, "")
			prefix = strings.TrimLeft(prefix, " ")
			if prefix != "" && !unicode.IsSpace(rune(prefix[len(prefix)-1])) {
				prefix += " "
			}
		}

		closeBraceRange := utils.TrimNodeTextRange(ctx.SourceFile, closeBrace)
		bodyText := nodeText(sourceText, openBraceRange.Pos(), closeBraceRange.End())
		if bodyText == "" {
			return nil
		}
		replacement := prefix + "type " + nameAndTypeParams + " = " + bodyText
		if interfaceDecl.HeritageClauses != nil {
			for _, clauseNode := range interfaceDecl.HeritageClauses.Nodes {
				clause := clauseNode.AsHeritageClause()
				if clause == nil || clause.Token != ast.KindExtendsKeyword || clause.Types == nil {
					continue
				}
				for _, heritageType := range clause.Types.Nodes {
					heritageText := strings.TrimSpace(nodeText(sourceText, heritageType.Pos(), heritageType.End()))
					if heritageText != "" {
						replacement += " & " + heritageText
					}
				}
			}
		}
		if hasDefaultExportModifier {
			replacement += "\nexport default " + name
		}

		return []rule.RuleFix{
			rule.RuleFixReplaceRange(nodeRange, replacement),
		}
	}

	checkTypeAlias := func(node *ast.Node) {
		if opts.Style != DefinitionStyleInterface {
			return
		}

		typeAlias := node.AsTypeAliasDeclaration()
		if typeAlias == nil {
			return
		}

		// Only report if it's a simple object type literal
		if !isSimpleObjectType(typeAlias.Type) {
			return
		}

		reportNode := node
		if typeAlias.Name() != nil {
			reportNode = typeAlias.Name()
		}

		msg := rule.RuleMessage{
			Id:          "interfaceOverType",
			Description: "Use an interface instead of a type literal.",
		}
		if fixes := buildInterfaceFromTypeAliasFixes(node, typeAlias); len(fixes) > 0 {
			ctx.ReportNodeWithFixes(reportNode, msg, fixes...)
		} else {
			ctx.ReportNode(reportNode, msg)
		}
	}

	checkInterface := func(node *ast.Node) {
		if opts.Style != DefinitionStyleType {
			return
		}

		interfaceDecl := node.AsInterfaceDeclaration()
		if interfaceDecl == nil {
			return
		}

		// Don't fix interfaces in global modules (see typescript-eslint #2707)
		reportNode := node
		if interfaceDecl.Name() != nil {
			reportNode = interfaceDecl.Name()
		}

		msg := rule.RuleMessage{
			Id:          "typeOverInterface",
			Description: "Use a type literal instead of an interface.",
		}

		if isInGlobalModule(node) {
			ctx.ReportNode(reportNode, msg)
			return
		}

		if fixes := buildTypeFromInterfaceFixes(node, interfaceDecl); len(fixes) > 0 {
			ctx.ReportNodeWithFixes(reportNode, msg, fixes...)
		} else {
			ctx.ReportNode(reportNode, msg)
		}
	}

	return rule.RuleListeners{
		ast.KindTypeAliasDeclaration: checkTypeAlias,
		ast.KindInterfaceDeclaration: checkInterface,
	}
}
