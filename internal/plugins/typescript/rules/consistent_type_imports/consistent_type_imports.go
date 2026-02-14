package consistent_type_imports

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ConsistentTypeImportsOptions struct {
	Prefer                  string `json:"prefer"`
	DisallowTypeAnnotations bool   `json:"disallowTypeAnnotations"`
	FixStyle                string `json:"fixStyle"`
}

type importedBinding struct {
	localName                    string
	symbol                       *ast.Symbol
	importDecl                   *ast.Node
	importSource                 string
	specifierNode                *ast.Node
	specifierKind                string
	isInlineType                 bool
	isTypeImport                 bool
	usedAsType                   bool
	usedAsValue                  bool
	usedAsDecoratorMetadataValue bool
}

const (
	importSpecifierKindDefault   = "default"
	importSpecifierKindNamespace = "namespace"
	importSpecifierKindNamed     = "named"
)

type usageContext struct {
	decoratorMetadataEnabled bool
	jsxValueNames            map[string]bool
	hasJSXSyntax             bool
}

// ConsistentTypeImportsRule enforces consistent type imports
var ConsistentTypeImportsRule = rule.CreateRule(rule.Rule{
	Name: "consistent-type-imports",
	Run:  run,
})

func parseOptions(options any) ConsistentTypeImportsOptions {
	opts := ConsistentTypeImportsOptions{
		Prefer:                  "type-imports",
		DisallowTypeAnnotations: true,
		FixStyle:                "separate-type-imports",
	}

	if options == nil {
		return opts
	}

	raw := options
	if optArray, isArray := options.([]interface{}); isArray {
		if len(optArray) == 0 {
			return opts
		}
		raw = optArray[0]
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return opts
	}
	_ = json.Unmarshal(encoded, &opts)
	if opts.Prefer != "type-imports" && opts.Prefer != "no-type-imports" {
		opts.Prefer = "type-imports"
	}
	if opts.FixStyle != "inline-type-imports" && opts.FixStyle != "separate-type-imports" {
		opts.FixStyle = "separate-type-imports"
	}
	return opts
}

func isImportDeclarationIdentifier(node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindImportDeclaration:
			return true
		case ast.KindSourceFile:
			return false
		}
	}
	return false
}

func walk(node *ast.Node, visit func(n *ast.Node)) {
	if node == nil {
		return
	}
	visit(node)
	node.ForEachChild(func(child *ast.Node) bool {
		walk(child, visit)
		return false
	})
}

func localBindingNodeFromImportClause(importClause *ast.ImportClause) *ast.Node {
	if importClause == nil {
		return nil
	}
	if importClause.Name() != nil {
		return importClause.Name().AsNode()
	}
	return nil
}

func nodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	text := sourceFile.Text()
	r := utils.TrimNodeTextRange(sourceFile, node)
	if r.Pos() < 0 || r.End() > len(text) || r.Pos() >= r.End() {
		return ""
	}
	return text[r.Pos():r.End()]
}

func addBinding(bindings *[]*importedBinding, ctx rule.RuleContext, importDecl *ast.Node, importSource string, localNode *ast.Node, specifierNode *ast.Node, specifierKind string, isInlineType bool, isTypeImport bool) {
	if localNode == nil || localNode.Kind != ast.KindIdentifier {
		return
	}
	binding := &importedBinding{
		localName:     localNode.AsIdentifier().Text,
		importDecl:    importDecl,
		importSource:  importSource,
		specifierNode: specifierNode,
		specifierKind: specifierKind,
		isInlineType:  isInlineType,
		isTypeImport:  isTypeImport,
	}
	if ctx.TypeChecker != nil {
		binding.symbol = ctx.TypeChecker.GetSymbolAtLocation(localNode)
	}
	*bindings = append(*bindings, binding)
}

func isTypeOnlyImportDeclaration(sourceFile *ast.SourceFile, importDeclNode *ast.Node, importClause *ast.ImportClause) bool {
	if importClause != nil && importClause.IsTypeOnly() {
		return true
	}
	if sourceFile == nil || importDeclNode == nil {
		return false
	}
	r := utils.TrimNodeTextRange(sourceFile, importDeclNode)
	start := r.Pos()
	end := r.End()
	sourceText := sourceFile.Text()
	if start < 0 || end > len(sourceText) || start >= end {
		return false
	}
	importText := strings.TrimSpace(sourceText[start:end])
	return strings.HasPrefix(importText, "import type ")
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

func tokenRange(sourceFile *ast.SourceFile, token *ast.Node) core.TextRange {
	return utils.TrimNodeTextRange(sourceFile, token)
}

func removeTypeKeywordRange(sourceFile *ast.SourceFile, node *ast.Node, maxPos int) (core.TextRange, bool) {
	if sourceFile == nil || node == nil {
		return core.NewTextRange(0, 0), false
	}
	typeToken := findFirstToken(node, ast.KindTypeKeyword, func(token *ast.Node) bool {
		if maxPos < 0 {
			return true
		}
		return tokenRange(sourceFile, token).Pos() < maxPos
	}, sourceFile)
	if typeToken == nil {
		return core.NewTextRange(0, 0), false
	}
	typeTokenRange := tokenRange(sourceFile, typeToken)
	sourceText := sourceFile.Text()
	removeEnd := typeTokenRange.End()
	for removeEnd < len(sourceText) && unicode.IsSpace(rune(sourceText[removeEnd])) {
		removeEnd++
	}
	return core.NewTextRange(typeTokenRange.Pos(), removeEnd), true
}

func importHasSemicolon(sourceFile *ast.SourceFile, node *ast.Node) bool {
	if sourceFile == nil || node == nil {
		return false
	}
	text := sourceFile.Text()
	r := utils.TrimNodeTextRange(sourceFile, node)
	if r.Pos() < 0 || r.End() > len(text) || r.Pos() >= r.End() {
		return false
	}
	return strings.HasSuffix(strings.TrimSpace(text[r.Pos():r.End()]), ";")
}

func skipLeadingTrivia(text string) int {
	i := 0
	for i < len(text) {
		for i < len(text) && unicode.IsSpace(rune(text[i])) {
			i++
		}
		if i+1 < len(text) && text[i] == '/' && text[i+1] == '*' {
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return i
			}
			i += 2 + end + 2
			continue
		}
		if i+1 < len(text) && text[i] == '/' && text[i+1] == '/' {
			end := strings.IndexByte(text[i+2:], '\n')
			if end < 0 {
				return len(text)
			}
			i += 2 + end + 1
			continue
		}
		break
	}
	return i
}

func addInlineTypePrefix(specifierText string) string {
	i := skipLeadingTrivia(specifierText)
	if i+4 < len(specifierText) &&
		specifierText[i:i+4] == "type" &&
		unicode.IsSpace(rune(specifierText[i+4])) {
		return specifierText
	}
	return specifierText[:i] + "type " + specifierText[i:]
}

func removeInlineTypePrefix(specifierText string) string {
	i := skipLeadingTrivia(specifierText)
	if i+4 > len(specifierText) || specifierText[i:i+4] != "type" {
		return specifierText
	}
	j := i + 4
	for j < len(specifierText) && unicode.IsSpace(rune(specifierText[j])) {
		j++
	}
	if j == i+4 {
		return specifierText
	}
	return specifierText[:i] + specifierText[j:]
}

func splitImportSpecifiersBody(body string) []string {
	if body == "" {
		return []string{""}
	}
	segments := []string{}
	start := 0
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < len(body); i++ {
		ch := body[i]
		if inLineComment {
			if ch == '\n' || ch == '\r' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < len(body) && body[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if inSingleQuote {
			if ch == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if ch == '\'' {
				inSingleQuote = false
			}
			continue
		}
		if inDoubleQuote {
			if ch == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if ch == '"' {
				inDoubleQuote = false
			}
			continue
		}
		if inBacktick {
			if ch == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		if ch == '/' && i+1 < len(body) {
			next := body[i+1]
			if next == '/' {
				inLineComment = true
				i++
				continue
			}
			if next == '*' {
				inBlockComment = true
				i++
				continue
			}
		}
		switch ch {
		case '\'':
			inSingleQuote = true
		case '"':
			inDoubleQuote = true
		case '`':
			inBacktick = true
		case ',':
			segments = append(segments, body[start:i])
			start = i + 1
		}
	}
	segments = append(segments, body[start:])
	return segments
}

func buildImportStatement(moduleSpecifier string, defaultText string, namespaceText string, namedTexts []string, topLevelType bool, hasSemicolon bool) string {
	builder := strings.Builder{}
	builder.WriteString("import")
	if topLevelType {
		builder.WriteString(" type")
	}
	builder.WriteString(" ")
	parts := []string{}
	if defaultText != "" {
		parts = append(parts, defaultText)
	}
	if namespaceText != "" {
		parts = append(parts, namespaceText)
	}
	if len(namedTexts) > 0 {
		namedBody := strings.Join(namedTexts, ", ")
		if topLevelType && len(namedTexts) == 1 {
			parts = append(parts, "{ "+namedBody+"}")
		} else {
			parts = append(parts, "{ "+namedBody+" }")
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "{}")
	}
	builder.WriteString(strings.Join(parts, ", "))
	builder.WriteString(" from ")
	builder.WriteString(moduleSpecifier)
	if hasSemicolon {
		builder.WriteString(";")
	}
	return builder.String()
}

func nodeLineIndent(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	text := sourceFile.Text()
	r := utils.TrimNodeTextRange(sourceFile, node)
	start := r.Pos()
	if start < 0 || start > len(text) {
		return ""
	}
	lineStart := start
	for lineStart > 0 {
		ch := text[lineStart-1]
		if ch == '\n' || ch == '\r' {
			break
		}
		lineStart--
	}
	indent := text[lineStart:start]
	for _, ch := range indent {
		if ch != ' ' && ch != '\t' {
			return ""
		}
	}
	return indent
}

func joinImportLines(lines []string, indent string) string {
	if len(lines) == 0 {
		return ""
	}
	result := lines[0]
	for i := 1; i < len(lines); i++ {
		result += "\n" + indent + lines[i]
	}
	return result
}

func buildImportStatementWithRawNamedBody(moduleSpecifier string, defaultText string, namespaceText string, namedBody string, topLevelType bool, hasSemicolon bool) string {
	builder := strings.Builder{}
	builder.WriteString("import")
	if topLevelType {
		builder.WriteString(" type")
	}
	builder.WriteString(" ")
	parts := []string{}
	if defaultText != "" {
		parts = append(parts, defaultText)
	}
	if namespaceText != "" {
		parts = append(parts, namespaceText)
	}
	if namedBody != "" {
		parts = append(parts, "{"+namedBody+"}")
	}
	if len(parts) == 0 {
		parts = append(parts, "{}")
	}
	builder.WriteString(strings.Join(parts, ", "))
	builder.WriteString(" from ")
	builder.WriteString(moduleSpecifier)
	if hasSemicolon {
		builder.WriteString(";")
	}
	return builder.String()
}

func extractNamedImportBodyForSubset(sourceFile *ast.SourceFile, importDeclNode *ast.Node, namedImportNodes []*ast.Node, includeSet map[*ast.Node]bool) (string, bool) {
	if sourceFile == nil || importDeclNode == nil {
		return "", false
	}
	openBrace := findFirstToken(importDeclNode, ast.KindOpenBraceToken, nil, sourceFile)
	closeBrace := findFirstToken(importDeclNode, ast.KindCloseBraceToken, nil, sourceFile)
	if openBrace == nil || closeBrace == nil {
		return "", false
	}
	openRange := tokenRange(sourceFile, openBrace)
	closeRange := tokenRange(sourceFile, closeBrace)
	sourceText := sourceFile.Text()
	if openRange.End() < 0 || closeRange.Pos() > len(sourceText) || openRange.End() > closeRange.Pos() {
		return "", false
	}
	inside := sourceText[openRange.End():closeRange.Pos()]
	segments := splitImportSpecifiersBody(inside)
	if len(segments) < len(namedImportNodes) {
		return "", false
	}
	selected := []string{}
	for i, specifierNode := range namedImportNodes {
		if !includeSet[specifierNode] {
			continue
		}
		selected = append(selected, segments[i])
	}
	if len(selected) == 0 {
		return "", true
	}
	body := strings.Join(selected, ",")
	if len(segments) > len(namedImportNodes) && includeSet[namedImportNodes[len(namedImportNodes)-1]] {
		body += "," + segments[len(namedImportNodes)]
	}
	return body, true
}

func interSpecifierCommentPrefix(sourceFile *ast.SourceFile, leftNode *ast.Node, rightNode *ast.Node) string {
	if sourceFile == nil || leftNode == nil || rightNode == nil {
		return ""
	}
	text := sourceFile.Text()
	leftRange := utils.TrimNodeTextRange(sourceFile, leftNode)
	rightRange := utils.TrimNodeTextRange(sourceFile, rightNode)
	if leftRange.End() < 0 || rightRange.Pos() > len(text) || leftRange.End() >= rightRange.Pos() {
		return ""
	}
	between := text[leftRange.End():rightRange.Pos()]
	if comma := strings.IndexByte(between, ','); comma >= 0 {
		between = between[comma+1:]
	}
	between = strings.TrimSpace(between)
	if between == "" {
		return ""
	}
	return between + " "
}

func splitDefaultImportSeparators(sourceFile *ast.SourceFile, defaultNode *ast.Node, nextNode *ast.Node) (string, string) {
	if sourceFile == nil || defaultNode == nil || nextNode == nil {
		return "", ""
	}
	text := sourceFile.Text()
	defaultRange := utils.TrimNodeTextRange(sourceFile, defaultNode)
	nextRange := utils.TrimNodeTextRange(sourceFile, nextNode)
	if defaultRange.End() < 0 || nextRange.Pos() > len(text) || defaultRange.End() >= nextRange.Pos() {
		return "", ""
	}
	between := text[defaultRange.End():nextRange.Pos()]
	comma := strings.IndexByte(between, ',')
	if comma < 0 {
		return "", ""
	}
	left := strings.TrimSpace(between[:comma])
	right := strings.TrimSpace(between[comma+1:])
	defaultSuffix := ""
	nextPrefix := ""
	if left != "" {
		defaultSuffix = " " + left
	}
	if right != "" {
		nextPrefix = right + " "
	}
	return defaultSuffix, nextPrefix
}

func collectImportBindings(ctx rule.RuleContext) ([]*importedBinding, map[*ast.Node][]*importedBinding) {
	bindings := []*importedBinding{}
	perImport := map[*ast.Node][]*importedBinding{}

	sourceFile := ctx.SourceFile
	if sourceFile == nil || sourceFile.Statements == nil {
		return bindings, perImport
	}

	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindImportDeclaration {
			continue
		}
		importDecl := statement.AsImportDeclaration()
		if importDecl == nil || importDecl.ImportClause == nil {
			continue
		}
		importClause := importDecl.ImportClause.AsImportClause()
		if importClause == nil {
			continue
		}
		importSource := ""
		if importDecl.ModuleSpecifier != nil {
			moduleLiteral := importDecl.ModuleSpecifier.AsStringLiteral()
			if moduleLiteral != nil {
				importSource = moduleLiteral.Text
			}
		}

		isTypeImportDecl := isTypeOnlyImportDeclaration(ctx.SourceFile, statement, importClause)

		if defaultLocal := localBindingNodeFromImportClause(importClause); defaultLocal != nil {
			addBinding(&bindings, ctx, statement, importSource, defaultLocal, defaultLocal, importSpecifierKindDefault, false, isTypeImportDecl)
		}

		if importClause.NamedBindings == nil {
			continue
		}
		switch importClause.NamedBindings.Kind {
		case ast.KindNamespaceImport:
			namespaceImport := importClause.NamedBindings.AsNamespaceImport()
			if namespaceImport != nil && namespaceImport.Name() != nil {
				addBinding(&bindings, ctx, statement, importSource, namespaceImport.Name(), importClause.NamedBindings, importSpecifierKindNamespace, false, isTypeImportDecl)
			}
		case ast.KindNamedImports:
			namedImports := importClause.NamedBindings.AsNamedImports()
			if namedImports == nil || namedImports.Elements == nil {
				continue
			}
			for _, element := range namedImports.Elements.Nodes {
				if element == nil || element.Kind != ast.KindImportSpecifier {
					continue
				}
				importSpecifier := element.AsImportSpecifier()
				if importSpecifier == nil || importSpecifier.Name() == nil {
					continue
				}
				addBinding(&bindings, ctx, statement, importSource, importSpecifier.Name(), element, importSpecifierKindNamed, importSpecifier.IsTypeOnly, isTypeImportDecl)
			}
		}
	}

	for _, binding := range bindings {
		perImport[binding.importDecl] = append(perImport[binding.importDecl], binding)
	}
	return bindings, perImport
}

func markBindingUsages(ctx rule.RuleContext, bindings []*importedBinding) {
	if len(bindings) == 0 {
		return
	}
	usageCtx := collectUsageContext(ctx)

	symbolBindings := map[*ast.Symbol][]*importedBinding{}
	nameBindings := map[string][]*importedBinding{}
	for _, binding := range bindings {
		if binding.symbol != nil {
			symbolBindings[binding.symbol] = append(symbolBindings[binding.symbol], binding)
		}
		nameBindings[binding.localName] = append(nameBindings[binding.localName], binding)
		if usageCtx.hasJSXSyntax && usageCtx.jsxValueNames[binding.localName] {
			binding.usedAsValue = true
		}
	}

	walk(ctx.SourceFile.AsNode(), func(n *ast.Node) {
		if n == nil || n.Kind != ast.KindIdentifier || isImportDeclarationIdentifier(n) {
			return
		}
		identifier := n.AsIdentifier()
		if identifier == nil {
			return
		}

		matched := []*importedBinding{}
		hadSymbol := false
		var referenceSymbol *ast.Symbol
		if ctx.TypeChecker != nil {
			if symbol := ctx.TypeChecker.GetSymbolAtLocation(n); symbol != nil {
				hadSymbol = true
				referenceSymbol = symbol
				matched = append(matched, symbolBindings[symbol]...)
			}
		}
		allowAliasNameFallback := referenceSymbol != nil && referenceSymbol.Flags&ast.SymbolFlagsAlias != 0
		if len(matched) == 0 && (!hadSymbol || isTypeOnlyExportReference(n) || allowAliasNameFallback) {
			matched = append(matched, nameBindings[identifier.Text]...)
		}
		if len(matched) == 0 {
			return
		}

		isTypeUse := isTypeUse(n) || isTypeOnlyExportReference(n)
		for _, binding := range matched {
			if isTypeUse {
				binding.usedAsType = true
				if usageCtx.decoratorMetadataEnabled && isDecoratorMetadataTypeReference(n) {
					binding.usedAsValue = true
					binding.usedAsDecoratorMetadataValue = true
				}
			} else {
				binding.usedAsValue = true
			}
		}
	})
}

func collectUsageContext(ctx rule.RuleContext) usageContext {
	result := usageContext{
		decoratorMetadataEnabled: false,
		jsxValueNames:            map[string]bool{},
		hasJSXSyntax:             false,
	}
	if ctx.ParserOptions != nil {
		result.decoratorMetadataEnabled =
			ctx.ParserOptions.ExperimentalDecorators &&
				ctx.ParserOptions.EmitDecoratorMetadata
		for _, name := range parseJSXFactoryIdentifiersFromParserOptions(ctx.ParserOptions) {
			if name == "" {
				continue
			}
			result.jsxValueNames[name] = true
		}
	}
	if ctx.Program != nil && ctx.Program.Options() != nil {
		compilerOptions := ctx.Program.Options()
		if !result.decoratorMetadataEnabled {
			result.decoratorMetadataEnabled =
				compilerOptions.ExperimentalDecorators.IsTrue() &&
					compilerOptions.EmitDecoratorMetadata.IsTrue()
		}
		for _, name := range parseJSXFactoryIdentifiers(compilerOptions) {
			if name == "" {
				continue
			}
			result.jsxValueNames[name] = true
		}
	}
	if len(result.jsxValueNames) == 0 {
		result.jsxValueNames["React"] = true
	}
	result.hasJSXSyntax = hasJSXNodes(ctx.SourceFile.AsNode())
	return result
}

func parseJSXFactoryIdentifiersFromParserOptions(parserOptions *rule.RuleParserOptions) []string {
	if parserOptions == nil {
		return nil
	}
	return parseJSXFactoryIdentifierCandidates([]string{
		parserOptions.JSXPragma,
		parserOptions.JSXFragmentName,
	})
}

func parseJSXFactoryIdentifiers(compilerOptions *core.CompilerOptions) []string {
	if compilerOptions == nil {
		return nil
	}
	candidates := []string{compilerOptions.JsxFactory, compilerOptions.JsxFragmentFactory}
	return parseJSXFactoryIdentifierCandidates(candidates)
}

func parseJSXFactoryIdentifierCandidates(candidates []string) []string {
	names := []string{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		parts := strings.Split(candidate, ".")
		if len(parts) == 0 {
			continue
		}
		base := strings.TrimSpace(parts[0])
		if base != "" {
			names = append(names, base)
		}
	}
	return names
}

func hasJSXNodes(node *ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	walk(node, func(n *ast.Node) {
		if found || n == nil {
			return
		}
		switch n.Kind {
		case ast.KindJsxElement,
			ast.KindJsxSelfClosingElement,
			ast.KindJsxFragment:
			found = true
		}
	})
	return found
}

func hasDecorators(node *ast.Node) bool {
	if node == nil || node.Modifiers() == nil {
		return false
	}
	for _, modifier := range node.Modifiers().Nodes {
		if modifier != nil && modifier.Kind == ast.KindDecorator {
			return true
		}
	}
	return false
}

func propertyNameKey(nameNode *ast.Node) string {
	if nameNode == nil {
		return ""
	}
	switch nameNode.Kind {
	case ast.KindIdentifier:
		return "name:" + nameNode.AsIdentifier().Text
	case ast.KindStringLiteral:
		return "name:" + nameNode.AsStringLiteral().Text
	case ast.KindNumericLiteral:
		return "name:" + nameNode.AsNumericLiteral().Text
	case ast.KindNoSubstitutionTemplateLiteral:
		return "name:" + nameNode.AsNoSubstitutionTemplateLiteral().Text
	case ast.KindPrivateIdentifier:
		return "private:" + nameNode.AsPrivateIdentifier().Text
	case ast.KindComputedPropertyName:
		computed := nameNode.AsComputedPropertyName()
		if computed == nil || computed.Expression == nil {
			return ""
		}
		switch computed.Expression.Kind {
		case ast.KindIdentifier:
			return "computed:" + computed.Expression.AsIdentifier().Text
		case ast.KindStringLiteral:
			return "name:" + computed.Expression.AsStringLiteral().Text
		case ast.KindNumericLiteral:
			return "name:" + computed.Expression.AsNumericLiteral().Text
		case ast.KindNoSubstitutionTemplateLiteral:
			return "name:" + computed.Expression.AsNoSubstitutionTemplateLiteral().Text
		default:
			return ""
		}
	default:
		return ""
	}
}

func accessorHasDecoratedPair(node *ast.Node) bool {
	if node == nil || (node.Kind != ast.KindGetAccessor && node.Kind != ast.KindSetAccessor) {
		return false
	}
	currentName := propertyNameKey(node.Name())
	if currentName == "" || node.Parent == nil || !ast.IsClassLike(node.Parent) {
		return false
	}
	var members *ast.NodeList
	switch node.Parent.Kind {
	case ast.KindClassDeclaration:
		classDecl := node.Parent.AsClassDeclaration()
		if classDecl != nil {
			members = classDecl.Members
		}
	case ast.KindClassExpression:
		classExpr := node.Parent.AsClassExpression()
		if classExpr != nil {
			members = classExpr.Members
		}
	}
	if members == nil {
		return false
	}
	for _, member := range members.Nodes {
		if member == nil || member == node {
			continue
		}
		if member.Kind != ast.KindGetAccessor && member.Kind != ast.KindSetAccessor {
			continue
		}
		if !hasDecorators(member) {
			continue
		}
		if propertyNameKey(member.Name()) == currentName {
			return true
		}
	}
	return false
}

func isDecoratorMetadataTypeReference(node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindParameter,
			ast.KindMethodDeclaration,
			ast.KindPropertyDeclaration,
			ast.KindGetAccessor,
			ast.KindSetAccessor,
			ast.KindConstructor:
			if hasDecorators(current) || accessorHasDecoratedPair(current) {
				return true
			}
		case ast.KindClassDeclaration, ast.KindClassExpression:
			return hasDecorators(current)
		}
	}
	return false
}

func isTypeUse(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if ast.IsPartOfTypeNode(node) || ast.IsPartOfTypeQuery(node) {
		return true
	}
	current := node
	for current.Parent != nil {
		parent := current.Parent
		if ast.IsPartOfTypeNode(parent) || ast.IsPartOfTypeQuery(parent) {
			return true
		}
		switch parent.Kind {
		case ast.KindQualifiedName:
			current = parent
		case ast.KindPropertyAccessExpression:
			propertyAccess := parent.AsPropertyAccessExpression()
			if propertyAccess == nil || propertyAccess.Expression != current {
				return false
			}
			current = parent
		default:
			return false
		}
	}
	return false
}

func isTypeOnlyExportReference(node *ast.Node) bool {
	if node == nil {
		return false
	}
	seenExportSpecifier := false
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindExportSpecifier:
			seenExportSpecifier = true
			specifier := current.AsExportSpecifier()
			if specifier != nil && specifier.IsTypeOnly {
				return true
			}
		case ast.KindExportDeclaration:
			if !seenExportSpecifier {
				return false
			}
			exportDecl := current.AsExportDeclaration()
			return exportDecl != nil && exportDecl.IsTypeOnly
		case ast.KindSourceFile, ast.KindBlock:
			return false
		}
	}
	return false
}

func reportPreferNoTypeImports(ctx rule.RuleContext) {
	sourceFile := ctx.SourceFile
	if sourceFile == nil || sourceFile.Statements == nil {
		return
	}

	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindImportDeclaration {
			continue
		}
		importDecl := statement.AsImportDeclaration()
		if importDecl == nil || importDecl.ImportClause == nil {
			continue
		}
		importClause := importDecl.ImportClause.AsImportClause()
		if importClause == nil {
			continue
		}
		if isTypeOnlyImportDeclaration(ctx.SourceFile, statement, importClause) {
			message := rule.RuleMessage{
				Id:          "avoidImportType",
				Description: "Use an `import` instead of an `import type`.",
			}
			specifierStart := -1
			if importClause.Name() != nil {
				specifierStart = utils.TrimNodeTextRange(ctx.SourceFile, importClause.Name()).Pos()
			} else if importClause.NamedBindings != nil {
				specifierStart = utils.TrimNodeTextRange(ctx.SourceFile, importClause.NamedBindings).Pos()
			} else if importDecl.ModuleSpecifier != nil {
				specifierStart = utils.TrimNodeTextRange(ctx.SourceFile, importDecl.ModuleSpecifier).Pos()
			}
			removeRange, ok := removeTypeKeywordRange(ctx.SourceFile, statement, specifierStart)
			if !ok {
				ctx.ReportNode(statement, message)
			} else {
				ctx.ReportNodeWithFixes(statement, message, rule.RuleFixRemoveRange(removeRange))
			}
		}
		if importClause.NamedBindings == nil || importClause.NamedBindings.Kind != ast.KindNamedImports {
			continue
		}
		namedImports := importClause.NamedBindings.AsNamedImports()
		if namedImports == nil || namedImports.Elements == nil {
			continue
		}
		for _, element := range namedImports.Elements.Nodes {
			if element == nil || element.Kind != ast.KindImportSpecifier {
				continue
			}
			importSpecifier := element.AsImportSpecifier()
			if importSpecifier == nil || !importSpecifier.IsTypeOnly {
				continue
			}
			message := rule.RuleMessage{
				Id:          "avoidImportType",
				Description: "Use an `import` instead of an `import type`.",
			}
			removeRange, ok := removeTypeKeywordRange(ctx.SourceFile, element, -1)
			if !ok {
				ctx.ReportNode(element, message)
			} else {
				ctx.ReportNodeWithFixes(element, message, rule.RuleFixRemoveRange(removeRange))
			}
		}
	}
}

func isTypeOnlyNonInlineBinding(binding *importedBinding) bool {
	if binding == nil || binding.isTypeImport || binding.isInlineType {
		return false
	}
	return binding.usedAsType && !binding.usedAsValue
}

func buildPreferTypeImportFixes(ctx rule.RuleContext, importDeclNode *ast.Node, importBindings []*importedBinding, opts ConsistentTypeImportsOptions, existingTypeOnlyNamedImport *ast.Node) []rule.RuleFix {
	if ctx.SourceFile == nil || importDeclNode == nil {
		return nil
	}
	importDecl := importDeclNode.AsImportDeclaration()
	if importDecl == nil || importDecl.ImportClause == nil || importDecl.ModuleSpecifier == nil {
		return nil
	}
	importClause := importDecl.ImportClause.AsImportClause()
	if importClause == nil {
		return nil
	}
	moduleSpecifierText := nodeText(ctx.SourceFile, importDecl.ModuleSpecifier)
	if moduleSpecifierText == "" {
		return nil
	}
	hasSemicolon := importHasSemicolon(ctx.SourceFile, importDeclNode)
	indent := nodeLineIndent(ctx.SourceFile, importDeclNode)

	var defaultBinding *importedBinding
	var namespaceBinding *importedBinding
	namedBindingByNode := map[*ast.Node]*importedBinding{}
	nonInlineCount := 0
	typeOnlyCount := 0
	for _, binding := range importBindings {
		if binding == nil || binding.isTypeImport {
			continue
		}
		if !binding.isInlineType {
			nonInlineCount++
			if isTypeOnlyNonInlineBinding(binding) {
				typeOnlyCount++
			}
		}
		switch binding.specifierKind {
		case importSpecifierKindDefault:
			defaultBinding = binding
		case importSpecifierKindNamespace:
			namespaceBinding = binding
		case importSpecifierKindNamed:
			namedBindingByNode[binding.specifierNode] = binding
		}
	}
	if nonInlineCount == 0 || typeOnlyCount == 0 {
		return nil
	}
	allNonInlineAreTypeOnly := nonInlineCount == typeOnlyCount

	defaultText := ""
	if importClause.Name() != nil {
		defaultText = strings.TrimSpace(nodeText(ctx.SourceFile, importClause.Name()))
	}
	namespaceText := ""
	namedImportNodes := []*ast.Node{}
	if importClause.NamedBindings != nil {
		switch importClause.NamedBindings.Kind {
		case ast.KindNamespaceImport:
			namespaceText = strings.TrimSpace(nodeText(ctx.SourceFile, importClause.NamedBindings))
		case ast.KindNamedImports:
			namedImports := importClause.NamedBindings.AsNamedImports()
			if namedImports != nil && namedImports.Elements != nil {
				namedImportNodes = namedImports.Elements.Nodes
			}
		}
	}
	if opts.FixStyle == "inline-type-imports" && defaultText == "" && namespaceText == "" && len(namedImportNodes) > 0 {
		inlineFixes := []rule.RuleFix{}
		for _, specifierNode := range namedImportNodes {
			if specifierNode == nil {
				continue
			}
			if !isTypeOnlyNonInlineBinding(namedBindingByNode[specifierNode]) {
				continue
			}
			inlineFixes = append(inlineFixes, rule.RuleFixInsertBefore(ctx.SourceFile, specifierNode, "type "))
		}
		if len(inlineFixes) > 0 {
			return inlineFixes
		}
	}

	buildNamedTexts := func(includeTypeOnly bool, includeValue bool, inlineForType bool, removeInlineTypeKeyword bool) []string {
		texts := []string{}
		for _, specifierNode := range namedImportNodes {
			if specifierNode == nil {
				continue
			}
			specifierText := strings.TrimSpace(nodeText(ctx.SourceFile, specifierNode))
			if specifierText == "" {
				continue
			}
			binding := namedBindingByNode[specifierNode]
			isTypeOnly := isTypeOnlyNonInlineBinding(binding)
			isValue := !isTypeOnly
			if isTypeOnly && !includeTypeOnly {
				continue
			}
			if isValue && !includeValue {
				continue
			}
			if isTypeOnly && inlineForType {
				specifierText = addInlineTypePrefix(specifierText)
			}
			if removeInlineTypeKeyword {
				specifierText = removeInlineTypePrefix(specifierText)
			}
			texts = append(texts, specifierText)
		}
		return texts
	}

	inlineTypeForAllNamed := opts.FixStyle == "inline-type-imports" && allNonInlineAreTypeOnly
	typeNamedTexts := buildNamedTexts(true, false, inlineTypeForAllNamed, !inlineTypeForAllNamed)
	valueNamedTexts := buildNamedTexts(false, true, opts.FixStyle == "inline-type-imports", false)
	typeNamedSet := map[*ast.Node]bool{}
	valueNamedSet := map[*ast.Node]bool{}
	for _, specifierNode := range namedImportNodes {
		if isTypeOnlyNonInlineBinding(namedBindingByNode[specifierNode]) {
			typeNamedSet[specifierNode] = true
		} else {
			valueNamedSet[specifierNode] = true
		}
	}
	typeNamedRawBody, hasTypeNamedRawBody := extractNamedImportBodyForSubset(ctx.SourceFile, importDeclNode, namedImportNodes, typeNamedSet)
	valueNamedRawBody, hasValueNamedRawBody := extractNamedImportBodyForSubset(ctx.SourceFile, importDeclNode, namedImportNodes, valueNamedSet)
	if hasTypeNamedRawBody {
		trimmedTypeNamedRawBody := strings.TrimRight(typeNamedRawBody, " \t\r\n")
		if strings.HasSuffix(trimmedTypeNamedRawBody, ",") {
			typeNamedRawBody = strings.TrimSuffix(trimmedTypeNamedRawBody, ",")
		}
	}
	prependFixes := []rule.RuleFix{}
	if !allNonInlineAreTypeOnly &&
		opts.FixStyle != "inline-type-imports" &&
		len(typeNamedTexts) > 0 &&
		existingTypeOnlyNamedImport != nil &&
		existingTypeOnlyNamedImport != importDeclNode {
		existingDecl := existingTypeOnlyNamedImport.AsImportDeclaration()
		if existingDecl != nil && existingDecl.ImportClause != nil {
			existingClause := existingDecl.ImportClause.AsImportClause()
			if existingClause != nil &&
				existingClause.Name() == nil &&
				existingClause.NamedBindings != nil &&
				existingClause.NamedBindings.Kind == ast.KindNamedImports {
				closeBrace := findFirstToken(existingTypeOnlyNamedImport, ast.KindCloseBraceToken, nil, ctx.SourceFile)
				if closeBrace != nil {
					closeRange := tokenRange(ctx.SourceFile, closeBrace)
					insertText := "," + typeNamedRawBody
					if typeNamedRawBody == "" || !hasTypeNamedRawBody {
						insertText = ", " + strings.Join(typeNamedTexts, ", ")
					}
					prependFixes = append(prependFixes, rule.RuleFixReplaceRange(core.NewTextRange(closeRange.Pos(), closeRange.Pos()), insertText))
					typeNamedTexts = nil
					typeNamedRawBody = ""
					hasTypeNamedRawBody = false
				}
			}
		}
	}

	typeLines := []string{}
	valueDefaultText := defaultText
	valueNamespaceText := namespaceText
	defaultTypeText := defaultText
	valueNamedPrefix := ""
	moveDefault := defaultBinding != nil && isTypeOnlyNonInlineBinding(defaultBinding)
	moveNamespace := namespaceBinding != nil && isTypeOnlyNonInlineBinding(namespaceBinding)
	if moveDefault {
		valueDefaultText = ""
	}
	if moveNamespace {
		valueNamespaceText = ""
	}
	if moveDefault &&
		!moveNamespace &&
		importClause.Name() != nil &&
		importClause.NamedBindings != nil &&
		importClause.NamedBindings.Kind == ast.KindNamespaceImport {
		if prefix := interSpecifierCommentPrefix(ctx.SourceFile, importClause.Name(), importClause.NamedBindings); prefix != "" {
			valueNamespaceText = prefix + namespaceText
		}
	}
	if moveDefault &&
		importClause.Name() != nil &&
		importClause.NamedBindings != nil &&
		importClause.NamedBindings.Kind == ast.KindNamedImports {
		defaultSuffix, namedPrefix := splitDefaultImportSeparators(ctx.SourceFile, importClause.Name(), importClause.NamedBindings)
		defaultTypeText = defaultText + defaultSuffix
		valueNamedPrefix = namedPrefix
	}

	if allNonInlineAreTypeOnly {
		lines := []string{}
		if len(typeNamedTexts) > 0 {
			topLevelTypeForNamed := opts.FixStyle != "inline-type-imports"
			if topLevelTypeForNamed && hasTypeNamedRawBody && typeNamedRawBody != "" {
				lines = append(lines, buildImportStatementWithRawNamedBody(moduleSpecifierText, "", "", typeNamedRawBody, true, hasSemicolon))
			} else if !topLevelTypeForNamed && moveDefault {
				// When splitting a default type import from named type-only imports,
				// upstream keeps compact braces: `import {type A, type B} ...`.
				lines = append(lines, buildImportStatementWithRawNamedBody(moduleSpecifierText, "", "", strings.Join(typeNamedTexts, ", "), false, hasSemicolon))
			} else {
				lines = append(lines, buildImportStatement(moduleSpecifierText, "", "", typeNamedTexts, topLevelTypeForNamed, hasSemicolon))
			}
		}
		if moveNamespace {
			lines = append(lines, buildImportStatement(moduleSpecifierText, "", namespaceText, nil, true, hasSemicolon))
		}
		if moveDefault {
			lines = append(lines, buildImportStatement(moduleSpecifierText, defaultTypeText, "", nil, true, hasSemicolon))
		}
		if len(lines) == 0 {
			return nil
		}
		return []rule.RuleFix{rule.RuleFixReplace(ctx.SourceFile, importDeclNode, joinImportLines(lines, indent))}
	}

	// Mixed imports
	if len(typeNamedTexts) > 0 {
		if opts.FixStyle == "inline-type-imports" {
			valueNamedTexts = buildNamedTexts(true, true, true, false)
			typeNamedTexts = nil
		} else {
			if hasTypeNamedRawBody && typeNamedRawBody != "" {
				typeLines = append(typeLines, buildImportStatementWithRawNamedBody(moduleSpecifierText, "", "", typeNamedRawBody, true, hasSemicolon))
			} else {
				typeLines = append(typeLines, buildImportStatement(moduleSpecifierText, "", "", typeNamedTexts, true, hasSemicolon))
			}
		}
	}
	if moveNamespace {
		typeLines = append(typeLines, buildImportStatement(moduleSpecifierText, "", namespaceText, nil, true, hasSemicolon))
	}
	if moveDefault {
		typeLines = append(typeLines, buildImportStatement(moduleSpecifierText, defaultTypeText, "", nil, true, hasSemicolon))
	}

	valueLine := ""
	if valueDefaultText != "" || valueNamespaceText != "" || len(valueNamedTexts) > 0 {
		trimmedRawValueNamedBody := strings.TrimRight(valueNamedRawBody, " \t\r\n")
		useRawValueNamedBody := opts.FixStyle != "inline-type-imports" &&
			hasValueNamedRawBody &&
			valueNamedRawBody != "" &&
			(strings.HasSuffix(trimmedRawValueNamedBody, ",") ||
				strings.Contains(valueNamedRawBody, "/*") ||
				strings.Contains(valueNamedRawBody, "//"))
		if useRawValueNamedBody {
			valueLine = buildImportStatementWithRawNamedBody(moduleSpecifierText, valueDefaultText, valueNamespaceText, valueNamedRawBody, false, hasSemicolon)
		} else {
			valueLine = buildImportStatement(moduleSpecifierText, valueDefaultText, valueNamespaceText, valueNamedTexts, false, hasSemicolon)
		}
		if valueNamedPrefix != "" && valueDefaultText == "" && valueNamespaceText == "" {
			if useRawValueNamedBody {
				valueLine = "import " + valueNamedPrefix + "{" + valueNamedRawBody + "} from " + moduleSpecifierText
			} else {
				valueLine = "import " + valueNamedPrefix + "{ " + strings.Join(valueNamedTexts, ", ") + " } from " + moduleSpecifierText
			}
			if hasSemicolon {
				valueLine += ";"
			}
		}
	}
	lines := append([]string{}, typeLines...)
	if valueLine != "" {
		lines = append(lines, valueLine)
	}
	if len(lines) == 0 {
		return nil
	}
	fixes := append([]rule.RuleFix{}, prependFixes...)
	fixes = append(fixes, rule.RuleFixReplace(ctx.SourceFile, importDeclNode, joinImportLines(lines, indent)))
	return fixes
}

func reportPreferTypeImports(ctx rule.RuleContext, perImport map[*ast.Node][]*importedBinding, opts ConsistentTypeImportsOptions) {
	typeOnlyImportBySource := map[string]bool{}
	typeOnlyNamedImportBySource := map[string]*ast.Node{}
	if ctx.SourceFile != nil && ctx.SourceFile.Statements != nil {
		for _, statement := range ctx.SourceFile.Statements.Nodes {
			if statement == nil || statement.Kind != ast.KindImportDeclaration {
				continue
			}
			importDecl := statement.AsImportDeclaration()
			if importDecl == nil || importDecl.ImportClause == nil || importDecl.ModuleSpecifier == nil {
				continue
			}
			importClause := importDecl.ImportClause.AsImportClause()
			if importClause == nil || !isTypeOnlyImportDeclaration(ctx.SourceFile, statement, importClause) {
				continue
			}
			moduleLiteral := importDecl.ModuleSpecifier.AsStringLiteral()
			if moduleLiteral == nil || moduleLiteral.Text == "" {
				continue
			}
			typeOnlyImportBySource[moduleLiteral.Text] = true
			if importClause.Name() == nil && importClause.NamedBindings != nil && importClause.NamedBindings.Kind == ast.KindNamedImports {
				typeOnlyNamedImportBySource[moduleLiteral.Text] = statement
			}
		}
	}

	for importDecl, importBindings := range perImport {
		if importDecl == nil {
			continue
		}

		typeOnlyCount := 0
		valueCount := 0
		unusedCount := 0
		partialTypeOnlyNames := []string{}
		hasDecoratorMetadataValueUse := false
		importSource := ""

		for _, binding := range importBindings {
			if binding == nil || binding.isTypeImport || binding.isInlineType {
				continue
			}
			if importSource == "" {
				importSource = binding.importSource
			}
			if binding.usedAsDecoratorMetadataValue {
				hasDecoratorMetadataValueUse = true
			}
			if binding.usedAsValue {
				valueCount++
				continue
			}
			if binding.usedAsType {
				typeOnlyCount++
				partialTypeOnlyNames = append(partialTypeOnlyNames, binding.localName)
			} else {
				unusedCount++
			}
		}
		if typeOnlyCount == 0 {
			continue
		}

		message := rule.RuleMessage{
			Id:          "typeOverValue",
			Description: "All imports in the declaration are only used as types. Use `import type`.",
		}

		if valueCount > 0 {
			message = rule.RuleMessage{
				Id:          "someImportsAreOnlyTypes",
				Description: "Imports [" + strings.Join(partialTypeOnlyNames, " ") + "] are only used as type.",
			}
		}
		if valueCount == 0 && unusedCount > 0 {
			message = rule.RuleMessage{
				Id:          "someImportsAreOnlyTypes",
				Description: "Imports [" + strings.Join(partialTypeOnlyNames, " ") + "] are only used as type.",
			}
		}
		if hasDecoratorMetadataValueUse && importSource != "" && typeOnlyImportBySource[importSource] {
			continue
		}

		alignToLineStart := message.Id == "someImportsAreOnlyTypes" &&
			importSource != "" &&
			hasPriorBareImportOfSameSource(ctx.SourceFile, importDecl, importSource)
		fixes := buildPreferTypeImportFixes(ctx, importDecl, importBindings, opts, typeOnlyNamedImportBySource[importSource])
		if len(fixes) == 0 {
			reportImportDeclaration(ctx, importDecl, message, alignToLineStart)
			continue
		}
		if !alignToLineStart || ctx.SourceFile == nil {
			ctx.ReportNodeWithFixes(importDecl, message, fixes...)
			continue
		}
		r := utils.TrimNodeTextRange(ctx.SourceFile, importDecl)
		start := r.Pos()
		sourceText := ctx.SourceFile.Text()
		for start > 0 {
			ch := sourceText[start-1]
			if ch == '\n' || ch == '\r' {
				break
			}
			start--
		}
		ctx.ReportRangeWithFixes(core.NewTextRange(start, r.End()), message, fixes...)
	}
}

func reportImportDeclaration(ctx rule.RuleContext, importDecl *ast.Node, message rule.RuleMessage, alignToLineStart bool) {
	if importDecl == nil || ctx.SourceFile == nil {
		if importDecl != nil {
			ctx.ReportNode(importDecl, message)
		}
		return
	}
	if !alignToLineStart {
		ctx.ReportNode(importDecl, message)
		return
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, importDecl)
	start := r.Pos()
	sourceText := ctx.SourceFile.Text()
	for start > 0 {
		ch := sourceText[start-1]
		if ch == '\n' || ch == '\r' {
			break
		}
		start--
	}
	ctx.ReportRange(core.NewTextRange(start, r.End()), message)
}

func hasPriorBareImportOfSameSource(sourceFile *ast.SourceFile, currentImportDecl *ast.Node, importSource string) bool {
	if sourceFile == nil || sourceFile.Statements == nil || currentImportDecl == nil || importSource == "" {
		return false
	}
	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement == currentImportDecl {
			break
		}
		if statement.Kind != ast.KindImportDeclaration {
			continue
		}
		importDecl := statement.AsImportDeclaration()
		if importDecl == nil || importDecl.ModuleSpecifier == nil {
			continue
		}
		moduleLiteral := importDecl.ModuleSpecifier.AsStringLiteral()
		if moduleLiteral == nil || moduleLiteral.Text != importSource {
			continue
		}
		if importDecl.ImportClause == nil {
			return true
		}
		importClause := importDecl.ImportClause.AsImportClause()
		if importClause == nil {
			continue
		}
		if importClause.Name() == nil && importClause.NamedBindings != nil && importClause.NamedBindings.Kind == ast.KindNamedImports {
			namedImports := importClause.NamedBindings.AsNamedImports()
			if namedImports != nil && namedImports.Elements != nil && len(namedImports.Elements.Nodes) == 0 {
				return true
			}
		}
	}
	return false
}

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := parseOptions(options)
	if opts.Prefer == "no-type-imports" {
		reportPreferNoTypeImports(ctx)
	} else if ctx.TypeChecker != nil {
		bindings, perImport := collectImportBindings(ctx)
		if len(bindings) > 0 {
			markBindingUsages(ctx, bindings)
			reportPreferTypeImports(ctx, perImport, opts)
		}
	}

	return rule.RuleListeners{
		ast.KindImportType: func(node *ast.Node) {
			if !opts.DisallowTypeAnnotations {
				return
			}
			if node.AsImportTypeNode() != nil {
				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "noImportTypeAnnotations",
					Description: "`import()` type annotations are forbidden.",
				})
			}
		},
	}
}
