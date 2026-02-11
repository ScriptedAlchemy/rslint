package no_deprecated

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

var deprecatedReasonPattern = regexp.MustCompile(`(?s)@deprecated\s*([\s\S]*?)\*/`)

func buildDeprecatedMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "deprecated",
		Description: "`" + name + "` is deprecated.",
	}
}

func buildDeprecatedWithReasonMessage(name string, reason string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "deprecatedWithReason",
		Description: "`" + name + "` is deprecated. " + reason,
	}
}

func stripQuotes(text string) string {
	text = strings.TrimSpace(text)
	if len(text) >= 2 {
		if (strings.HasPrefix(text, "'") && strings.HasSuffix(text, "'")) ||
			(strings.HasPrefix(text, "\"") && strings.HasSuffix(text, "\"")) ||
			(strings.HasPrefix(text, "`") && strings.HasSuffix(text, "`")) {
			return text[1 : len(text)-1]
		}
	}
	return text
}

func normalizeComparableName(text string) string {
	return strings.TrimPrefix(stripQuotes(text), "#")
}

func diagnosticEntityName(diagnostic *ast.Diagnostic) string {
	if diagnostic == nil {
		return ""
	}
	args := diagnostic.MessageArgs()
	if len(args) == 0 {
		return ""
	}
	if diagnostic.Code() == 6387 && len(args) >= 2 {
		return stripQuotes(args[1])
	}
	return stripQuotes(args[0])
}

func sourceSpanText(sourceFile *ast.SourceFile, pos int, end int) string {
	if sourceFile == nil {
		return ""
	}
	text := sourceFile.Text()
	if pos < 0 || end > len(text) || pos >= end {
		return ""
	}
	return text[pos:end]
}

func cleanupDeprecatedReason(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	text = strings.TrimPrefix(text, ":")
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, "*/")
	text = strings.TrimSpace(text)
	lines := strings.Split(text, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "*")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func deprecatedReasonFromDiagnostic(diagnostic *ast.Diagnostic) string {
	if diagnostic == nil {
		return ""
	}
	for _, related := range diagnostic.RelatedInformation() {
		if related == nil || related.File() == nil {
			continue
		}
		text := sourceSpanText(related.File(), related.Pos(), related.End())
		if text == "" {
			continue
		}
		at := strings.Index(text, "@deprecated")
		if at < 0 {
			continue
		}
		reason := cleanupDeprecatedReason(text[at+len("@deprecated"):])
		if reason != "" {
			return reason
		}
	}
	return ""
}

func deprecatedReasonFromDeclaration(declaration *ast.Node) string {
	if declaration == nil {
		return ""
	}
	sourceFile := ast.GetSourceFileOfNode(declaration)
	if sourceFile == nil {
		return ""
	}
	text := sourceFile.Text()
	if text == "" {
		return ""
	}

	start := declaration.Pos()
	if start < 0 || start > len(text) {
		return ""
	}
	windowStart := start - 512
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := declaration.End()
	if windowEnd < start {
		windowEnd = start
	}
	if windowEnd > len(text) {
		windowEnd = len(text)
	}
	snippet := text[windowStart:windowEnd]
	matches := deprecatedReasonPattern.FindAllStringSubmatch(snippet, -1)
	if len(matches) == 0 {
		return ""
	}
	lastMatch := matches[len(matches)-1]
	if len(lastMatch) < 2 {
		return ""
	}
	return cleanupDeprecatedReason(lastMatch[1])
}

type noDeprecatedAllowEntry struct {
	From    string
	Name    string
	Package string
}

func parseAllowEntries(options any) []noDeprecatedAllowEntry {
	entries := []noDeprecatedAllowEntry{}
	optionList, ok := options.([]interface{})
	if !ok || len(optionList) == 0 {
		return entries
	}
	optionMap, ok := optionList[0].(map[string]interface{})
	if !ok {
		return entries
	}
	rawAllow, ok := optionMap["allow"].([]interface{})
	if !ok {
		return entries
	}
	for _, raw := range rawAllow {
		switch value := raw.(type) {
		case string:
			entries = append(entries, noDeprecatedAllowEntry{
				Name: value,
			})
		case map[string]interface{}:
			entry := noDeprecatedAllowEntry{}
			if name, ok := value["name"].(string); ok {
				entry.Name = name
			}
			if from, ok := value["from"].(string); ok {
				entry.From = from
			}
			if pkg, ok := value["package"].(string); ok {
				entry.Package = pkg
			}
			if entry.Name != "" {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

func diagnosticNode(sourceFile *ast.SourceFile, position int, end int) *ast.Node {
	if sourceFile == nil {
		return nil
	}
	candidates := []int{
		position,
		end - 1,
		(position + end) / 2,
		position + 1,
		position - 1,
	}
	for _, candidate := range candidates {
		if candidate < 0 || candidate >= len(sourceFile.Text()) {
			continue
		}
		if node := ast.GetNodeAtPosition(sourceFile, candidate, true); node != nil {
			return node
		}
	}
	return nil
}

func symbolHierarchyNames(symbol *ast.Symbol) map[string]bool {
	names := map[string]bool{}
	for current := symbol; current != nil; current = current.Parent {
		if current.Name == "" {
			continue
		}
		names[current.Name] = true
		unquoted := strings.Trim(current.Name, "\"'")
		if unquoted != "" {
			names[unquoted] = true
		}
	}
	return names
}

func declarationInCurrentFile(symbol *ast.Symbol, sourceFile *ast.SourceFile) bool {
	if symbol == nil || sourceFile == nil {
		return false
	}
	for _, declaration := range symbol.Declarations {
		if declaration == nil {
			continue
		}
		if ast.GetSourceFileOfNode(declaration) == sourceFile {
			return true
		}
	}
	return false
}

func packageMatchesSymbol(entryPackage string, symbol *ast.Symbol) bool {
	if entryPackage == "" || symbol == nil {
		return false
	}
	hierarchy := symbolHierarchyNames(symbol)
	if hierarchy[entryPackage] || hierarchy["@types/"+entryPackage] {
		return true
	}
	for current := symbol; current != nil; current = current.Parent {
		for _, declaration := range current.Declarations {
			sourceFile := ast.GetSourceFileOfNode(declaration)
			if sourceFile == nil {
				continue
			}
			fileName := sourceFile.FileName()
			if strings.Contains(fileName, "/node_modules/"+entryPackage+"/") ||
				strings.Contains(fileName, "/node_modules/@types/"+entryPackage+"/") {
				return true
			}
		}
	}
	return false
}

func nameImportedFromPackage(sourceFile *ast.SourceFile, name string, pkg string) bool {
	if sourceFile == nil || name == "" || pkg == "" {
		return false
	}
	sourceText := sourceFile.Text()
	if sourceText == "" {
		return false
	}
	namePattern := regexp.QuoteMeta(name)
	pkgPattern := regexp.QuoteMeta(pkg)
	staticImportPattern := regexp.MustCompile(`(?s)import\s*\{[^}]*\b` + namePattern + `\b[^}]*\}\s*from\s*['"]` + pkgPattern + `['"]`)
	if staticImportPattern.MatchString(sourceText) {
		return true
	}
	dynamicImportPattern := regexp.MustCompile(`(?s)\{[^}]*\b` + namePattern + `\b[^}]*\}\s*=\s*import\(\s*['"]` + pkgPattern + `['"]\s*\)`)
	return dynamicImportPattern.MatchString(sourceText)
}

func allowEntryMatches(entry noDeprecatedAllowEntry, diagnosticName string, symbol *ast.Symbol, sourceFile *ast.SourceFile) bool {
	if entry.Name != "" {
		if normalizeComparableName(diagnosticName) == normalizeComparableName(entry.Name) {
			// direct match
		} else if symbol != nil {
			hierarchy := symbolHierarchyNames(symbol)
			nameMatched := false
			for hierarchyName := range hierarchy {
				if normalizeComparableName(hierarchyName) == normalizeComparableName(entry.Name) {
					nameMatched = true
					break
				}
			}
			if !nameMatched {
				return false
			}
		} else {
			return false
		}
	}

	switch entry.From {
	case "":
		return true
	case "file":
		if symbol == nil {
			return entry.Name != "" && normalizeComparableName(diagnosticName) == normalizeComparableName(entry.Name)
		}
		return declarationInCurrentFile(symbol, sourceFile)
	case "package":
		if packageMatchesSymbol(entry.Package, symbol) {
			return true
		}
		return nameImportedFromPackage(sourceFile, entry.Name, entry.Package)
	default:
		return false
	}
}

func shouldAllowDiagnostic(entries []noDeprecatedAllowEntry, diagnosticName string, symbol *ast.Symbol, sourceFile *ast.SourceFile) bool {
	for _, entry := range entries {
		if allowEntryMatches(entry, diagnosticName, symbol, sourceFile) {
			return true
		}
	}
	return false
}

func symbolAtLocation(typeChecker *checker.Checker, node *ast.Node) *ast.Symbol {
	if typeChecker == nil || node == nil {
		return nil
	}
	if symbol := typeChecker.GetSymbolAtLocation(node); symbol != nil {
		return symbol
	}
	switch node.Kind {
	case ast.KindPropertyAccessExpression:
		access := node.AsPropertyAccessExpression()
		if access != nil && access.Name() != nil {
			if symbol := typeChecker.GetSymbolAtLocation(access.Name()); symbol != nil {
				return symbol
			}
		}
	case ast.KindElementAccessExpression:
		access := node.AsElementAccessExpression()
		if access != nil && access.ArgumentExpression != nil {
			if symbol := typeChecker.GetSymbolAtLocation(access.ArgumentExpression); symbol != nil {
				return symbol
			}
		}
	case ast.KindJsxOpeningElement:
		opening := node.AsJsxOpeningElement()
		if opening != nil && opening.TagName != nil {
			if symbol := typeChecker.GetSymbolAtLocation(opening.TagName); symbol != nil {
				return symbol
			}
		}
	case ast.KindJsxClosingElement:
		closing := node.AsJsxClosingElement()
		if closing != nil && closing.TagName != nil {
			if symbol := typeChecker.GetSymbolAtLocation(closing.TagName); symbol != nil {
				return symbol
			}
		}
	case ast.KindJsxSelfClosingElement:
		selfClosing := node.AsJsxSelfClosingElement()
		if selfClosing != nil && selfClosing.TagName != nil {
			if symbol := typeChecker.GetSymbolAtLocation(selfClosing.TagName); symbol != nil {
				return symbol
			}
		}
	}
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if symbol := typeChecker.GetSymbolAtLocation(parent); symbol != nil {
			return symbol
		}
		if parent.Kind == ast.KindPropertyAccessExpression {
			access := parent.AsPropertyAccessExpression()
			if access != nil && access.Name() != nil {
				if symbol := typeChecker.GetSymbolAtLocation(access.Name()); symbol != nil {
					return symbol
				}
			}
		}
	}
	return nil
}

func propertyAccessForDiagnosticRange(node *ast.Node, pos int, end int) *ast.PropertyAccessExpression {
	for current := node; current != nil; current = current.Parent {
		if current.Kind != ast.KindPropertyAccessExpression {
			continue
		}
		access := current.AsPropertyAccessExpression()
		if access == nil || access.Name() == nil {
			continue
		}
		nameNode := access.Name()
		if nameNode.Pos() == pos && nameNode.End() == end {
			return access
		}
	}
	return nil
}

func isDynamicImportResultIdentifier(symbol *ast.Symbol) bool {
	if symbol == nil {
		return false
	}
	for _, declaration := range symbol.Declarations {
		if declaration == nil || declaration.Kind != ast.KindVariableDeclaration {
			continue
		}
		variableDeclaration := declaration.AsVariableDeclaration()
		if variableDeclaration == nil || variableDeclaration.Initializer == nil {
			continue
		}
		initializer := ast.SkipParentheses(variableDeclaration.Initializer)
		if initializer == nil {
			continue
		}
		if initializer.Kind == ast.KindAwaitExpression {
			awaitExpression := initializer.AsAwaitExpression()
			if awaitExpression == nil {
				continue
			}
			initializer = ast.SkipParentheses(awaitExpression.Expression)
		}
		if initializer == nil || initializer.Kind != ast.KindCallExpression {
			continue
		}
		callExpression := initializer.AsCallExpression()
		if callExpression == nil || callExpression.Expression == nil {
			continue
		}
		callee := ast.SkipParentheses(callExpression.Expression)
		if callee != nil && callee.Kind == ast.KindImportKeyword {
			return true
		}
	}
	return false
}

func shouldIgnoreDynamicImportDefault(node *ast.Node, pos int, end int, entityName string, typeChecker *checker.Checker) bool {
	if entityName != "default" || node == nil || typeChecker == nil {
		return false
	}
	access := propertyAccessForDiagnosticRange(node, pos, end)
	if access == nil || access.Expression == nil {
		return false
	}
	target := ast.SkipParentheses(access.Expression)
	if target == nil || target.Kind != ast.KindIdentifier {
		return false
	}
	symbol := typeChecker.GetSymbolAtLocation(target)
	return isDynamicImportResultIdentifier(symbol)
}

func promotedDynamicImportDefaultRange(node *ast.Node, pos int, end int, entityName string, typeChecker *checker.Checker) *core.TextRange {
	if entityName != "default" || node == nil || typeChecker == nil {
		return nil
	}
	access := propertyAccessForDiagnosticRange(node, pos, end)
	if access == nil || access.Expression == nil {
		return nil
	}
	target := ast.SkipParentheses(access.Expression)
	if target == nil || target.Kind != ast.KindIdentifier {
		return nil
	}
	if !isDynamicImportResultIdentifier(typeChecker.GetSymbolAtLocation(target)) {
		return nil
	}
	if access.AsNode().Parent == nil || access.AsNode().Parent.Kind != ast.KindPropertyAccessExpression {
		return nil
	}
	parentAccess := access.AsNode().Parent.AsPropertyAccessExpression()
	if parentAccess == nil || parentAccess.Expression != access.AsNode() || parentAccess.Name() == nil {
		return nil
	}
	if parentAccess.Name().Text() != "default" {
		return nil
	}
	promoted := core.NewTextRange(parentAccess.Name().Pos(), parentAccess.Name().End())
	return &promoted
}

func isWithinJsxClosingElement(node *ast.Node, pos int, end int) bool {
	for current := node; current != nil; current = current.Parent {
		if current.Kind != ast.KindJsxClosingElement {
			continue
		}
		closingElement := current.AsJsxClosingElement()
		if closingElement == nil || closingElement.TagName == nil {
			continue
		}
		if closingElement.TagName.Pos() == pos && closingElement.TagName.End() == end {
			return true
		}
	}
	return false
}

func isImportBindingAtRange(node *ast.Node, pos int, end int) bool {
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindImportSpecifier:
			specifier := current.AsImportSpecifier()
			if specifier != nil && specifier.Name() != nil {
				nameNode := specifier.Name()
				if nameNode.Pos() == pos && nameNode.End() == end {
					return true
				}
			}
		case ast.KindImportClause:
			clause := current.AsImportClause()
			if clause != nil && clause.Name() != nil {
				nameNode := clause.Name()
				if nameNode.Pos() == pos && nameNode.End() == end {
					return true
				}
			}
		case ast.KindNamespaceImport:
			namespaceImport := current.AsNamespaceImport()
			if namespaceImport != nil && namespaceImport.Name() != nil {
				nameNode := namespaceImport.Name()
				if nameNode.Pos() == pos && nameNode.End() == end {
					return true
				}
			}
		case ast.KindImportEqualsDeclaration:
			importEquals := current.AsImportEqualsDeclaration()
			if importEquals != nil && importEquals.Name() != nil {
				nameNode := importEquals.Name()
				if nameNode.Pos() == pos && nameNode.End() == end {
					return true
				}
			}
		}
	}
	return false
}

func isInImportStatementRange(sourceFile *ast.SourceFile, pos int) bool {
	if sourceFile == nil {
		return false
	}
	text := sourceFile.Text()
	if pos < 0 || pos >= len(text) {
		return false
	}
	lineStart := strings.LastIndex(text[:pos], "\n") + 1
	lineEndRelative := strings.Index(text[pos:], "\n")
	lineEnd := len(text)
	if lineEndRelative >= 0 {
		lineEnd = pos + lineEndRelative
	}
	lineText := text[lineStart:lineEnd]
	trimmedLine := strings.TrimSpace(lineText)
	if !strings.HasPrefix(trimmedLine, "import ") {
		return false
	}
	if fromIndex := strings.Index(lineText, " from "); fromIndex >= 0 {
		return pos < lineStart+fromIndex
	}
	return true
}

func symbolIsDeprecated(typeChecker *checker.Checker, symbol *ast.Symbol) bool {
	if typeChecker == nil || symbol == nil {
		return false
	}
	if symbol.ValueDeclaration != nil && typeChecker.IsDeprecatedDeclaration(symbol.ValueDeclaration) {
		return true
	}
	if len(symbol.Declarations) == 0 {
		return false
	}
	for _, declaration := range symbol.Declarations {
		if declaration == nil || !typeChecker.IsDeprecatedDeclaration(declaration) {
			return false
		}
	}
	return true
}

func bindingElementPropertyName(bindingElement *ast.BindingElement) string {
	if bindingElement == nil {
		return ""
	}
	if bindingElement.PropertyName != nil {
		switch bindingElement.PropertyName.Kind {
		case ast.KindIdentifier:
			return bindingElement.PropertyName.AsIdentifier().Text
		case ast.KindStringLiteral:
			return bindingElement.PropertyName.AsStringLiteral().Text
		case ast.KindNumericLiteral:
			return bindingElement.PropertyName.Text()
		}
	}
	if bindingElement.Name() != nil && bindingElement.Name().Kind == ast.KindIdentifier {
		return bindingElement.Name().AsIdentifier().Text
	}
	return ""
}

func resolveConstantPropertyName(ctx rule.RuleContext, node *ast.Node, depth int, seen map[*ast.Symbol]bool) (string, bool) {
	if ctx.TypeChecker == nil || node == nil || depth > 8 {
		return "", false
	}
	node = ast.SkipParentheses(node)
	if node == nil {
		return "", false
	}
	switch node.Kind {
	case ast.KindStringLiteral:
		stringLiteral := node.AsStringLiteral()
		if stringLiteral == nil {
			return "", false
		}
		return stringLiteral.Text, true
	case ast.KindNoSubstitutionTemplateLiteral:
		templateLiteral := node.AsNoSubstitutionTemplateLiteral()
		if templateLiteral == nil {
			return "", false
		}
		return templateLiteral.Text, true
	case ast.KindNumericLiteral:
		numericLiteral := node.AsNumericLiteral()
		if numericLiteral == nil {
			return "", false
		}
		return numericLiteral.Text, true
	case ast.KindAsExpression:
		asExpression := node.AsAsExpression()
		if asExpression == nil {
			return "", false
		}
		return resolveConstantPropertyName(ctx, asExpression.Expression, depth+1, seen)
	case ast.KindTypeAssertionExpression:
		typeAssertion := node.AsTypeAssertion()
		if typeAssertion == nil {
			return "", false
		}
		return resolveConstantPropertyName(ctx, typeAssertion.Expression, depth+1, seen)
	case ast.KindPropertyAccessExpression:
		propertyAccess := node.AsPropertyAccessExpression()
		if propertyAccess == nil || propertyAccess.Name() == nil {
			return "", false
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(propertyAccess.Name())
		if symbol != nil && symbol.ValueDeclaration != nil && symbol.ValueDeclaration.Kind == ast.KindEnumMember {
			enumMember := symbol.ValueDeclaration.AsEnumMember()
			if enumMember != nil {
				return resolveConstantPropertyName(ctx, enumMember.Initializer, depth+1, seen)
			}
		}
	case ast.KindIdentifier:
		symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
		if symbol == nil || symbol.ValueDeclaration == nil || symbol.ValueDeclaration.Kind != ast.KindVariableDeclaration {
			return "", false
		}
		if seen[symbol] {
			return "", false
		}
		seen[symbol] = true
		defer delete(seen, symbol)

		variableDeclaration := symbol.ValueDeclaration.AsVariableDeclaration()
		if variableDeclaration == nil || variableDeclaration.Initializer == nil {
			return "", false
		}
		return resolveConstantPropertyName(ctx, variableDeclaration.Initializer, depth+1, seen)
	}
	if constantValue := ctx.TypeChecker.GetConstantValue(node); constantValue != nil {
		if text, ok := constantValue.(string); ok {
			return text, true
		}
		switch value := constantValue.(type) {
		case float64:
			return strconv.FormatFloat(value, 'f', -1, 64), true
		case int:
			return strconv.Itoa(value), true
		case int32:
			return strconv.Itoa(int(value)), true
		case int64:
			return strconv.FormatInt(value, 10), true
		}
	}
	return "", false
}

func elementAccessPropertyName(ctx rule.RuleContext, argument *ast.Node) (string, bool) {
	return resolveConstantPropertyName(ctx, argument, 0, map[*ast.Symbol]bool{})
}

func objectBindingPatternSourceType(ctx rule.RuleContext, objectBindingPatternNode *ast.Node, seen map[*ast.Node]bool) *checker.Type {
	if ctx.TypeChecker == nil || objectBindingPatternNode == nil || objectBindingPatternNode.Kind != ast.KindObjectBindingPattern {
		return nil
	}
	if seen[objectBindingPatternNode] {
		return nil
	}
	seen[objectBindingPatternNode] = true
	defer delete(seen, objectBindingPatternNode)

	parent := objectBindingPatternNode.Parent
	if parent == nil {
		return nil
	}
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		variableDeclaration := parent.AsVariableDeclaration()
		if variableDeclaration == nil {
			return nil
		}
		if variableDeclaration.Initializer != nil {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, variableDeclaration.Initializer)
		}
		if variableDeclaration.Type != nil {
			return ctx.TypeChecker.GetTypeAtLocation(variableDeclaration.Type)
		}
	case ast.KindParameter:
		parameter := parent.AsParameterDeclaration()
		if parameter == nil {
			return nil
		}
		if parameter.Type != nil {
			return ctx.TypeChecker.GetTypeAtLocation(parameter.Type)
		}
		if parameter.Initializer != nil {
			return utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, parameter.Initializer)
		}
	case ast.KindBindingElement:
		bindingElement := parent.AsBindingElement()
		if bindingElement == nil {
			return nil
		}
		if bindingElementType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, parent); bindingElementType != nil {
			return bindingElementType
		}
		if parent.Parent == nil || parent.Parent.Kind != ast.KindObjectBindingPattern {
			return nil
		}
		outerObjectType := objectBindingPatternSourceType(ctx, parent.Parent, seen)
		if outerObjectType == nil {
			return nil
		}
		propertyName := bindingElementPropertyName(bindingElement)
		if propertyName == "" {
			return nil
		}
		propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, outerObjectType, propertyName)
		if propertySymbol == nil {
			return nil
		}
		return ctx.TypeChecker.GetTypeOfSymbolAtLocation(propertySymbol, parent)
	}

	return nil
}

func deprecatedInfoByNameInSource(sourceFile *ast.SourceFile, name string) (bool, string) {
	if sourceFile == nil || name == "" {
		return false, ""
	}
	text := sourceFile.Text()
	if text == "" {
		return false, ""
	}
	pattern := regexp.MustCompile(`(?s)@deprecated\s*([\s\S]*?)\*/[\s\S]{0,200}\b` + regexp.QuoteMeta(name) + `\b`)
	matches := pattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return false, ""
	}
	last := matches[len(matches)-1]
	if len(last) < 2 {
		return true, ""
	}
	return true, cleanupDeprecatedReason(last[1])
}

func deprecatedReasonByNameInSource(sourceFile *ast.SourceFile, name string) string {
	_, reason := deprecatedInfoByNameInSource(sourceFile, name)
	return reason
}

func deprecatedPropertyInfoByNameInSource(sourceFile *ast.SourceFile, name string) (bool, string) {
	if sourceFile == nil || name == "" {
		return false, ""
	}
	sourceText := sourceFile.Text()
	if sourceText == "" {
		return false, ""
	}
	propertyPattern := regexp.MustCompile(`(?s)@deprecated\s*([\s\S]*?)\*/\s*(?:readonly\s+)?(?:(?:public|private|protected|static|accessor)\s+)*['"]?` + regexp.QuoteMeta(name) + `['"]?\s*(?:\?|!)?\s*:`)
	matches := propertyPattern.FindAllStringSubmatch(sourceText, -1)
	if len(matches) == 0 {
		return false, ""
	}
	last := matches[len(matches)-1]
	if len(last) < 2 {
		return true, ""
	}
	return true, cleanupDeprecatedReason(last[1])
}

var NoDeprecatedRule = rule.CreateRule(rule.Rule{
	Name: "no-deprecated",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		if ctx.TypeChecker == nil || ctx.SourceFile == nil {
			return rule.RuleListeners{}
		}
		allowEntries := parseAllowEntries(options)
		diagnostics := ctx.TypeChecker.GetSuggestionDiagnostics(context.Background(), ctx.SourceFile)
		reported := map[string]bool{}
		reportRange := func(diagnosticRange core.TextRange, message rule.RuleMessage) {
			key := strconv.Itoa(diagnosticRange.Pos()) + ":" + strconv.Itoa(diagnosticRange.End())
			if reported[key] {
				return
			}
			reported[key] = true
			ctx.ReportRange(diagnosticRange, message)
		}
		for _, diagnostic := range diagnostics {
			if diagnostic == nil || !diagnostic.ReportsDeprecated() || diagnostic.File() != ctx.SourceFile {
				continue
			}
			name := diagnosticEntityName(diagnostic)
			node := diagnosticNode(ctx.SourceFile, diagnostic.Pos(), diagnostic.End())
			symbol := symbolAtLocation(ctx.TypeChecker, node)
			if isWithinJsxClosingElement(node, diagnostic.Pos(), diagnostic.End()) {
				continue
			}
			if isImportBindingAtRange(node, diagnostic.Pos(), diagnostic.End()) {
				continue
			}
			if isInImportStatementRange(ctx.SourceFile, diagnostic.Pos()) {
				continue
			}
			diagnosticRange := core.NewTextRange(diagnostic.Pos(), diagnostic.End())
			if promotedRange := promotedDynamicImportDefaultRange(node, diagnostic.Pos(), diagnostic.End(), name, ctx.TypeChecker); promotedRange != nil {
				diagnosticRange = *promotedRange
			} else if shouldIgnoreDynamicImportDefault(node, diagnostic.Pos(), diagnostic.End(), name, ctx.TypeChecker) {
				continue
			}
			if shouldAllowDiagnostic(allowEntries, name, symbol, ctx.SourceFile) {
				continue
			}
			message := buildDeprecatedMessage(name)
			if reason := deprecatedReasonFromDiagnostic(diagnostic); reason != "" {
				message = buildDeprecatedWithReasonMessage(name, reason)
			} else if symbol != nil {
				for _, declaration := range symbol.Declarations {
					if declaration == nil {
						continue
					}
					if reason := deprecatedReasonFromDeclaration(declaration); reason != "" {
						message = buildDeprecatedWithReasonMessage(name, reason)
						break
					}
				}
			}
			if message.Id != "deprecatedWithReason" {
				if reason := deprecatedReasonByNameInSource(ctx.SourceFile, name); reason != "" {
					message = buildDeprecatedWithReasonMessage(name, reason)
				}
			}
			reportRange(diagnosticRange, message)
		}
		return rule.RuleListeners{
			ast.KindBindingElement: func(node *ast.Node) {
				bindingElement := node.AsBindingElement()
				if bindingElement == nil {
					return
				}
				propertyName := bindingElementPropertyName(bindingElement)
				if propertyName == "" {
					return
				}
				if node.Parent == nil || node.Parent.Kind != ast.KindObjectBindingPattern {
					return
				}
				objectType := objectBindingPatternSourceType(ctx, node.Parent, map[*ast.Node]bool{})
				if objectType == nil {
					return
				}
				propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, objectType, propertyName)
				if !symbolIsDeprecated(ctx.TypeChecker, propertySymbol) {
					return
				}
				if shouldAllowDiagnostic(allowEntries, propertyName, propertySymbol, ctx.SourceFile) {
					return
				}
				message := buildDeprecatedMessage(propertyName)
				for _, declaration := range propertySymbol.Declarations {
					if reason := deprecatedReasonFromDeclaration(declaration); reason != "" {
						message = buildDeprecatedWithReasonMessage(propertyName, reason)
						break
					}
				}
				nameNode := bindingElement.Name()
				if bindingElement.PropertyName != nil {
					nameNode = bindingElement.PropertyName
				}
				if nameNode == nil {
					return
				}
				trimmedRange := utils.TrimNodeTextRange(ctx.SourceFile, nameNode)
				reportRange(core.NewTextRange(trimmedRange.Pos(), trimmedRange.End()), message)
			},
			ast.KindJsxAttribute: func(node *ast.Node) {
				jsxAttribute := node.AsJsxAttribute()
				if jsxAttribute == nil || jsxAttribute.Name() == nil {
					return
				}
				nameNode := jsxAttribute.Name()
				nameText := nameNode.Text()
				if nameText == "" {
					return
				}
				propertySymbol := symbolAtLocation(ctx.TypeChecker, nameNode)
				if propertySymbol == nil && node.Parent != nil && node.Parent.Kind == ast.KindJsxAttributes {
					attributesType := ctx.TypeChecker.GetTypeAtLocation(node.Parent)
					if attributesType != nil {
						propertySymbol = checker.Checker_getPropertyOfType(ctx.TypeChecker, attributesType, nameText)
					}
				}
				isDeprecated := symbolIsDeprecated(ctx.TypeChecker, propertySymbol)
				sourceDeprecated, sourceReason := deprecatedPropertyInfoByNameInSource(ctx.SourceFile, nameText)
				if !isDeprecated && !sourceDeprecated {
					return
				}
				if shouldAllowDiagnostic(allowEntries, nameText, propertySymbol, ctx.SourceFile) {
					return
				}
				message := buildDeprecatedMessage(nameText)
				if propertySymbol != nil {
					for _, declaration := range propertySymbol.Declarations {
						if reason := deprecatedReasonFromDeclaration(declaration); reason != "" {
							message = buildDeprecatedWithReasonMessage(nameText, reason)
							break
						}
					}
				}
				if message.Id != "deprecatedWithReason" && sourceReason != "" {
					message = buildDeprecatedWithReasonMessage(nameText, sourceReason)
				}
				trimmedRange := utils.TrimNodeTextRange(ctx.SourceFile, nameNode)
				reportRange(core.NewTextRange(trimmedRange.Pos(), trimmedRange.End()), message)
			},
			ast.KindElementAccessExpression: func(node *ast.Node) {
				elementAccess := node.AsElementAccessExpression()
				if elementAccess == nil || elementAccess.Expression == nil || elementAccess.ArgumentExpression == nil {
					return
				}
				propertyName, ok := elementAccessPropertyName(ctx, elementAccess.ArgumentExpression)
				if !ok || propertyName == "" {
					return
				}
				objectType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, elementAccess.Expression)
				if objectType == nil {
					return
				}
				propertySymbol := checker.Checker_getPropertyOfType(ctx.TypeChecker, objectType, propertyName)
				if !symbolIsDeprecated(ctx.TypeChecker, propertySymbol) {
					return
				}
				if shouldAllowDiagnostic(allowEntries, propertyName, propertySymbol, ctx.SourceFile) {
					return
				}
				message := buildDeprecatedMessage(propertyName)
				for _, declaration := range propertySymbol.Declarations {
					if reason := deprecatedReasonFromDeclaration(declaration); reason != "" {
						message = buildDeprecatedWithReasonMessage(propertyName, reason)
						break
					}
				}
				trimmedRange := utils.TrimNodeTextRange(ctx.SourceFile, elementAccess.ArgumentExpression)
				reportRange(core.NewTextRange(trimmedRange.Pos(), trimmedRange.End()), message)
			},
		}
	},
})
