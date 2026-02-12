package consistent_type_imports

import (
	"encoding/json"
	"strings"

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
	isInlineType                 bool
	isTypeImport                 bool
	usedAsType                   bool
	usedAsValue                  bool
	usedAsDecoratorMetadataValue bool
}

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

func addBinding(bindings *[]*importedBinding, ctx rule.RuleContext, importDecl *ast.Node, importSource string, localNode *ast.Node, isInlineType bool, isTypeImport bool) {
	if localNode == nil || localNode.Kind != ast.KindIdentifier {
		return
	}
	binding := &importedBinding{
		localName:    localNode.AsIdentifier().Text,
		importDecl:   importDecl,
		importSource: importSource,
		isInlineType: isInlineType,
		isTypeImport: isTypeImport,
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
			addBinding(&bindings, ctx, statement, importSource, defaultLocal, false, isTypeImportDecl)
		}

		if importClause.NamedBindings == nil {
			continue
		}
		switch importClause.NamedBindings.Kind {
		case ast.KindNamespaceImport:
			namespaceImport := importClause.NamedBindings.AsNamespaceImport()
			if namespaceImport != nil && namespaceImport.Name() != nil {
				addBinding(&bindings, ctx, statement, importSource, namespaceImport.Name(), false, isTypeImportDecl)
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
				addBinding(&bindings, ctx, statement, importSource, importSpecifier.Name(), importSpecifier.IsTypeOnly, isTypeImportDecl)
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
			ctx.ReportNode(statement, rule.RuleMessage{
				Id:          "avoidImportType",
				Description: "Use an `import` instead of an `import type`.",
			})
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
			ctx.ReportNode(element, rule.RuleMessage{
				Id:          "avoidImportType",
				Description: "Use an `import` instead of an `import type`.",
			})
		}
	}
}

func reportPreferTypeImports(ctx rule.RuleContext, perImport map[*ast.Node][]*importedBinding) {
	typeOnlyImportBySource := map[string]bool{}
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

		_ = partialTypeOnlyNames
		alignToLineStart := message.Id == "someImportsAreOnlyTypes" &&
			importSource != "" &&
			hasPriorBareImportOfSameSource(ctx.SourceFile, importDecl, importSource)
		reportImportDeclaration(ctx, importDecl, message, alignToLineStart)
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
			reportPreferTypeImports(ctx, perImport)
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
