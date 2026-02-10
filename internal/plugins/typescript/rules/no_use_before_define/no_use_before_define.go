package no_use_before_define

import (
	"slices"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type noUseBeforeDefineOptions struct {
	AllowNamedExports   bool
	Classes             bool
	Enums               bool
	Functions           bool
	IgnoreTypeReference bool
	Typedefs            bool
	Variables           bool
}

type declarationKind int

const (
	declarationUnknown declarationKind = iota
	declarationFunction
	declarationClass
	declarationEnum
	declarationTypedef
	declarationVariable
)

type declarationInfo struct {
	Name              string
	PrimaryDecl       *ast.Node
	PrimaryIdentifier *ast.Node
	DefinedEnd        int
	Kind              declarationKind
	VariableScope     *ast.Node
	HasDeclaration    bool
}

func buildNoUseBeforeDefineMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noUseBeforeDefine",
		Description: "'" + name + "' was used before it was defined.",
	}
}

func defaultOptions() noUseBeforeDefineOptions {
	return noUseBeforeDefineOptions{
		AllowNamedExports:   false,
		Classes:             true,
		Enums:               true,
		Functions:           true,
		IgnoreTypeReference: true,
		Typedefs:            true,
		Variables:           true,
	}
}

func parseOptions(options any) noUseBeforeDefineOptions {
	opts := defaultOptions()
	if options == nil {
		return opts
	}

	var raw any
	if arr, ok := options.([]interface{}); ok {
		if len(arr) == 0 {
			return opts
		}
		raw = arr[0]
	} else {
		raw = options
	}

	if optionString, ok := raw.(string); ok {
		if optionString == "nofunc" {
			opts.Functions = false
		}
		return opts
	}

	optionMap, ok := raw.(map[string]interface{})
	if !ok {
		return opts
	}

	if v, ok := optionMap["allowNamedExports"].(bool); ok {
		opts.AllowNamedExports = v
	}
	if v, ok := optionMap["classes"].(bool); ok {
		opts.Classes = v
	}
	if v, ok := optionMap["enums"].(bool); ok {
		opts.Enums = v
	}
	if v, ok := optionMap["functions"].(bool); ok {
		opts.Functions = v
	}
	if v, ok := optionMap["ignoreTypeReferences"].(bool); ok {
		opts.IgnoreTypeReference = v
	}
	if v, ok := optionMap["typedefs"].(bool); ok {
		opts.Typedefs = v
	}
	if v, ok := optionMap["variables"].(bool); ok {
		opts.Variables = v
	}

	return opts
}

func isFunctionLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindMethodDeclaration, ast.KindConstructor, ast.KindGetAccessor, ast.KindSetAccessor:
		return true
	}
	return false
}

func variableScopeNode(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if current.Kind == ast.KindSourceFile || isFunctionLike(current) {
			return current
		}
	}
	return nil
}

func declarationIdentifierNode(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		decl := node.AsVariableDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindBindingElement:
		decl := node.AsBindingElement()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindParameter:
		decl := node.AsParameterDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindFunctionDeclaration:
		decl := node.AsFunctionDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindFunctionExpression:
		decl := node.AsFunctionExpression()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindClassDeclaration:
		decl := node.AsClassDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindClassExpression:
		decl := node.AsClassExpression()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindTypeAliasDeclaration:
		decl := node.AsTypeAliasDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindInterfaceDeclaration:
		decl := node.AsInterfaceDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindEnumDeclaration:
		decl := node.AsEnumDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindModuleDeclaration:
		decl := node.AsModuleDeclaration()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindImportClause:
		decl := node.AsImportClause()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindImportSpecifier:
		decl := node.AsImportSpecifier()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindNamespaceImport:
		decl := node.AsNamespaceImport()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	case ast.KindTypeParameter:
		decl := node.AsTypeParameter()
		if decl != nil && decl.Name() != nil && decl.Name().Kind == ast.KindIdentifier {
			return decl.Name()
		}
	}
	return nil
}

func isDeclarationIdentifier(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindIdentifier || node.Parent == nil {
		return false
	}
	return declarationIdentifierNode(node.Parent) == node
}

func declarationKindFromNode(node *ast.Node, symbol *ast.Symbol) declarationKind {
	if node == nil {
		return declarationUnknown
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression:
		return declarationFunction
	case ast.KindClassDeclaration, ast.KindClassExpression:
		return declarationClass
	case ast.KindEnumDeclaration:
		return declarationEnum
	case ast.KindTypeAliasDeclaration, ast.KindInterfaceDeclaration, ast.KindTypeParameter:
		return declarationTypedef
	case ast.KindVariableDeclaration, ast.KindBindingElement, ast.KindParameter, ast.KindImportClause, ast.KindImportSpecifier, ast.KindNamespaceImport:
		return declarationVariable
	}

	if symbol != nil {
		switch {
		case symbol.Flags&ast.SymbolFlagsFunction != 0:
			return declarationFunction
		case symbol.Flags&ast.SymbolFlagsClass != 0:
			return declarationClass
		case symbol.Flags&(ast.SymbolFlagsConstEnum|ast.SymbolFlagsRegularEnum) != 0:
			return declarationEnum
		case symbol.Flags&(ast.SymbolFlagsTypeAlias|ast.SymbolFlagsInterface|ast.SymbolFlagsTypeParameter) != 0:
			return declarationTypedef
		case symbol.Flags&(ast.SymbolFlagsVariable|ast.SymbolFlagsBlockScopedVariable|ast.SymbolFlagsFunctionScopedVariable) != 0:
			return declarationVariable
		}
	}

	return declarationUnknown
}

func resolveAliasSymbol(typeChecker *checker.Checker, symbol *ast.Symbol) *ast.Symbol {
	if typeChecker == nil || symbol == nil {
		return nil
	}
	if symbol.Flags&ast.SymbolFlagsAlias == 0 {
		return symbol
	}
	if resolved, found := typeChecker.ResolveAlias(symbol); found && resolved != nil {
		return resolved
	}
	return symbol
}

func collectDeclarationInfo(symbol *ast.Symbol) declarationInfo {
	info := declarationInfo{}
	if symbol == nil {
		return info
	}

	candidates := make([]*ast.Node, 0, len(symbol.Declarations)+1)
	candidates = append(candidates, symbol.Declarations...)
	if symbol.ValueDeclaration != nil {
		candidates = append(candidates, symbol.ValueDeclaration)
	}

	filtered := make([]*ast.Node, 0, len(candidates))
	seen := map[*ast.Node]bool{}
	for _, decl := range candidates {
		if decl == nil || seen[decl] {
			continue
		}
		seen[decl] = true
		filtered = append(filtered, decl)
	}
	if len(filtered) == 0 {
		return info
	}

	slices.SortFunc(filtered, func(a, b *ast.Node) int {
		if a.Pos() == b.Pos() {
			return a.End() - b.End()
		}
		return a.Pos() - b.Pos()
	})

	primaryDecl := filtered[0]
	primaryIdentifier := declarationIdentifierNode(primaryDecl)
	definedEnd := primaryDecl.End()
	if primaryIdentifier != nil {
		definedEnd = primaryIdentifier.End()
		info.Name = primaryIdentifier.AsIdentifier().Text
	}

	for _, decl := range filtered {
		id := declarationIdentifierNode(decl)
		if id == nil || id.Kind != ast.KindIdentifier {
			continue
		}
		if info.Name == "" {
			info.Name = id.AsIdentifier().Text
		}
		if id.End() < definedEnd {
			definedEnd = id.End()
			primaryDecl = decl
			primaryIdentifier = id
		}
	}

	info.PrimaryDecl = primaryDecl
	info.PrimaryIdentifier = primaryIdentifier
	info.DefinedEnd = definedEnd
	info.Kind = declarationKindFromNode(primaryDecl, symbol)
	info.VariableScope = variableScopeNode(primaryDecl)
	info.HasDeclaration = true
	return info
}

func symbolHasDeclarationInSourceFile(symbol *ast.Symbol, sourceFile *ast.SourceFile) bool {
	if symbol == nil || sourceFile == nil {
		return false
	}
	if symbol.ValueDeclaration != nil && ast.GetSourceFileOfNode(symbol.ValueDeclaration) == sourceFile {
		return true
	}
	for _, decl := range symbol.Declarations {
		if decl != nil && ast.GetSourceFileOfNode(decl) == sourceFile {
			return true
		}
	}
	return false
}

func shouldCheckSymbol(symbol *ast.Symbol, sourceFile *ast.SourceFile) bool {
	if symbol == nil {
		return false
	}
	checkable := ast.SymbolFlagsVariable |
		ast.SymbolFlagsFunction |
		ast.SymbolFlagsClass |
		ast.SymbolFlagsConstEnum |
		ast.SymbolFlagsRegularEnum |
		ast.SymbolFlagsTypeAlias |
		ast.SymbolFlagsTypeParameter |
		ast.SymbolFlagsInterface |
		ast.SymbolFlagsAlias |
		ast.SymbolFlagsValueModule |
		ast.SymbolFlagsNamespaceModule

	if symbol.Flags&checkable == 0 {
		return false
	}
	return symbolHasDeclarationInSourceFile(symbol, sourceFile)
}

func isNamedExportLocalIdentifier(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindIdentifier || node.Parent == nil || node.Parent.Kind != ast.KindExportSpecifier {
		return false
	}
	spec := node.Parent.AsExportSpecifier()
	if spec == nil {
		return false
	}
	if spec.PropertyName != nil {
		return spec.PropertyName == node
	}
	return spec.Name() == node
}

func isNamedExportExportedIdentifier(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindIdentifier || node.Parent == nil || node.Parent.Kind != ast.KindExportSpecifier {
		return false
	}
	spec := node.Parent.AsExportSpecifier()
	return spec != nil && spec.PropertyName != nil && spec.Name() == node
}

func isTypeReference(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return ast.IsPartOfTypeNode(node) || ast.IsPartOfTypeQuery(node)
}

func isInsideFunctionTypeScope(node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindFunctionType, ast.KindConstructorType, ast.KindCallSignature, ast.KindConstructSignature, ast.KindMethodSignature:
			return true
		}
	}
	return false
}

func isInRange(node *ast.Node, location int) bool {
	if node == nil {
		return false
	}
	return node.Pos() <= location && location <= node.End()
}

func isInInitializer(declNode *ast.Node, refNode *ast.Node) bool {
	if declNode == nil || refNode == nil {
		return false
	}
	if variableScopeNode(declNode) != variableScopeNode(refNode) {
		return false
	}
	location := refNode.End()
	for current := declNode; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindVariableDeclaration:
			decl := current.AsVariableDeclaration()
			if decl != nil {
				if isInRange(decl.Initializer, location) {
					return true
				}
				if current.Parent != nil && current.Parent.Parent != nil &&
					(current.Parent.Parent.Kind == ast.KindForInStatement || current.Parent.Parent.Kind == ast.KindForOfStatement) {
					forInOrOf := current.Parent.Parent.AsForInOrOfStatement()
					if forInOrOf != nil && isInRange(forInOrOf.Expression, location) {
						return true
					}
				}
			}
			return false
		case ast.KindParameter:
			decl := current.AsParameterDeclaration()
			return decl != nil && isInRange(decl.Initializer, location)
		case ast.KindBindingElement:
			decl := current.AsBindingElement()
			if decl != nil && isInRange(decl.Initializer, location) {
				return true
			}
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindClassDeclaration, ast.KindClassExpression, ast.KindCatchClause, ast.KindImportDeclaration, ast.KindExportDeclaration:
			return false
		}
	}
	return false
}

func isClassReferenceInDecorator(classNode *ast.Node, referenceNode *ast.Node) bool {
	if classNode == nil || referenceNode == nil {
		return false
	}
	if classNode.Kind != ast.KindClassDeclaration && classNode.Kind != ast.KindClassExpression {
		return false
	}
	modifiers := classNode.Modifiers()
	if modifiers == nil {
		return false
	}
	for _, modifier := range modifiers.Nodes {
		if modifier != nil && modifier.Kind == ast.KindDecorator && modifier.Pos() <= referenceNode.Pos() && referenceNode.End() <= modifier.End() {
			return true
		}
	}
	return false
}

func isForbiddenByOptions(opts noUseBeforeDefineOptions, info declarationInfo, referenceNode *ast.Node) bool {
	if opts.IgnoreTypeReference && isTypeReference(referenceNode) {
		return false
	}

	outerScope := info.VariableScope != nil && info.VariableScope != variableScopeNode(referenceNode)

	switch info.Kind {
	case declarationFunction:
		return opts.Functions
	case declarationClass:
		if outerScope {
			return opts.Classes
		}
		return true
	case declarationEnum:
		if outerScope {
			return opts.Enums
		}
		return true
	case declarationVariable:
		if outerScope {
			return opts.Variables
		}
		return true
	case declarationTypedef:
		return opts.Typedefs
	}
	return true
}

func isDefinedBeforeUse(info declarationInfo, referenceNode *ast.Node) bool {
	if !info.HasDeclaration || referenceNode == nil {
		return false
	}
	if info.PrimaryDecl != nil && info.PrimaryDecl.Kind == ast.KindTypeParameter {
		if id := info.PrimaryIdentifier; id != nil && id.End() <= referenceNode.End() {
			return true
		}
	}
	if info.DefinedEnd > referenceNode.End() {
		return false
	}
	return !isInInitializer(info.PrimaryDecl, referenceNode)
}

var NoUseBeforeDefineRule = rule.CreateRule(rule.Rule{
	Name: "no-use-before-define",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		declCache := map[ast.SymbolId]declarationInfo{}

		return rule.RuleListeners{
			ast.KindIdentifier: func(node *ast.Node) {
				if node == nil || node.Parent == nil || node.Kind != ast.KindIdentifier {
					return
				}
				if isNamedExportExportedIdentifier(node) {
					return
				}
				if isDeclarationIdentifier(node) {
					return
				}

				namedExport := isNamedExportLocalIdentifier(node)
				if namedExport && opts.AllowNamedExports {
					return
				}
				symbol := resolveAliasSymbol(ctx.TypeChecker, ctx.TypeChecker.GetSymbolAtLocation(node))
				if symbol == nil {
					if namedExport && !opts.AllowNamedExports {
						ctx.ReportNode(node, buildNoUseBeforeDefineMessage(node.AsIdentifier().Text))
					}
					return
				}
				if !shouldCheckSymbol(symbol, ctx.SourceFile) {
					return
				}

				symbolID := ast.GetSymbolId(symbol)
				if symbolID == 0 {
					return
				}
				info, ok := declCache[symbolID]
				if !ok {
					info = collectDeclarationInfo(symbol)
					declCache[symbolID] = info
				}
				if !info.HasDeclaration {
					return
				}

				if namedExport && !opts.AllowNamedExports {
					if !isDefinedBeforeUse(info, node) {
						ctx.ReportNode(node, buildNoUseBeforeDefineMessage(node.AsIdentifier().Text))
					}
					return
				}

				forbidden := isForbiddenByOptions(opts, info, node)
				if !forbidden {
					return
				}
				if isClassReferenceInDecorator(info.PrimaryDecl, node) {
					return
				}
				if isInsideFunctionTypeScope(node) {
					return
				}
				if !isDefinedBeforeUse(info, node) {
					ctx.ReportNode(node, buildNoUseBeforeDefineMessage(node.AsIdentifier().Text))
				}
			},
		}
	},
})
