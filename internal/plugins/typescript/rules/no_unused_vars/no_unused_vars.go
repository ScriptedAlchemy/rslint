package no_unused_vars

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type Config struct {
	Vars                           string `json:"vars"`
	VarsIgnorePattern              string `json:"varsIgnorePattern"`
	DestructuredArrayIgnorePattern string `json:"destructuredArrayIgnorePattern"`
	Args                           string `json:"args"`
	ArgsIgnorePattern              string `json:"argsIgnorePattern"`
	CaughtErrors                   string `json:"caughtErrors"`
	CaughtErrorsIgnorePattern      string `json:"caughtErrorsIgnorePattern"`
	IgnoreRestSiblings             bool   `json:"ignoreRestSiblings"`
	ReportUsedIgnorePattern        bool   `json:"reportUsedIgnorePattern"`
}

type VariableInfo struct {
	Variable       *ast.Node
	Used           bool
	OnlyUsedAsType bool
	References     []*ast.Node
	Definition     *ast.Node
}

var exportedCommentRe = regexp.MustCompile(`(?i)^\s*exported\s+(.+)$`)
var globalCommentRe = regexp.MustCompile(`(?i)^\s*global\s+(.+)$`)
var useEveryACommentRe = regexp.MustCompile(`@rule-tester/use-every-a`)

func parseOptions(options interface{}) Config {
	config := Config{
		Vars:                           "all",
		VarsIgnorePattern:              "",
		DestructuredArrayIgnorePattern: "",
		Args:                           "after-used",
		ArgsIgnorePattern:              "",
		CaughtErrors:                   "all",
		CaughtErrorsIgnorePattern:      "",
		IgnoreRestSiblings:             false,
		ReportUsedIgnorePattern:        false,
	}

	if options == nil {
		return config
	}

	applyMap := func(optsMap map[string]interface{}) {
		if val, ok := optsMap["vars"].(string); ok {
			config.Vars = val
		}
		if val, ok := optsMap["varsIgnorePattern"].(string); ok {
			config.VarsIgnorePattern = val
		}
		if val, ok := optsMap["destructuredArrayIgnorePattern"].(string); ok {
			config.DestructuredArrayIgnorePattern = val
		}
		if val, ok := optsMap["args"].(string); ok {
			config.Args = val
		}
		if val, ok := optsMap["argsIgnorePattern"].(string); ok {
			config.ArgsIgnorePattern = val
		}
		if val, ok := optsMap["caughtErrors"].(string); ok {
			config.CaughtErrors = val
		}
		if val, ok := optsMap["caughtErrorsIgnorePattern"].(string); ok {
			config.CaughtErrorsIgnorePattern = val
		}
		if val, ok := optsMap["ignoreRestSiblings"].(bool); ok {
			config.IgnoreRestSiblings = val
		}
		if val, ok := optsMap["reportUsedIgnorePattern"].(bool); ok {
			config.ReportUsedIgnorePattern = val
		}
	}

	switch opts := options.(type) {
	case map[string]interface{}:
		applyMap(opts)
	case []interface{}:
		if len(opts) > 0 {
			if first, ok := opts[0].(string); ok {
				config.Vars = first
			}
			if firstMap, ok := opts[0].(map[string]interface{}); ok {
				applyMap(firstMap)
			}
		}
		if len(opts) > 1 {
			if secondMap, ok := opts[1].(map[string]interface{}); ok {
				applyMap(secondMap)
			}
		}
	}

	return config
}

func isInTypeContext(node *ast.Node) bool {
	parent := node.Parent
	for parent != nil {
		switch parent.Kind {
		case ast.KindTypeReference,
			ast.KindTypeAliasDeclaration,
			ast.KindInterfaceDeclaration,
			ast.KindTypeParameter,
			ast.KindTypeQuery,
			ast.KindTypeOperator,
			ast.KindIndexedAccessType,
			ast.KindConditionalType,
			ast.KindInferType,
			ast.KindTypeLiteral,
			ast.KindMappedType:
			return true
		case ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression:
			return true
		}
		parent = parent.Parent
	}
	return false
}

func isPartOfDeclaration(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}

	parent := node.Parent
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		varDecl := parent.AsVariableDeclaration()
		if varDecl == nil {
			return false
		}
		return varDecl.Name() == node
	case ast.KindBindingElement:
		bindingElement := parent.AsBindingElement()
		if bindingElement == nil {
			return false
		}
		return bindingElement.Name() == node
	case ast.KindFunctionDeclaration:
		funcDecl := parent.AsFunctionDeclaration()
		if funcDecl == nil {
			return false
		}
		return funcDecl.Name() == node
	case ast.KindParameter:
		paramDecl := parent.AsParameterDeclaration()
		if paramDecl == nil {
			return false
		}
		return paramDecl.Name() == node
	case ast.KindClassDeclaration:
		classDecl := parent.AsClassDeclaration()
		if classDecl == nil {
			return false
		}
		return classDecl.Name() == node
	case ast.KindInterfaceDeclaration:
		interfaceDecl := parent.AsInterfaceDeclaration()
		if interfaceDecl == nil {
			return false
		}
		return interfaceDecl.Name() == node
	case ast.KindTypeAliasDeclaration:
		typeAlias := parent.AsTypeAliasDeclaration()
		if typeAlias == nil {
			return false
		}
		return typeAlias.Name() == node
	case ast.KindEnumDeclaration:
		enumDecl := parent.AsEnumDeclaration()
		if enumDecl == nil {
			return false
		}
		return enumDecl.Name() == node
	case ast.KindCatchClause:
		// For catch clauses, the identifier is directly the VariableDeclaration
		// Only the actual catch variable declaration should be considered a declaration
		catchClause := parent.AsCatchClause()
		if catchClause == nil {
			return false
		}
		return catchClause.VariableDeclaration == node
	case ast.KindImportClause:
		importClause := parent.AsImportClause()
		return importClause != nil && importClause.Name() == node
	case ast.KindImportSpecifier:
		importSpecifier := parent.AsImportSpecifier()
		return importSpecifier != nil && importSpecifier.Name() == node
	case ast.KindNamespaceImport:
		namespaceImport := parent.AsNamespaceImport()
		return namespaceImport != nil && namespaceImport.Name() == node
	case ast.KindImportEqualsDeclaration:
		importEquals := parent.AsImportEqualsDeclaration()
		return importEquals != nil && importEquals.Name() == node
	case ast.KindModuleDeclaration:
		moduleDeclaration := parent.AsModuleDeclaration()
		return moduleDeclaration != nil && moduleDeclaration.Name() == node
	}

	return false
}

func isPartOfAssignment(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}

	parent := node.Parent
	if parent.Kind == ast.KindBinaryExpression {
		binaryExpr := parent.AsBinaryExpression()
		if binaryExpr == nil {
			return false
		}
		// Assignment targets are not usages by default.
		if isAssignmentOperator(binaryExpr.OperatorToken.Kind) && binaryExpr.Left == node {
			return true
		}
	}

	return false
}

func isIdentifierUsageCandidate(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}

	switch node.Parent.Kind {
	case ast.KindPropertyAccessExpression:
		propertyAccess := node.Parent.AsPropertyAccessExpression()
		return propertyAccess != nil && propertyAccess.Expression == node
	case ast.KindPropertyAssignment:
		propertyAssignment := node.Parent.AsPropertyAssignment()
		return propertyAssignment != nil && propertyAssignment.Initializer == node
	case ast.KindMethodDeclaration,
		ast.KindMethodSignature,
		ast.KindPropertyDeclaration,
		ast.KindPropertySignature,
		ast.KindEnumMember:
		return false
	}

	return true
}

func shouldIgnoreVariable(varName string, varInfo *VariableInfo, opts Config, allUsages map[string][]*ast.Node, exportedNames map[string]bool, forcedUsedNames map[string]bool) bool {
	// Check if it matches ignore patterns
	if opts.VarsIgnorePattern != "" {
		if matched, _ := regexp.MatchString(opts.VarsIgnorePattern, varName); matched {
			if !varInfo.Used || !opts.ReportUsedIgnorePattern {
				return true
			}
		}
	}
	if opts.DestructuredArrayIgnorePattern != "" && isArrayBindingElementDefinition(varInfo.Definition) {
		if matched, _ := regexp.MatchString(opts.DestructuredArrayIgnorePattern, varName); matched {
			if !varInfo.Used || !opts.ReportUsedIgnorePattern {
				return true
			}
		}
	}

	if forcedUsedNames[varName] {
		return true
	}
	if isIgnoredByRestSibling(varInfo.Definition, opts) {
		return true
	}

	// Check if it's a function parameter and should be ignored
	if parameterNode := parameterNodeForDefinition(varInfo.Definition); parameterNode != nil {
		return shouldIgnoreParameter(varName, varInfo, parameterNode, opts, allUsages)
	}

	// Check if it's a caught error and should be ignored
	if isCaughtError(varInfo.Definition) {
		return shouldIgnoreCaughtError(varName, opts)
	}
	if exportedNames[varName] && isProgramLevelDefinition(varInfo.Definition) {
		return true
	}
	if opts.Vars == "local" && isProgramLevelDefinition(varInfo.Definition) {
		return true
	}

	return false
}

func isArrayBindingElementDefinition(definition *ast.Node) bool {
	return definition != nil && definition.Kind == ast.KindBindingElement && definition.Parent != nil && definition.Parent.Kind == ast.KindArrayBindingPattern
}

func isIgnoredByRestSibling(definition *ast.Node, opts Config) bool {
	if !opts.IgnoreRestSiblings || definition == nil || definition.Kind != ast.KindBindingElement || definition.Parent == nil || definition.Parent.Kind != ast.KindObjectBindingPattern {
		return false
	}
	pattern := definition.Parent.AsBindingPattern()
	if pattern == nil || pattern.Elements == nil {
		return false
	}
	seenCurrent := false
	for _, elementNode := range pattern.Elements.Nodes {
		if elementNode == nil || elementNode.Kind != ast.KindBindingElement {
			continue
		}
		if elementNode == definition {
			seenCurrent = true
			continue
		}
		if !seenCurrent {
			continue
		}
		element := elementNode.AsBindingElement()
		if element != nil && element.DotDotDotToken != nil {
			return true
		}
	}
	return false
}

func isProgramLevelDefinition(node *ast.Node) bool {
	if node == nil {
		return false
	}
	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindSourceFile:
			return true
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor,
			ast.KindBlock,
			ast.KindCatchClause,
			ast.KindModuleDeclaration,
			ast.KindModuleBlock:
			return false
		}
	}
	return false
}

func isParameter(node *ast.Node) bool {
	return parameterNodeForDefinition(node) != nil
}

func parameterNodeForDefinition(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	if node.Kind == ast.KindParameter {
		return node
	}
	if node.Kind != ast.KindBindingElement {
		return nil
	}
	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindParameter:
			return current
		case ast.KindVariableDeclaration:
			return nil
		}
	}
	return nil
}

func isCaughtError(node *ast.Node) bool {
	if node == nil {
		return false
	}
	// Check if the node is within a catch clause or is directly a catch variable
	parent := node.Parent
	for parent != nil {
		if parent.Kind == ast.KindCatchClause {
			return true
		}
		parent = parent.Parent
	}
	return false
}

func isAmbientParameter(param *ast.Node) bool {
	if param == nil {
		return false
	}
	switch param.Parent.Kind {
	case ast.KindFunctionType, ast.KindCallSignature, ast.KindConstructSignature, ast.KindMethodSignature, ast.KindConstructorType, ast.KindIndexSignature:
		return true
	}

	for current := param.Parent; current != nil; current = current.Parent {
		if utils.IncludesModifier(current, ast.KindDeclareKeyword) {
			return true
		}
	}

	if param.Parent.Kind == ast.KindFunctionDeclaration {
		functionDeclaration := param.Parent.AsFunctionDeclaration()
		if functionDeclaration != nil && functionDeclaration.Body == nil {
			return true
		}
	}
	if param.Parent.Kind == ast.KindConstructor {
		constructorDeclaration := param.Parent.AsConstructorDeclaration()
		if constructorDeclaration != nil && constructorDeclaration.Body == nil {
			return true
		}
	}
	if param.Parent.Kind == ast.KindMethodDeclaration {
		methodDeclaration := param.Parent.AsMethodDeclaration()
		if methodDeclaration != nil && methodDeclaration.Body == nil {
			return true
		}
	}

	return false
}

func isParameterProperty(param *ast.Node) bool {
	if param == nil || param.Kind != ast.KindParameter {
		return false
	}
	modifierFlags := ast.GetCombinedModifierFlags(param)
	return modifierFlags&ast.ModifierFlagsPrivate != 0 ||
		modifierFlags&ast.ModifierFlagsProtected != 0 ||
		modifierFlags&ast.ModifierFlagsPublic != 0 ||
		modifierFlags&ast.ModifierFlagsReadonly != 0
}

func isAmbientDefinition(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	if isTypeOnlyDefinition(definition) {
		return false
	}
	if definition.Kind == ast.KindVariableDeclaration {
		declareModule := enclosingDeclareModule(definition)
		if declareModule != nil && isInDeclareModuleContext(definition) {
			enclosingModule := enclosingModuleDeclaration(definition)
			if enclosingModule != nil && enclosingModule != declareModule {
				return true
			}
			moduleDeclaration := declareModule.AsModuleDeclaration()
			if moduleDeclaration != nil && moduleDeclaration.Name() != nil && moduleDeclaration.Name().Kind == ast.KindIdentifier {
				return true
			}
			return !moduleDeclarationHasValueStatements(declareModule)
		}
		return false
	}
	for current := definition; current != nil; current = current.Parent {
		if utils.IncludesModifier(current, ast.KindDeclareKeyword) {
			return true
		}
	}
	switch definition.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := definition.AsFunctionDeclaration()
		return functionDeclaration != nil && functionDeclaration.Body == nil
	case ast.KindMethodDeclaration:
		methodDeclaration := definition.AsMethodDeclaration()
		return methodDeclaration != nil && methodDeclaration.Body == nil
	}
	return false
}

func parameterIndexInParent(param *ast.Node) (int, []*ast.Node) {
	if param == nil || param.Parent == nil {
		return -1, nil
	}
	params := param.Parent.Parameters()
	for idx, current := range params {
		if current == param {
			return idx, params
		}
	}
	return -1, params
}

func isParameterUsed(param *ast.Node, allUsages map[string][]*ast.Node) bool {
	if param == nil {
		return false
	}
	if isParameterProperty(param) {
		return true
	}
	decl := param.AsParameterDeclaration()
	if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
		return true
	}
	name := decl.Name().AsIdentifier().Text
	for _, usage := range allUsages[name] {
		if usage == nil || usage.Pos() == decl.Name().Pos() {
			continue
		}
		if isPartOfAssignment(usage) || isInTypeContext(usage) {
			continue
		}
		return true
	}
	return false
}

func shouldIgnoreParameter(varName string, varInfo *VariableInfo, param *ast.Node, opts Config, allUsages map[string][]*ast.Node) bool {
	if varInfo == nil || param == nil {
		return false
	}
	if varName == "this" {
		return true
	}

	if isAmbientParameter(param) {
		return true
	}
	if isParameterProperty(param) {
		return true
	}
	if param.Parent != nil && param.Parent.Kind == ast.KindSetAccessor {
		return true
	}

	if opts.Args == "none" {
		return true
	}

	if opts.ArgsIgnorePattern != "" {
		if matched, _ := regexp.MatchString(opts.ArgsIgnorePattern, varName); matched {
			return true
		}
	}

	if opts.Args == "after-used" {
		index, params := parameterIndexInParent(param)
		if index >= 0 {
			lastUsedIndex := -1
			for idx, sibling := range params {
				if isParameterUsed(sibling, allUsages) {
					lastUsedIndex = idx
				}
			}
			if lastUsedIndex >= 0 && index < lastUsedIndex {
				return true
			}
		}
	}

	return false
}

func shouldIgnoreCaughtError(varName string, opts Config) bool {
	if opts.CaughtErrors == "none" {
		return true
	}

	if opts.CaughtErrorsIgnorePattern != "" {
		if matched, _ := regexp.MatchString(opts.CaughtErrorsIgnorePattern, varName); matched {
			return true
		}
	}

	return false
}

func isExported(varInfo *VariableInfo) bool {
	if varInfo.Variable == nil {
		return false
	}

	// Check for export modifier flags first
	if varInfo.Definition != nil {
		modifierFlags := ast.GetCombinedModifierFlags(varInfo.Definition)
		if modifierFlags&ast.ModifierFlagsExport != 0 {
			return true
		}
	}

	// Check for export declarations by looking up the AST
	parent := varInfo.Variable.Parent
	for parent != nil {
		if parent.Kind == ast.KindExportDeclaration {
			return true
		}
		parent = parent.Parent
	}

	// Also check if it's referenced in an export
	for _, ref := range varInfo.References {
		refParent := ref.Parent
		for refParent != nil {
			if refParent.Kind == ast.KindExportDeclaration {
				return true
			}
			refParent = refParent.Parent
		}
	}

	return false
}

func buildUnusedVarMessage(varName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unusedVar",
		Description: fmt.Sprintf("'%s' is defined but never used.", varName),
	}
}

func buildUsedOnlyAsTypeMessage(varName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "usedOnlyAsType",
		Description: fmt.Sprintf("'%s' is defined but only used as a type.", varName),
	}
}

func buildUsedIgnoredVarMessage(varName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "usedIgnoredVar",
		Description: fmt.Sprintf("'%s' is marked as ignored but is used.", varName),
	}
}

func isTypeOnlyImportDefinition(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	switch definition.Kind {
	case ast.KindImportClause:
		importClause := definition.AsImportClause()
		return importClause != nil && importClause.IsTypeOnly()
	case ast.KindImportSpecifier:
		importSpecifier := definition.AsImportSpecifier()
		if importSpecifier == nil {
			return false
		}
		if importSpecifier.IsTypeOnly {
			return true
		}
		for current := definition.Parent; current != nil; current = current.Parent {
			if current.Kind == ast.KindImportClause {
				importClause := current.AsImportClause()
				return importClause != nil && importClause.IsTypeOnly()
			}
		}
	case ast.KindNamespaceImport:
		for current := definition.Parent; current != nil; current = current.Parent {
			if current.Kind == ast.KindImportClause {
				importClause := current.AsImportClause()
				return importClause != nil && importClause.IsTypeOnly()
			}
		}
	}
	return false
}

func isJSXPragmaImportUsed(ctx rule.RuleContext, definition *ast.Node, name string, sourceHasJSX bool) bool {
	if !sourceHasJSX || definition == nil || name == "" {
		return false
	}
	if ctx.ParserOptions == nil || ctx.ParserOptions.EcmaFeatures == nil || !ctx.ParserOptions.EcmaFeatures.JSX {
		return false
	}

	pragma := ctx.ParserOptions.JSXPragma
	if pragma == "" {
		if !hasMultipleReactImports(definition) {
			return false
		}
		pragma = "React"
	}
	pragmaIdentifier := pragma
	if dot := strings.IndexByte(pragma, '.'); dot >= 0 {
		pragmaIdentifier = pragma[:dot]
	}
	if pragmaIdentifier != name {
		return false
	}

	switch definition.Kind {
	case ast.KindImportClause:
		importClause := definition.AsImportClause()
		return importClause != nil && !importClause.IsTypeOnly()
	case ast.KindImportSpecifier:
		importSpecifier := definition.AsImportSpecifier()
		if importSpecifier == nil || importSpecifier.IsTypeOnly {
			return false
		}
		for current := definition.Parent; current != nil; current = current.Parent {
			if current.Kind == ast.KindImportClause {
				importClause := current.AsImportClause()
				return importClause != nil && !importClause.IsTypeOnly()
			}
		}
		return true
	case ast.KindNamespaceImport:
		for current := definition.Parent; current != nil; current = current.Parent {
			if current.Kind == ast.KindImportClause {
				importClause := current.AsImportClause()
				return importClause != nil && !importClause.IsTypeOnly()
			}
		}
		return true
	case ast.KindImportEqualsDeclaration:
		return true
	default:
		return false
	}
}

func hasMultipleReactImports(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	root := definition
	for root.Parent != nil {
		root = root.Parent
	}
	if root.Kind != ast.KindSourceFile {
		return false
	}
	sourceFile := root.AsSourceFile()
	if sourceFile == nil || sourceFile.Statements == nil {
		return false
	}
	reactImportCount := 0
	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindImportDeclaration {
			continue
		}
		importDeclaration := statement.AsImportDeclaration()
		if importDeclaration == nil || importDeclaration.ModuleSpecifier == nil || importDeclaration.ModuleSpecifier.Kind != ast.KindStringLiteral {
			continue
		}
		if importDeclaration.ModuleSpecifier.AsStringLiteral().Text == "react" {
			reactImportCount++
			if reactImportCount > 1 {
				return true
			}
		}
	}
	return false
}

func isImportDefinition(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	switch definition.Kind {
	case ast.KindImportClause, ast.KindImportSpecifier, ast.KindNamespaceImport, ast.KindImportEqualsDeclaration:
		return true
	default:
		return false
	}
}

func isTypeOnlyDefinition(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	switch definition.Kind {
	case ast.KindInterfaceDeclaration, ast.KindTypeAliasDeclaration, ast.KindTypeParameter, ast.KindEnumDeclaration, ast.KindModuleDeclaration:
		return true
	default:
		return false
	}
}

func safeTypeParameters(node *ast.Node) (params []*ast.Node) {
	if node == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			params = nil
		}
	}()
	return node.TypeParameters()
}

func nodeDeclaresTypeParameters(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration,
		ast.KindFunctionExpression,
		ast.KindArrowFunction,
		ast.KindMethodDeclaration,
		ast.KindMethodSignature,
		ast.KindCallSignature,
		ast.KindConstructSignature,
		ast.KindFunctionType,
		ast.KindConstructorType,
		ast.KindClassDeclaration,
		ast.KindClassExpression,
		ast.KindInterfaceDeclaration,
		ast.KindTypeAliasDeclaration:
		return true
	default:
		return false
	}
}

func isUsageShadowedByTypeParameter(usage *ast.Node, name string) bool {
	if usage == nil || name == "" {
		return false
	}
	for current := usage.Parent; current != nil; current = current.Parent {
		if !nodeDeclaresTypeParameters(current) {
			continue
		}
		for _, typeParameter := range safeTypeParameters(current) {
			if typeParameter == nil {
				continue
			}
			decl := typeParameter.AsTypeParameter()
			if decl == nil || decl.Name() == nil {
				continue
			}
			if decl.Name().Text() == name {
				return true
			}
		}
	}
	return false
}

func isDescendantOf(node *ast.Node, ancestor *ast.Node) bool {
	if node == nil || ancestor == nil {
		return false
	}
	for current := node.Parent; current != nil; current = current.Parent {
		if current == ancestor {
			return true
		}
	}
	return false
}

func scopeDepth(node *ast.Node) int {
	depth := 0
	for current := node; current != nil; current = current.Parent {
		depth++
	}
	return depth
}

func isValueScopeBoundary(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindSourceFile,
		ast.KindFunctionDeclaration,
		ast.KindFunctionExpression,
		ast.KindArrowFunction,
		ast.KindMethodDeclaration,
		ast.KindConstructor,
		ast.KindGetAccessor,
		ast.KindSetAccessor:
		return true
	}
	return false
}

func nearestValueScope(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if isValueScopeBoundary(current) {
			return current
		}
	}
	return nil
}

func isBlockScopeBoundary(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindSourceFile,
		ast.KindBlock,
		ast.KindModuleBlock,
		ast.KindForStatement,
		ast.KindForInStatement,
		ast.KindForOfStatement,
		ast.KindCatchClause,
		ast.KindFunctionDeclaration,
		ast.KindFunctionExpression,
		ast.KindArrowFunction,
		ast.KindMethodDeclaration,
		ast.KindConstructor,
		ast.KindGetAccessor,
		ast.KindSetAccessor:
		return true
	}
	return false
}

func nearestBlockScope(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if isBlockScopeBoundary(current) {
			return current
		}
	}
	return nil
}

func valueDeclarationScope(definition *ast.Node) *ast.Node {
	if definition == nil {
		return nil
	}
	switch definition.Kind {
	case ast.KindVariableDeclaration:
		if definition.Parent != nil && definition.Parent.Kind == ast.KindVariableDeclarationList {
			declarationList := definition.Parent.AsVariableDeclarationList()
			if declarationList != nil && declarationList.Flags&ast.NodeFlagsBlockScoped == 0 {
				return nearestValueScope(definition.Parent)
			}
		}
		return nearestBlockScope(definition.Parent)
	case ast.KindBindingElement:
		for current := definition.Parent; current != nil; current = current.Parent {
			switch current.Kind {
			case ast.KindVariableDeclaration:
				return valueDeclarationScope(current)
			case ast.KindParameter:
				return valueDeclarationScope(current)
			}
		}
		return nearestBlockScope(definition.Parent)
	case ast.KindParameter:
		return nearestValueScope(definition.Parent)
	case ast.KindFunctionDeclaration,
		ast.KindClassDeclaration,
		ast.KindEnumDeclaration,
		ast.KindImportClause,
		ast.KindImportSpecifier,
		ast.KindNamespaceImport,
		ast.KindImportEqualsDeclaration:
		return nearestBlockScope(definition.Parent)
	case ast.KindFunctionExpression:
		return nearestValueScope(definition.Parent)
	}
	return nearestBlockScope(definition.Parent)
}

func isForInOrOfIterationVariable(definition *ast.Node) bool {
	if definition == nil {
		return false
	}

	variableDeclaration := definition
	if definition.Kind == ast.KindBindingElement {
		for current := definition.Parent; current != nil; current = current.Parent {
			if current.Kind == ast.KindVariableDeclaration {
				variableDeclaration = current
				break
			}
			if current.Kind == ast.KindParameter {
				return false
			}
		}
	}
	if variableDeclaration == nil || variableDeclaration.Kind != ast.KindVariableDeclaration {
		return false
	}
	if variableDeclaration.Parent == nil || variableDeclaration.Parent.Kind != ast.KindVariableDeclarationList || variableDeclaration.Parent.Parent == nil {
		return false
	}

	variableDeclarationList := variableDeclaration.Parent
	switch variableDeclarationList.Parent.Kind {
	case ast.KindForInStatement:
		forInStatement := variableDeclarationList.Parent.AsForInOrOfStatement()
		return forInStatement != nil && forInStatement.Initializer == variableDeclarationList
	case ast.KindForOfStatement:
		forOfStatement := variableDeclarationList.Parent.AsForInOrOfStatement()
		return forOfStatement != nil && forOfStatement.Initializer == variableDeclarationList
	}
	return false
}

func isUsageShadowedByValueDeclaration(usage *ast.Node, definition *ast.Node, name string, allValueDeclarations map[string][]*ast.Node) bool {
	if usage == nil || definition == nil || name == "" {
		return false
	}

	definitionScope := valueDeclarationScope(definition)
	if definitionScope == nil {
		return false
	}

	bestDepth := scopeDepth(definitionScope)
	bestDefinition := definition

	for _, candidate := range allValueDeclarations[name] {
		if candidate == nil || candidate == definition {
			continue
		}
		candidateScope := valueDeclarationScope(candidate)
		if candidateScope == nil || candidateScope == definitionScope {
			continue
		}
		if !isDescendantOf(usage, candidateScope) {
			continue
		}

		candidateDepth := scopeDepth(candidateScope)
		if candidateDepth > bestDepth {
			bestDepth = candidateDepth
			bestDefinition = candidate
			continue
		}
		if candidateDepth == bestDepth && candidate.Pos() > bestDefinition.Pos() {
			bestDefinition = candidate
		}
	}

	return bestDefinition != definition
}

func collectVariableUsages(node *ast.Node, usages map[string][]*ast.Node) {
	if node == nil {
		return
	}

	// Visit current node
	if ast.IsIdentifier(node) && !isPartOfDeclaration(node) && isIdentifierUsageCandidate(node) {
		if isPartOfAssignment(node) && !isUsedAssignmentTarget(node) {
			return
		}
		identifier := node.AsIdentifier()
		if identifier == nil {
			return
		}
		name := identifier.Text
		usages[name] = append(usages[name], node)
	}

	// Recursively visit all children using ForEachChild
	node.ForEachChild(func(child *ast.Node) bool {
		collectVariableUsages(child, usages)
		return false // Continue traversing
	})
}

func isUsedAssignmentTarget(node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Kind != ast.KindBinaryExpression {
		return false
	}
	assignmentExpression := node.Parent
	binaryExpression := assignmentExpression.AsBinaryExpression()
	if binaryExpression == nil || !isAssignmentOperator(binaryExpression.OperatorToken.Kind) || binaryExpression.Left != node {
		return false
	}
	consumed := false
	for current := assignmentExpression.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindParenthesizedExpression {
			continue
		}
		consumed = current.Kind != ast.KindExpressionStatement
		break
	}
	if !consumed {
		return false
	}

	if binaryExpression.OperatorToken.Kind != ast.KindEqualsToken {
		return true
	}
	if binaryExpression.Left == nil || binaryExpression.Left.Kind != ast.KindIdentifier {
		return false
	}
	name := binaryExpression.Left.AsIdentifier().Text
	if name == "" || binaryExpression.Right == nil {
		return false
	}
	return assignmentExpressionHasSelfRead(binaryExpression.Right, name)
}

func assignmentExpressionHasSelfRead(node *ast.Node, name string) bool {
	if node == nil || name == "" {
		return false
	}
	found := false
	var visit func(current *ast.Node)
	visit = func(current *ast.Node) {
		if current == nil || found {
			return
		}
		switch current.Kind {
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return
		}
		if current.Kind == ast.KindIdentifier && current.AsIdentifier().Text == name && !isPartOfDeclaration(current) {
			found = true
			return
		}
		current.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return found
		})
	}
	visit(node)
	return found
}

func collectVariableWrites(node *ast.Node, writes map[string][]*ast.Node) {
	if node == nil {
		return
	}

	if ast.IsIdentifier(node) {
		identifier := node.AsIdentifier()
		if identifier == nil {
			return
		}
		name := identifier.Text
		if isAssignmentTarget(node) {
			writes[name] = append(writes[name], node)
		} else if isPartOfDeclaration(node) && node.Parent != nil && node.Parent.Kind == ast.KindVariableDeclaration {
			variableDeclaration := node.Parent.AsVariableDeclaration()
			if variableDeclaration != nil && variableDeclaration.Initializer != nil {
				writes[name] = append(writes[name], node)
			}
		}
	}

	node.ForEachChild(func(child *ast.Node) bool {
		collectVariableWrites(child, writes)
		return false
	})
}

func isAssignmentTarget(node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Kind != ast.KindBinaryExpression {
		return false
	}
	binaryExpression := node.Parent.AsBinaryExpression()
	if binaryExpression == nil {
		return false
	}
	return isAssignmentOperator(binaryExpression.OperatorToken.Kind) && binaryExpression.Left == node
}

func collectValueDeclarations(node *ast.Node, declarations map[string][]*ast.Node) {
	if node == nil {
		return
	}

	addNamed := func(nameNode *ast.Node) {
		if nameNode == nil || nameNode.Kind != ast.KindIdentifier {
			return
		}
		name := nameNode.AsIdentifier().Text
		declarations[name] = append(declarations[name], node)
	}

	switch node.Kind {
	case ast.KindVariableDeclaration:
		varDecl := node.AsVariableDeclaration()
		if varDecl != nil {
			addNamed(varDecl.Name())
		}
	case ast.KindBindingElement:
		bindingElement := node.AsBindingElement()
		if bindingElement != nil {
			addNamed(bindingElement.Name())
		}
	case ast.KindFunctionDeclaration:
		funcDecl := node.AsFunctionDeclaration()
		if funcDecl != nil {
			addNamed(funcDecl.Name())
		}
	case ast.KindClassDeclaration:
		classDecl := node.AsClassDeclaration()
		if classDecl != nil {
			addNamed(classDecl.Name())
		}
	case ast.KindEnumDeclaration:
		enumDecl := node.AsEnumDeclaration()
		if enumDecl != nil {
			addNamed(enumDecl.Name())
		}
	case ast.KindImportClause:
		importClause := node.AsImportClause()
		if importClause != nil && importClause.Name() != nil {
			addNamed(importClause.Name().AsNode())
		}
	case ast.KindImportSpecifier:
		importSpecifier := node.AsImportSpecifier()
		if importSpecifier != nil {
			addNamed(importSpecifier.Name())
		}
	case ast.KindNamespaceImport:
		namespaceImport := node.AsNamespaceImport()
		if namespaceImport != nil && namespaceImport.Name() != nil {
			addNamed(namespaceImport.Name().AsNode())
		}
	case ast.KindImportEqualsDeclaration:
		importEquals := node.AsImportEqualsDeclaration()
		if importEquals != nil {
			addNamed(importEquals.Name())
		}
	}

	node.ForEachChild(func(child *ast.Node) bool {
		collectValueDeclarations(child, declarations)
		return false
	})
}

func collectTypeDeclarations(node *ast.Node, declarations map[string][]*ast.Node) {
	if node == nil {
		return
	}

	addNamed := func(name string) {
		if name == "" {
			return
		}
		declarations[name] = append(declarations[name], node)
	}

	switch node.Kind {
	case ast.KindInterfaceDeclaration:
		interfaceDeclaration := node.AsInterfaceDeclaration()
		if interfaceDeclaration != nil && interfaceDeclaration.Name() != nil {
			addNamed(interfaceDeclaration.Name().Text())
		}
	case ast.KindTypeAliasDeclaration:
		typeAliasDeclaration := node.AsTypeAliasDeclaration()
		if typeAliasDeclaration != nil && typeAliasDeclaration.Name() != nil {
			addNamed(typeAliasDeclaration.Name().Text())
		}
	case ast.KindEnumDeclaration:
		enumDeclaration := node.AsEnumDeclaration()
		if enumDeclaration != nil && enumDeclaration.Name() != nil && enumDeclaration.Name().Kind == ast.KindIdentifier {
			addNamed(enumDeclaration.Name().AsIdentifier().Text)
		}
	}

	node.ForEachChild(func(child *ast.Node) bool {
		collectTypeDeclarations(child, declarations)
		return false
	})
}

func hasOtherValueDeclaration(name string, definition *ast.Node, declarations map[string][]*ast.Node) bool {
	if name == "" {
		return false
	}
	for _, declNode := range declarations[name] {
		if declNode != nil && declNode != definition {
			return true
		}
	}
	return false
}

func hasEarlierTypeDeclaration(name string, definition *ast.Node, declarations map[string][]*ast.Node) bool {
	if name == "" || definition == nil {
		return false
	}
	for _, declNode := range declarations[name] {
		if declNode == nil || declNode == definition || declNode.Kind != definition.Kind {
			continue
		}
		if declNode.Pos() < definition.Pos() {
			return true
		}
	}
	return false
}

func declarationNameText(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindInterfaceDeclaration:
		interfaceDeclaration := node.AsInterfaceDeclaration()
		if interfaceDeclaration != nil && interfaceDeclaration.Name() != nil {
			return interfaceDeclaration.Name().Text()
		}
	case ast.KindTypeAliasDeclaration:
		typeAliasDeclaration := node.AsTypeAliasDeclaration()
		if typeAliasDeclaration != nil && typeAliasDeclaration.Name() != nil {
			return typeAliasDeclaration.Name().Text()
		}
	case ast.KindEnumDeclaration:
		enumDeclaration := node.AsEnumDeclaration()
		if enumDeclaration != nil && enumDeclaration.Name() != nil && enumDeclaration.Name().Kind == ast.KindIdentifier {
			return enumDeclaration.Name().AsIdentifier().Text
		}
	case ast.KindModuleDeclaration:
		moduleDeclaration := node.AsModuleDeclaration()
		if moduleDeclaration != nil && moduleDeclaration.Name() != nil && moduleDeclaration.Name().Kind == ast.KindIdentifier {
			return moduleDeclaration.Name().AsIdentifier().Text
		}
	}
	return ""
}

func usageInSameNamedTypeDeclaration(usage *ast.Node, definition *ast.Node, name string) bool {
	if usage == nil || definition == nil || name == "" {
		return false
	}
	for current := usage.Parent; current != nil; current = current.Parent {
		if !isTypeOnlyDefinition(current) {
			continue
		}
		if declarationNameText(current) != name {
			continue
		}
		return current != definition
	}
	return false
}

func isAssignmentOperator(kind ast.Kind) bool {
	switch kind {
	case ast.KindEqualsToken,
		ast.KindPlusEqualsToken,
		ast.KindMinusEqualsToken,
		ast.KindAsteriskEqualsToken,
		ast.KindSlashEqualsToken,
		ast.KindPercentEqualsToken,
		ast.KindAsteriskAsteriskEqualsToken,
		ast.KindAmpersandEqualsToken,
		ast.KindBarEqualsToken,
		ast.KindCaretEqualsToken,
		ast.KindLessThanLessThanEqualsToken,
		ast.KindGreaterThanGreaterThanEqualsToken,
		ast.KindGreaterThanGreaterThanGreaterThanEqualsToken:
		return true
	default:
		return false
	}
}

func isSelfAssignmentUsage(usage *ast.Node, name string) bool {
	if usage == nil || name == "" {
		return false
	}
	for current := usage.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return false
		}
		if current.Kind != ast.KindBinaryExpression {
			continue
		}
		binaryExpression := current.AsBinaryExpression()
		if binaryExpression == nil || !isAssignmentOperator(binaryExpression.OperatorToken.Kind) {
			continue
		}
		if binaryExpression.Left == nil || binaryExpression.Left.Kind != ast.KindIdentifier {
			return false
		}
		if binaryExpression.Left.AsIdentifier().Text != name {
			return false
		}
		return binaryExpression.Left != usage
	}
	return false
}

func parseExportedCommentNames(sourceText string) map[string]bool {
	names := map[string]bool{}
	if sourceText == "" {
		return names
	}

	addNames := func(commentBody string) {
		matches := exportedCommentRe.FindStringSubmatch(commentBody)
		if len(matches) < 2 {
			return
		}
		for _, token := range strings.Split(matches[1], ",") {
			name := strings.TrimSpace(token)
			if name == "" {
				continue
			}
			if colon := strings.Index(name, ":"); colon >= 0 {
				name = strings.TrimSpace(name[:colon])
			}
			if name != "" {
				names[name] = true
			}
		}
	}

	for i := 0; i < len(sourceText)-1; i++ {
		if sourceText[i] != '/' {
			continue
		}
		if sourceText[i+1] == '/' {
			j := i + 2
			for j < len(sourceText) && sourceText[j] != '\n' && sourceText[j] != '\r' {
				j++
			}
			addNames(sourceText[i+2 : j])
			i = j
			continue
		}
		if sourceText[i+1] == '*' {
			j := i + 2
			for j+1 < len(sourceText) && (sourceText[j] != '*' || sourceText[j+1] != '/') {
				j++
			}
			if j+1 >= len(sourceText) {
				break
			}
			addNames(sourceText[i+2 : j])
			i = j + 1
		}
	}

	return names
}

func parseGlobalCommentNames(sourceText string) map[string]bool {
	names := map[string]bool{}
	if sourceText == "" {
		return names
	}

	addNames := func(commentBody string) {
		matches := globalCommentRe.FindStringSubmatch(commentBody)
		if len(matches) < 2 {
			return
		}
		for _, token := range strings.Split(matches[1], ",") {
			name := strings.TrimSpace(token)
			if name == "" {
				continue
			}
			if colon := strings.Index(name, ":"); colon >= 0 {
				name = strings.TrimSpace(name[:colon])
			}
			if name != "" {
				names[name] = true
			}
		}
	}

	for i := 0; i < len(sourceText)-1; i++ {
		if sourceText[i] != '/' {
			continue
		}
		if sourceText[i+1] == '/' {
			j := i + 2
			for j < len(sourceText) && sourceText[j] != '\n' && sourceText[j] != '\r' {
				j++
			}
			addNames(sourceText[i+2 : j])
			i = j
			continue
		}
		if sourceText[i+1] == '*' {
			j := i + 2
			for j+1 < len(sourceText) && (sourceText[j] != '*' || sourceText[j+1] != '/') {
				j++
			}
			if j+1 >= len(sourceText) {
				break
			}
			addNames(sourceText[i+2 : j])
			i = j + 1
		}
	}

	return names
}

func hasUseEveryAComment(sourceText string) bool {
	return useEveryACommentRe.MatchString(sourceText)
}

func functionLikeBodyNode(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		if functionDeclaration != nil {
			return functionDeclaration.Body
		}
	case ast.KindFunctionExpression:
		functionExpression := node.AsFunctionExpression()
		if functionExpression != nil {
			return functionExpression.Body
		}
	case ast.KindMethodDeclaration:
		methodDeclaration := node.AsMethodDeclaration()
		if methodDeclaration != nil {
			return methodDeclaration.Body
		}
	case ast.KindConstructor:
		constructorDeclaration := node.AsConstructorDeclaration()
		if constructorDeclaration != nil {
			return constructorDeclaration.Body
		}
	case ast.KindGetAccessor:
		getAccessorDeclaration := node.AsGetAccessorDeclaration()
		if getAccessorDeclaration != nil {
			return getAccessorDeclaration.Body
		}
	case ast.KindSetAccessor:
		setAccessorDeclaration := node.AsSetAccessorDeclaration()
		if setAccessorDeclaration != nil {
			return setAccessorDeclaration.Body
		}
	case ast.KindArrowFunction:
		arrowFunction := node.AsArrowFunction()
		if arrowFunction != nil {
			return arrowFunction.Body
		}
	}
	return nil
}

func sourceFileHasJSX(root *ast.Node) bool {
	if root == nil {
		return false
	}
	hasJSX := false
	var visit func(node *ast.Node)
	visit = func(node *ast.Node) {
		if node == nil || hasJSX {
			return
		}
		switch node.Kind {
		case ast.KindJsxElement, ast.KindJsxSelfClosingElement, ast.KindJsxFragment:
			hasJSX = true
			return
		}
		node.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return hasJSX
		})
	}
	visit(root)
	return hasJSX
}

func enclosingDeclareModule(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if current.Kind == ast.KindModuleDeclaration && utils.IncludesModifier(current, ast.KindDeclareKeyword) {
			return current
		}
	}
	return nil
}

func moduleDeclarationHasValueStatements(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindModuleDeclaration {
		return false
	}
	moduleDeclaration := node.AsModuleDeclaration()
	if moduleDeclaration == nil || moduleDeclaration.Body == nil {
		return false
	}
	if moduleDeclaration.Body.Kind == ast.KindModuleDeclaration {
		return moduleDeclarationHasValueStatements(moduleDeclaration.Body)
	}
	if moduleDeclaration.Body.Kind != ast.KindModuleBlock {
		return false
	}
	moduleBlock := moduleDeclaration.Body.AsModuleBlock()
	if moduleBlock == nil || moduleBlock.Statements == nil {
		return false
	}
	for _, statement := range moduleBlock.Statements.Nodes {
		if statement == nil {
			continue
		}
		switch statement.Kind {
		case ast.KindInterfaceDeclaration, ast.KindTypeAliasDeclaration:
			continue
		case ast.KindImportDeclaration:
			importDeclaration := statement.AsImportDeclaration()
			if importDeclaration == nil || importDeclaration.ImportClause == nil {
				return true
			}
			if importDeclaration.ImportClause.IsTypeOnly() {
				continue
			}
			return true
		case ast.KindModuleDeclaration:
			if moduleDeclarationHasValueStatements(statement) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func moduleDeclarationHasExportMarker(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindModuleDeclaration {
		return false
	}
	moduleDeclaration := node.AsModuleDeclaration()
	if moduleDeclaration == nil || moduleDeclaration.Body == nil {
		return false
	}
	if moduleDeclaration.Body.Kind == ast.KindModuleDeclaration {
		return moduleDeclarationHasExportMarker(moduleDeclaration.Body)
	}
	if moduleDeclaration.Body.Kind != ast.KindModuleBlock {
		return false
	}
	moduleBlock := moduleDeclaration.Body.AsModuleBlock()
	if moduleBlock == nil || moduleBlock.Statements == nil {
		return false
	}
	for _, statement := range moduleBlock.Statements.Nodes {
		if statement == nil {
			continue
		}
		switch statement.Kind {
		case ast.KindExportAssignment:
			return true
		case ast.KindExportDeclaration:
			exportDeclaration := statement.AsExportDeclaration()
			if exportDeclaration == nil {
				continue
			}
			return true
		case ast.KindModuleDeclaration:
			if moduleDeclarationHasExportMarker(statement) {
				return true
			}
		}
	}
	return false
}

func moduleDeclarationHasOwnExportMarker(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindModuleDeclaration {
		return false
	}
	moduleDeclaration := node.AsModuleDeclaration()
	if moduleDeclaration == nil || moduleDeclaration.Body == nil || moduleDeclaration.Body.Kind != ast.KindModuleBlock {
		return false
	}
	moduleBlock := moduleDeclaration.Body.AsModuleBlock()
	if moduleBlock == nil || moduleBlock.Statements == nil {
		return false
	}
	for _, statement := range moduleBlock.Statements.Nodes {
		if statement == nil {
			continue
		}
		if statement.Kind == ast.KindExportAssignment || statement.Kind == ast.KindExportDeclaration {
			return true
		}
	}
	return false
}

func moduleDeclarationHasDirectNestedNamespaceWithValues(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindModuleDeclaration {
		return false
	}
	moduleDeclaration := node.AsModuleDeclaration()
	if moduleDeclaration == nil || moduleDeclaration.Body == nil || moduleDeclaration.Body.Kind != ast.KindModuleBlock {
		return false
	}
	moduleBlock := moduleDeclaration.Body.AsModuleBlock()
	if moduleBlock == nil || moduleBlock.Statements == nil {
		return false
	}
	for _, statement := range moduleBlock.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindModuleDeclaration {
			continue
		}
		if moduleDeclarationHasValueStatements(statement) {
			return true
		}
	}
	return false
}

func sourceFileHasExportMarker(sourceFile *ast.SourceFile) bool {
	if sourceFile == nil || sourceFile.Statements == nil {
		return false
	}
	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil {
			continue
		}
		switch statement.Kind {
		case ast.KindExportAssignment, ast.KindExportDeclaration:
			return true
		}
	}
	return false
}

func enclosingModuleDeclaration(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if current.Kind == ast.KindModuleDeclaration {
			return current
		}
	}
	return nil
}

func parentModuleDeclaration(node *ast.Node) *ast.Node {
	if node == nil || node.Parent == nil {
		return nil
	}
	if node.Parent.Kind == ast.KindModuleDeclaration {
		return node.Parent
	}
	if node.Parent.Kind == ast.KindModuleBlock && node.Parent.Parent != nil && node.Parent.Parent.Kind == ast.KindModuleDeclaration {
		return node.Parent.Parent
	}
	return nil
}

func nodeDefinesName(node *ast.Node, name string) bool {
	if node == nil || name == "" {
		return false
	}
	matchesIdentifier := func(identifier *ast.Node) bool {
		return identifier != nil && identifier.Kind == ast.KindIdentifier && identifier.AsIdentifier().Text == name
	}

	switch node.Kind {
	case ast.KindFunctionDeclaration:
		functionDeclaration := node.AsFunctionDeclaration()
		return functionDeclaration != nil && matchesIdentifier(functionDeclaration.Name())
	case ast.KindClassDeclaration:
		classDeclaration := node.AsClassDeclaration()
		return classDeclaration != nil && matchesIdentifier(classDeclaration.Name())
	case ast.KindEnumDeclaration:
		enumDeclaration := node.AsEnumDeclaration()
		return enumDeclaration != nil && matchesIdentifier(enumDeclaration.Name())
	case ast.KindInterfaceDeclaration:
		interfaceDeclaration := node.AsInterfaceDeclaration()
		return interfaceDeclaration != nil && interfaceDeclaration.Name() != nil && interfaceDeclaration.Name().Text() == name
	case ast.KindTypeAliasDeclaration:
		typeAliasDeclaration := node.AsTypeAliasDeclaration()
		return typeAliasDeclaration != nil && typeAliasDeclaration.Name() != nil && typeAliasDeclaration.Name().Text() == name
	case ast.KindModuleDeclaration:
		moduleDeclaration := node.AsModuleDeclaration()
		return moduleDeclaration != nil && matchesIdentifier(moduleDeclaration.Name())
	case ast.KindVariableStatement:
		variableStatement := node.AsVariableStatement()
		if variableStatement == nil || variableStatement.DeclarationList == nil {
			return false
		}
		declarationList := variableStatement.DeclarationList.AsVariableDeclarationList()
		if declarationList == nil {
			return false
		}
		for _, declaration := range declarationList.Declarations.Nodes {
			if declaration == nil || declaration.Name() == nil {
				continue
			}
			if declaration.Name().Kind == ast.KindIdentifier && declaration.Name().AsIdentifier().Text == name {
				return true
			}
		}
	}
	return false
}

func moduleHasInnerSameNameDeclaration(moduleNode *ast.Node, name string) bool {
	if moduleNode == nil || moduleNode.Kind != ast.KindModuleDeclaration || name == "" {
		return false
	}
	moduleDeclaration := moduleNode.AsModuleDeclaration()
	if moduleDeclaration == nil || moduleDeclaration.Body == nil {
		return false
	}
	if moduleDeclaration.Body.Kind == ast.KindModuleDeclaration {
		if nodeDefinesName(moduleDeclaration.Body, name) {
			return true
		}
		return moduleHasInnerSameNameDeclaration(moduleDeclaration.Body, name)
	}
	if moduleDeclaration.Body.Kind != ast.KindModuleBlock {
		return false
	}
	moduleBlock := moduleDeclaration.Body.AsModuleBlock()
	if moduleBlock == nil || moduleBlock.Statements == nil {
		return false
	}
	for _, statement := range moduleBlock.Statements.Nodes {
		if nodeDefinesName(statement, name) {
			return true
		}
		if statement != nil && statement.Kind == ast.KindModuleDeclaration && moduleHasInnerSameNameDeclaration(statement, name) {
			return true
		}
	}
	return false
}

func hasOwnExportModifier(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	return ast.HasSyntacticModifier(definition, ast.ModifierFlagsExport) || ast.HasSyntacticModifier(definition, ast.ModifierFlagsDefault)
}

func hasOwnDeclareModifier(definition *ast.Node) bool {
	if definition == nil {
		return false
	}
	return utils.IncludesModifier(definition, ast.KindDeclareKeyword)
}

func hasOwnDeclareVariableModifier(definition *ast.Node) bool {
	if definition == nil || definition.Kind != ast.KindVariableDeclaration || definition.Parent == nil {
		return false
	}
	if definition.Parent.Kind != ast.KindVariableDeclarationList || definition.Parent.Parent == nil {
		return false
	}
	if definition.Parent.Parent.Kind != ast.KindVariableStatement {
		return false
	}
	variableStatement := definition.Parent.Parent.AsVariableStatement()
	if variableStatement == nil {
		return false
	}
	return utils.IncludesModifier(variableStatement, ast.KindDeclareKeyword)
}

func isTypeDeclarationMergedWithExportedNamespace(definition *ast.Node, name string) bool {
	if definition == nil || name == "" {
		return false
	}
	for current := definition.Parent; current != nil; current = current.Parent {
		if current.Kind != ast.KindModuleDeclaration {
			continue
		}
		moduleDeclaration := current.AsModuleDeclaration()
		if moduleDeclaration == nil || moduleDeclaration.Name() == nil || moduleDeclaration.Name().Kind != ast.KindIdentifier {
			continue
		}
		if moduleDeclaration.Name().AsIdentifier().Text != name {
			continue
		}
		if hasOwnExportModifier(current) {
			return true
		}
	}
	return false
}

func isTopLevelVariableDeclaration(definition *ast.Node) bool {
	if definition == nil || definition.Kind != ast.KindVariableDeclaration || definition.Parent == nil {
		return false
	}
	if definition.Parent.Kind != ast.KindVariableDeclarationList || definition.Parent.Parent == nil {
		return false
	}
	if definition.Parent.Parent.Kind != ast.KindVariableStatement || definition.Parent.Parent.Parent == nil {
		return false
	}
	return definition.Parent.Parent.Parent.Kind == ast.KindSourceFile
}

func isDottedNamespaceContinuation(ctx rule.RuleContext, node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Kind != ast.KindModuleDeclaration {
		return false
	}
	parent := node.Parent.AsModuleDeclaration()
	if parent == nil || parent.Name() == nil {
		return false
	}
	start := parent.Name().End()
	end := node.Pos()
	sourceText := ctx.SourceFile.Text()
	if start < 0 || end < 0 || end < start || end > len(sourceText) {
		return false
	}
	return strings.Contains(sourceText[start:end], ".")
}

func isDottedNamespaceContainer(ctx rule.RuleContext, node *ast.Node, moduleDeclaration *ast.ModuleDeclaration) bool {
	if node == nil || moduleDeclaration == nil || moduleDeclaration.Name() == nil || moduleDeclaration.Body == nil || moduleDeclaration.Body.Kind != ast.KindModuleDeclaration {
		return false
	}
	start := moduleDeclaration.Name().End()
	end := moduleDeclaration.Body.Pos()
	sourceText := ctx.SourceFile.Text()
	if start < 0 || end < 0 || end < start || end > len(sourceText) {
		return false
	}
	return strings.Contains(sourceText[start:end], ".")
}

func isInDeclareModuleContext(node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		if current.Kind == ast.KindModuleDeclaration && utils.IncludesModifier(current, ast.KindDeclareKeyword) {
			return true
		}
	}
	return false
}

func processVariable(ctx rule.RuleContext, nameNode *ast.Node, name string, definition *ast.Node, opts Config, allUsages map[string][]*ast.Node, allWrites map[string][]*ast.Node, allValueDeclarations map[string][]*ast.Node, allTypeDeclarations map[string][]*ast.Node, exportedNames map[string]bool, forcedUsedNames map[string]bool, sourceHasJSX bool) {
	if nameNode == nil || name == "" {
		return
	}

	// Create variable info
	varInfo := &VariableInfo{
		Variable:       nameNode,
		Used:           false,
		OnlyUsedAsType: false,
		References:     []*ast.Node{},
		Definition:     definition,
	}

	// Check if this variable is used
	if usageNodes, exists := allUsages[name]; exists {
		varInfo.References = usageNodes
		moduleHasInnerShadow := definition != nil && definition.Kind == ast.KindModuleDeclaration && moduleHasInnerSameNameDeclaration(definition, name)

		// Remove self-references (the declaration itself)
		filteredUsages := []*ast.Node{}
		for _, usage := range usageNodes {
			if usage == nil {
				continue
			}
			if varInfo.Variable != nil && usage.Pos() == varInfo.Variable.Pos() {
				continue
			}
			if definition != nil && definition.Kind == ast.KindModuleDeclaration && isDescendantOf(usage, definition) {
				if moduleHasInnerShadow || !isInTypeContext(usage) {
					continue
				}
			}
			if parameterNode := parameterNodeForDefinition(definition); parameterNode != nil {
				if parameterNode.Parent == nil || !isDescendantOf(usage, parameterNode.Parent) {
					continue
				}
				bodyNode := functionLikeBodyNode(parameterNode.Parent)
				if bodyNode != nil {
					if usage != bodyNode && !isDescendantOf(usage, bodyNode) {
						continue
					}
				} else if usage.Pos() <= parameterNode.End() {
					continue
				}
			}
			if isSelfAssignmentUsage(usage, name) {
				continue
			}
			if definition != nil && definition.Kind == ast.KindFunctionDeclaration {
				functionDeclaration := definition.AsFunctionDeclaration()
				if functionDeclaration != nil && functionDeclaration.Body != nil && isDescendantOf(usage, functionDeclaration.Body) {
					continue
				}
			}
			if isTypeOnlyDefinition(definition) && usageInSameNamedTypeDeclaration(usage, definition, name) {
				continue
			}
			if isTypeOnlyDefinition(definition) && (definition == nil || definition.Kind != ast.KindModuleDeclaration) && isDescendantOf(usage, definition) {
				continue
			}
			if isImportDefinition(definition) && isUsageShadowedByTypeParameter(usage, name) {
				continue
			}
			if isUsageShadowedByValueDeclaration(usage, definition, name, allValueDeclarations) {
				continue
			}
			filteredUsages = append(filteredUsages, usage)
		}

		if len(filteredUsages) > 0 {
			if isTypeOnlyDefinition(definition) {
				varInfo.Used = true
				varInfo.OnlyUsedAsType = false
			} else {
				// Check if only used in type context
				onlyUsedAsType := true
				for _, usage := range filteredUsages {
					if !isInTypeContext(usage) {
						onlyUsedAsType = false
						break
					}
				}
				varInfo.Used = !onlyUsedAsType
				varInfo.OnlyUsedAsType = onlyUsedAsType
			}
		}
	}

	if !varInfo.Used && isTypeOnlyDefinition(definition) && (definition == nil || definition.Kind != ast.KindModuleDeclaration) && hasOtherValueDeclaration(name, definition, allValueDeclarations) {
		varInfo.Used = true
		varInfo.OnlyUsedAsType = false
	}
	if !varInfo.Used && isTypeOnlyDefinition(definition) && isTypeDeclarationMergedWithExportedNamespace(definition, name) {
		varInfo.Used = true
		varInfo.OnlyUsedAsType = false
	}
	if !varInfo.Used && isJSXPragmaImportUsed(ctx, definition, name, sourceHasJSX) {
		varInfo.Used = true
		varInfo.OnlyUsedAsType = false
	}
	if !varInfo.Used && isForInOrOfIterationVariable(definition) {
		varInfo.Used = true
		varInfo.OnlyUsedAsType = false
	}

	// Check if we should report this variable
	if shouldIgnoreVariable(name, varInfo, opts, allUsages, exportedNames, forcedUsedNames) {
		return
	}
	if ctx.SourceFile != nil && ctx.SourceFile.IsDeclarationFile && !ast.IsExternalModule(ctx.SourceFile) {
		if definition != nil && definition.Parent != nil && definition.Parent.Kind == ast.KindSourceFile {
			return
		}
	}
	if ctx.SourceFile != nil && ctx.SourceFile.IsDeclarationFile && definition != nil && hasOwnDeclareVariableModifier(definition) {
		return
	}
	if ctx.SourceFile != nil && ctx.SourceFile.IsDeclarationFile && definition != nil && definition.Kind == ast.KindVariableDeclaration {
		if isTopLevelVariableDeclaration(definition) && !sourceFileHasExportMarker(ctx.SourceFile) {
			return
		}
		enclosingModule := enclosingModuleDeclaration(definition)
		if enclosingModule != nil && !moduleDeclarationHasExportMarker(enclosingModule) {
			return
		}
	}
	if ctx.SourceFile != nil && ctx.SourceFile.IsDeclarationFile && isTypeOnlyDefinition(definition) {
		enclosingModule := enclosingModuleDeclaration(definition)
		if enclosingModule != nil {
			if !moduleDeclarationHasExportMarker(enclosingModule) {
				return
			}
		} else if !sourceFileHasExportMarker(ctx.SourceFile) {
			return
		}
	}
	if isAmbientDefinition(definition) {
		if definition != nil && hasOwnDeclareModifier(definition) && ctx.SourceFile != nil && sourceFileHasExportMarker(ctx.SourceFile) {
			// In source modules that explicitly export, declare'd values are still tracked.
		} else {
			return
		}
	}
	if definition != nil && definition.Kind == ast.KindModuleDeclaration && isInDeclareModuleContext(definition) {
		if hasOwnDeclareModifier(definition) {
			return
		}
		if moduleDeclarationHasOwnExportMarker(definition) {
			if moduleDeclarationHasDirectNestedNamespaceWithValues(definition) {
				return
			}
		} else {
			parentModule := parentModuleDeclaration(definition)
			if parentModule == nil || !moduleDeclarationHasOwnExportMarker(parentModule) || !moduleDeclarationHasValueStatements(definition) {
				return
			}
		}
		if !moduleDeclarationHasValueStatements(definition) {
			return
		}
	}

	// Skip exported variables
	if definition == nil || definition.Kind != ast.KindModuleDeclaration {
		if isExported(varInfo) {
			return
		}
	} else {
		if hasOwnExportModifier(definition) {
			return
		}
	}

	if !varInfo.Used && isTypeOnlyDefinition(definition) {
		declareModule := enclosingDeclareModule(definition)
		if declareModule != nil && !moduleDeclarationHasExportMarker(declareModule) {
			return
		}
	}

	// Report unused variables
	if varInfo.OnlyUsedAsType && opts.Vars == "all" {
		if isTypeOnlyDefinition(definition) {
			return
		}
		if isImportDefinition(definition) {
			return
		}
		if isTypeOnlyImportDefinition(definition) {
			return
		}
		// Variable is only used in type contexts
		ctx.ReportNode(varInfo.Variable, buildUsedOnlyAsTypeMessage(name))
	} else if !varInfo.Used {
		if isTypeOnlyDefinition(definition) && hasEarlierTypeDeclaration(name, definition, allTypeDeclarations) {
			return
		}
		reportNode := varInfo.Variable
		if writeNodes, ok := allWrites[name]; ok {
			for _, writeNode := range writeNodes {
				if writeNode == nil {
					continue
				}
				if reportNode == nil || writeNode.Pos() > reportNode.Pos() {
					reportNode = writeNode
				}
			}
		}
		if reportNode == nil {
			reportNode = varInfo.Variable
		}
		// Variable is not used at all
		ctx.ReportNode(reportNode, buildUnusedVarMessage(name))
	} else if varInfo.Used && opts.ReportUsedIgnorePattern {
		// Check if used but matches ignore pattern and should be reported
		if opts.VarsIgnorePattern != "" {
			if matched, _ := regexp.MatchString(opts.VarsIgnorePattern, name); matched {
				ctx.ReportNode(varInfo.Variable, buildUsedIgnoredVarMessage(name))
			}
		}
	}
}

var NoUnusedVarsRule = rule.CreateRule(rule.Rule{
	Name: "no-unused-vars",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		// We need to collect all variable usages once per source file
		allUsages := make(map[string][]*ast.Node)
		allWrites := make(map[string][]*ast.Node)
		allValueDeclarations := make(map[string][]*ast.Node)
		allTypeDeclarations := make(map[string][]*ast.Node)
		exportedNames := map[string]bool{}
		forcedUsedNames := map[string]bool{}
		globalCommentNames := map[string]bool{}
		collected := false
		sourceHasJSX := false

		// Helper function to get root source file node
		getRootSourceFile := func(node *ast.Node) *ast.Node {
			current := node
			for current.Parent != nil {
				current = current.Parent
			}
			return current
		}

		if ctx.SourceFile != nil {
			sourceText := ctx.SourceFile.Text()
			globalCommentNames = parseGlobalCommentNames(sourceText)
			if hasUseEveryAComment(sourceText) {
				forcedUsedNames["a"] = true
			}
			if len(globalCommentNames) > 0 && opts.Vars != "local" {
				commentUsages := map[string][]*ast.Node{}
				collectVariableUsages(ctx.SourceFile.AsNode(), commentUsages)
				for name := range globalCommentNames {
					if usages, ok := commentUsages[name]; ok && len(usages) > 0 {
						continue
					}
					if opts.VarsIgnorePattern != "" {
						if matched, _ := regexp.MatchString(opts.VarsIgnorePattern, name); matched {
							continue
						}
					}
					ctx.ReportRange(core.NewTextRange(0, 0), buildUnusedVarMessage(name))
				}
			}
		}

		return rule.RuleListeners{
			// Handle variable declarations
			ast.KindVariableDeclaration: func(node *ast.Node) {
				varDecl := node.AsVariableDeclaration()
				if varDecl == nil {
					return
				}
				if ast.IsIdentifier(varDecl.Name()) {
					nameNode := varDecl.Name()
					identifier := nameNode.AsIdentifier()
					if identifier == nil {
						return
					}
					name := identifier.Text

					// Collect usages for the entire source file on first variable
					if !collected {
						sourceFile := getRootSourceFile(node)
						collectVariableUsages(sourceFile, allUsages)
						collectVariableWrites(sourceFile, allWrites)
						collectValueDeclarations(sourceFile, allValueDeclarations)
						collectTypeDeclarations(sourceFile, allTypeDeclarations)
						sourceHasJSX = sourceFileHasJSX(sourceFile)
						if ctx.SourceFile != nil {
							sourceText := ctx.SourceFile.Text()
							exportedNames = parseExportedCommentNames(sourceText)
							globalCommentNames = parseGlobalCommentNames(sourceText)
							if hasUseEveryAComment(sourceText) {
								forcedUsedNames["a"] = true
							}
						}
						collected = true
					}

					processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
				}
			},

			// Handle function declarations
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				funcDecl := node.AsFunctionDeclaration()
				if funcDecl == nil {
					return
				}
				if funcDecl.Name() != nil && ast.IsIdentifier(funcDecl.Name()) {
					nameNode := funcDecl.Name()
					identifier := nameNode.AsIdentifier()
					if identifier == nil {
						return
					}
					name := identifier.Text

					// Collect usages for the entire source file on first variable
					if !collected {
						sourceFile := getRootSourceFile(node)
						collectVariableUsages(sourceFile, allUsages)
						collectVariableWrites(sourceFile, allWrites)
						collectValueDeclarations(sourceFile, allValueDeclarations)
						collectTypeDeclarations(sourceFile, allTypeDeclarations)
						sourceHasJSX = sourceFileHasJSX(sourceFile)
						if ctx.SourceFile != nil {
							sourceText := ctx.SourceFile.Text()
							exportedNames = parseExportedCommentNames(sourceText)
							globalCommentNames = parseGlobalCommentNames(sourceText)
							if hasUseEveryAComment(sourceText) {
								forcedUsedNames["a"] = true
							}
						}
						collected = true
					}

					processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
				}
			},

			// Handle function parameters
			ast.KindParameter: func(node *ast.Node) {
				paramDecl := node.AsParameterDeclaration()
				if paramDecl == nil {
					return
				}
				if paramDecl.Name() != nil && ast.IsIdentifier(paramDecl.Name()) {
					nameNode := paramDecl.Name()
					identifier := nameNode.AsIdentifier()
					if identifier == nil {
						return
					}
					name := identifier.Text

					// Collect usages for the entire source file on first variable
					if !collected {
						sourceFile := getRootSourceFile(node)
						collectVariableUsages(sourceFile, allUsages)
						collectVariableWrites(sourceFile, allWrites)
						collectValueDeclarations(sourceFile, allValueDeclarations)
						collectTypeDeclarations(sourceFile, allTypeDeclarations)
						sourceHasJSX = sourceFileHasJSX(sourceFile)
						if ctx.SourceFile != nil {
							sourceText := ctx.SourceFile.Text()
							exportedNames = parseExportedCommentNames(sourceText)
							globalCommentNames = parseGlobalCommentNames(sourceText)
							if hasUseEveryAComment(sourceText) {
								forcedUsedNames["a"] = true
							}
						}
						collected = true
					}

					processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
				}
			},

			// Handle destructured binding elements
			ast.KindBindingElement: func(node *ast.Node) {
				bindingElement := node.AsBindingElement()
				if bindingElement == nil || bindingElement.Name() == nil || !ast.IsIdentifier(bindingElement.Name()) {
					return
				}
				nameNode := bindingElement.Name()
				identifier := nameNode.AsIdentifier()
				if identifier == nil {
					return
				}
				name := identifier.Text

				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}

				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			// Handle catch clauses
			ast.KindCatchClause: func(node *ast.Node) {
				catchClause := node.AsCatchClause()
				if catchClause == nil {
					return
				}
				if catchClause.VariableDeclaration != nil && ast.IsIdentifier(catchClause.VariableDeclaration) {
					nameNode := catchClause.VariableDeclaration
					identifier := nameNode.AsIdentifier()
					if identifier == nil {
						return
					}
					name := identifier.Text

					// Collect usages for the entire source file on first variable
					if !collected {
						sourceFile := getRootSourceFile(node)
						collectVariableUsages(sourceFile, allUsages)
						collectVariableWrites(sourceFile, allWrites)
						collectValueDeclarations(sourceFile, allValueDeclarations)
						collectTypeDeclarations(sourceFile, allTypeDeclarations)
						sourceHasJSX = sourceFileHasJSX(sourceFile)
						if ctx.SourceFile != nil {
							sourceText := ctx.SourceFile.Text()
							exportedNames = parseExportedCommentNames(sourceText)
							globalCommentNames = parseGlobalCommentNames(sourceText)
							if hasUseEveryAComment(sourceText) {
								forcedUsedNames["a"] = true
							}
						}
						collected = true
					}

					processVariable(ctx, nameNode, name, nameNode, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
				}
			},

			ast.KindImportClause: func(node *ast.Node) {
				importClause := node.AsImportClause()
				if importClause == nil || importClause.Name() == nil {
					return
				}
				nameNode := importClause.Name().AsNode()
				name := importClause.Name().Text()
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindImportSpecifier: func(node *ast.Node) {
				importSpecifier := node.AsImportSpecifier()
				if importSpecifier == nil || importSpecifier.Name() == nil {
					return
				}
				nameNode := importSpecifier.Name()
				name := importSpecifier.Name().Text()
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindNamespaceImport: func(node *ast.Node) {
				namespaceImport := node.AsNamespaceImport()
				if namespaceImport == nil || namespaceImport.Name() == nil {
					return
				}
				nameNode := namespaceImport.Name().AsNode()
				name := namespaceImport.Name().Text()
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindImportEqualsDeclaration: func(node *ast.Node) {
				importEqualsDeclaration := node.AsImportEqualsDeclaration()
				if importEqualsDeclaration == nil || importEqualsDeclaration.Name() == nil {
					return
				}
				nameNode := importEqualsDeclaration.Name()
				name := importEqualsDeclaration.Name().Text()
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindEnumDeclaration: func(node *ast.Node) {
				enumDeclaration := node.AsEnumDeclaration()
				if enumDeclaration == nil || enumDeclaration.Name() == nil || enumDeclaration.Name().Kind != ast.KindIdentifier {
					return
				}
				nameNode := enumDeclaration.Name()
				name := enumDeclaration.Name().AsIdentifier().Text
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindClassDeclaration: func(node *ast.Node) {
				classDeclaration := node.AsClassDeclaration()
				if classDeclaration == nil || classDeclaration.Name() == nil || classDeclaration.Name().Kind != ast.KindIdentifier {
					return
				}
				nameNode := classDeclaration.Name()
				name := classDeclaration.Name().AsIdentifier().Text
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				interfaceDeclaration := node.AsInterfaceDeclaration()
				if interfaceDeclaration == nil || interfaceDeclaration.Name() == nil || interfaceDeclaration.Name().Kind != ast.KindIdentifier {
					return
				}
				nameNode := interfaceDeclaration.Name().AsNode()
				name := interfaceDeclaration.Name().Text()
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				typeAliasDeclaration := node.AsTypeAliasDeclaration()
				if typeAliasDeclaration == nil || typeAliasDeclaration.Name() == nil || typeAliasDeclaration.Name().Kind != ast.KindIdentifier {
					return
				}
				nameNode := typeAliasDeclaration.Name().AsNode()
				name := typeAliasDeclaration.Name().Text()
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectVariableWrites(sourceFile, allWrites)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},

			ast.KindModuleDeclaration: func(node *ast.Node) {
				moduleDeclaration := node.AsModuleDeclaration()
				if moduleDeclaration == nil || moduleDeclaration.Name() == nil || moduleDeclaration.Name().Kind != ast.KindIdentifier {
					return
				}
				if isDottedNamespaceContainer(ctx, node, moduleDeclaration) {
					return
				}
				if isDottedNamespaceContinuation(ctx, node) {
					return
				}
				nameNode := moduleDeclaration.Name()
				name := moduleDeclaration.Name().AsIdentifier().Text
				if !collected {
					sourceFile := getRootSourceFile(node)
					collectVariableUsages(sourceFile, allUsages)
					collectValueDeclarations(sourceFile, allValueDeclarations)
					collectTypeDeclarations(sourceFile, allTypeDeclarations)
					sourceHasJSX = sourceFileHasJSX(sourceFile)
					if ctx.SourceFile != nil {
						sourceText := ctx.SourceFile.Text()
						exportedNames = parseExportedCommentNames(sourceText)
						globalCommentNames = parseGlobalCommentNames(sourceText)
						if hasUseEveryAComment(sourceText) {
							forcedUsedNames["a"] = true
						}
					}
					collected = true
				}
				processVariable(ctx, nameNode, name, node, opts, allUsages, allWrites, allValueDeclarations, allTypeDeclarations, exportedNames, forcedUsedNames, sourceHasJSX)
			},
		}
	},
})
