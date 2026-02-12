package no_unused_vars

import (
	"fmt"
	"regexp"
	"sort"
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
var globalCommentRe = regexp.MustCompile(`(?is)^\s*globals?\s+(.+)$`)
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
	return assignmentTargetExpressionForNode(node) != nil
}

func isUpdateExpressionTarget(node *ast.Node) bool {
	return updateExpressionForTarget(node) != nil
}

func updateExpressionForTarget(node *ast.Node) *ast.Node {
	if node == nil || node.Parent == nil {
		return nil
	}
	switch node.Parent.Kind {
	case ast.KindPrefixUnaryExpression:
		prefixUnaryExpression := node.Parent.AsPrefixUnaryExpression()
		if prefixUnaryExpression != nil &&
			(prefixUnaryExpression.Operator == ast.KindPlusPlusToken || prefixUnaryExpression.Operator == ast.KindMinusMinusToken) &&
			isAssignmentTargetWithinLeft(node, prefixUnaryExpression.Operand) {
			return node.Parent
		}
	case ast.KindPostfixUnaryExpression:
		postfixUnaryExpression := node.Parent.AsPostfixUnaryExpression()
		if postfixUnaryExpression != nil &&
			(postfixUnaryExpression.Operator == ast.KindPlusPlusToken || postfixUnaryExpression.Operator == ast.KindMinusMinusToken) &&
			isAssignmentTargetWithinLeft(node, postfixUnaryExpression.Operand) {
			return node.Parent
		}
	default:
		return nil
	}
	return nil
}

func isUsedUpdateExpressionTarget(node *ast.Node) bool {
	updateExpression := updateExpressionForTarget(node)
	if updateExpression == nil {
		return false
	}
	return isExpressionValueConsumed(updateExpression)
}

func isExpressionValueConsumed(expression *ast.Node) bool {
	if expression == nil {
		return false
	}
	current := expression
	for parent := current.Parent; parent != nil; parent = parent.Parent {
		if parent.Kind == ast.KindParenthesizedExpression {
			current = parent
			continue
		}
		switch parent.Kind {
		case ast.KindExpressionStatement:
			return false
		case ast.KindBinaryExpression:
			binaryExpression := parent.AsBinaryExpression()
			if binaryExpression == nil || binaryExpression.OperatorToken.Kind != ast.KindCommaToken {
				return true
			}
			if binaryExpression.Left != nil && (current == binaryExpression.Left || isDescendantOf(current, binaryExpression.Left)) {
				return false
			}
			if binaryExpression.Right == nil || !(current == binaryExpression.Right || isDescendantOf(current, binaryExpression.Right)) {
				return false
			}
			current = parent
			continue
		default:
			return true
		}
	}
	return false
}

func assignmentTargetExpressionForNode(node *ast.Node) *ast.BinaryExpression {
	if node == nil {
		return nil
	}
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind != ast.KindBinaryExpression {
			continue
		}
		binaryExpression := current.AsBinaryExpression()
		if binaryExpression == nil || !isAssignmentOperator(binaryExpression.OperatorToken.Kind) || binaryExpression.Left == nil {
			continue
		}
		if isAssignmentTargetWithinLeft(node, binaryExpression.Left) {
			return binaryExpression
		}
	}
	return nil
}

func isAssignmentTargetWithinLeft(node *ast.Node, left *ast.Node) bool {
	if node == nil || left == nil {
		return false
	}
	if node == left {
		return true
	}

	for current := node; current != nil && current != left; current = current.Parent {
		parent := current.Parent
		if parent == nil {
			return false
		}
		switch parent.Kind {
		case ast.KindArrayLiteralExpression,
			ast.KindObjectLiteralExpression,
			ast.KindSpreadElement,
			ast.KindSpreadAssignment,
			ast.KindParenthesizedExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			continue
		case ast.KindPropertyAssignment:
			propertyAssignment := parent.AsPropertyAssignment()
			if propertyAssignment == nil || propertyAssignment.Initializer != current {
				return false
			}
		case ast.KindShorthandPropertyAssignment:
			shorthandPropertyAssignment := parent.AsShorthandPropertyAssignment()
			if shorthandPropertyAssignment == nil || shorthandPropertyAssignment.Name() != current {
				return false
			}
		default:
			return false
		}
	}

	return isDescendantOf(node, left)
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

func shouldIgnoreVariable(varName string, varInfo *VariableInfo, opts Config, allUsages map[string][]*ast.Node, allWrites map[string][]*ast.Node, allValueDeclarations map[string][]*ast.Node, exportedNames map[string]bool, forcedUsedNames map[string]bool) bool {
	if isCaughtError(varInfo.Definition) {
		if forcedUsedNames[varName] {
			return true
		}
		return shouldIgnoreCaughtError(varName, opts)
	}

	if forcedUsedNames[varName] {
		return true
	}
	if isIgnoredByRestSibling(varInfo.Definition, opts) {
		return true
	}
	if opts.IgnoreRestSiblings && hasObjectRestSiblingWrite(varName, allWrites) {
		return true
	}
	if opts.DestructuredArrayIgnorePattern != "" && isArrayBindingElementDefinition(varInfo.Definition) {
		if matched, _ := regexp.MatchString(opts.DestructuredArrayIgnorePattern, varName); matched {
			if !varInfo.Used || !opts.ReportUsedIgnorePattern {
				return true
			}
		}
	}
	if opts.DestructuredArrayIgnorePattern != "" && hasArrayDestructuringWrite(varName, allWrites) {
		if matched, _ := regexp.MatchString(opts.DestructuredArrayIgnorePattern, varName); matched {
			if !varInfo.Used || !opts.ReportUsedIgnorePattern {
				return true
			}
		}
	}

	// Parameter options should take precedence over varsIgnorePattern.
	if parameterNode := parameterNodeForDefinition(varInfo.Definition); parameterNode != nil {
		return shouldIgnoreParameter(varName, varInfo, varInfo.Definition, parameterNode, opts, allUsages, allValueDeclarations, forcedUsedNames)
	}

	// Check if it matches ignore patterns
	if opts.VarsIgnorePattern != "" {
		if matched, _ := regexp.MatchString(opts.VarsIgnorePattern, varName); matched {
			if !varInfo.Used || !opts.ReportUsedIgnorePattern {
				return true
			}
		}
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

func hasArrayDestructuringWrite(varName string, allWrites map[string][]*ast.Node) bool {
	for _, write := range allWrites[varName] {
		if write == nil {
			continue
		}
		assignmentExpression := assignmentTargetExpressionForNode(write)
		if assignmentExpression == nil || assignmentExpression.Left == nil {
			continue
		}
		left := unwrapAssignmentTarget(assignmentExpression.Left)
		if left != nil && left.Kind == ast.KindArrayLiteralExpression {
			return true
		}
	}
	return false
}

func hasObjectRestSiblingWrite(varName string, allWrites map[string][]*ast.Node) bool {
	for _, write := range allWrites[varName] {
		if write == nil {
			continue
		}
		assignmentExpression := assignmentTargetExpressionForNode(write)
		if assignmentExpression == nil || assignmentExpression.Left == nil {
			continue
		}
		left := unwrapAssignmentTarget(assignmentExpression.Left)
		if left == nil || left.Kind != ast.KindObjectLiteralExpression {
			continue
		}
		objectLiteralExpression := left.AsObjectLiteralExpression()
		if objectLiteralExpression == nil || objectLiteralExpression.Properties == nil {
			continue
		}
		var containingProperty *ast.Node
		for current := write.Parent; current != nil && current != left; current = current.Parent {
			if current.Parent != left {
				continue
			}
			switch current.Kind {
			case ast.KindPropertyAssignment, ast.KindShorthandPropertyAssignment:
				containingProperty = current
			}
			break
		}
		if containingProperty == nil {
			continue
		}
		seenCurrent := false
		for _, property := range objectLiteralExpression.Properties.Nodes {
			if property == nil {
				continue
			}
			if property == containingProperty {
				seenCurrent = true
				continue
			}
			if !seenCurrent {
				continue
			}
			if property.Kind == ast.KindSpreadAssignment || property.Kind == ast.KindSpreadElement {
				return true
			}
		}
	}
	return false
}

func isDestructuringAssignmentWrite(writeNode *ast.Node) bool {
	if writeNode == nil {
		return false
	}
	assignmentExpression := assignmentTargetExpressionForNode(writeNode)
	if assignmentExpression == nil || assignmentExpression.Left == nil {
		return false
	}
	left := unwrapAssignmentTarget(assignmentExpression.Left)
	if left == nil {
		return false
	}
	return left.Kind == ast.KindArrayLiteralExpression
}

func unwrapAssignmentTarget(node *ast.Node) *ast.Node {
	current := node
	for current != nil {
		switch current.Kind {
		case ast.KindParenthesizedExpression:
			parenthesizedExpression := current.AsParenthesizedExpression()
			if parenthesizedExpression == nil || parenthesizedExpression.Expression == nil {
				return current
			}
			current = parenthesizedExpression.Expression
		case ast.KindAsExpression:
			asExpression := current.AsAsExpression()
			if asExpression == nil || asExpression.Expression == nil {
				return current
			}
			current = asExpression.Expression
		case ast.KindTypeAssertionExpression:
			typeAssertionExpression := current.AsTypeAssertion()
			if typeAssertionExpression == nil || typeAssertionExpression.Expression == nil {
				return current
			}
			current = typeAssertionExpression.Expression
		case ast.KindSatisfiesExpression:
			satisfiesExpression := current.AsSatisfiesExpression()
			if satisfiesExpression == nil || satisfiesExpression.Expression == nil {
				return current
			}
			current = satisfiesExpression.Expression
		case ast.KindNonNullExpression:
			nonNullExpression := current.AsNonNullExpression()
			if nonNullExpression == nil || nonNullExpression.Expression == nil {
				return current
			}
			current = nonNullExpression.Expression
		default:
			return current
		}
	}
	return nil
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

type parameterBindingInfo struct {
	name       string
	definition *ast.Node
	nameNode   *ast.Node
}

func appendParameterBindingInfos(node *ast.Node, parameter *ast.Node, out *[]parameterBindingInfo) {
	if node == nil || out == nil {
		return
	}
	switch node.Kind {
	case ast.KindIdentifier:
		identifier := node.AsIdentifier()
		if identifier == nil || identifier.Text == "" {
			return
		}
		definition := parameter
		if node.Parent != nil && node.Parent.Kind == ast.KindBindingElement {
			definition = node.Parent
		}
		*out = append(*out, parameterBindingInfo{
			name:       identifier.Text,
			definition: definition,
			nameNode:   node,
		})
	case ast.KindBindingElement:
		bindingElement := node.AsBindingElement()
		if bindingElement != nil && bindingElement.Name() != nil {
			appendParameterBindingInfos(bindingElement.Name(), parameter, out)
		}
	case ast.KindArrayBindingPattern, ast.KindObjectBindingPattern:
		bindingPattern := node.AsBindingPattern()
		if bindingPattern == nil || bindingPattern.Elements == nil {
			return
		}
		for _, element := range bindingPattern.Elements.Nodes {
			if element == nil {
				continue
			}
			appendParameterBindingInfos(element, parameter, out)
		}
	}
}

func isParameterUsed(param *ast.Node, allUsages map[string][]*ast.Node, allValueDeclarations map[string][]*ast.Node, forcedUsedNames map[string]bool) bool {
	if param == nil {
		return false
	}
	if isParameterProperty(param) {
		return true
	}
	decl := param.AsParameterDeclaration()
	if decl == nil || decl.Name() == nil {
		return false
	}

	bindingInfos := make([]parameterBindingInfo, 0, 4)
	appendParameterBindingInfos(decl.Name(), param, &bindingInfos)
	if len(bindingInfos) == 0 {
		return false
	}

	for _, bindingInfo := range bindingInfos {
		if bindingInfo.name == "" {
			continue
		}
		if forcedUsedNames[bindingInfo.name] {
			return true
		}
		for _, usage := range allUsages[bindingInfo.name] {
			if usage == nil {
				continue
			}
			if bindingInfo.nameNode != nil && usage.Pos() == bindingInfo.nameNode.Pos() {
				continue
			}
			if isPartOfDeclaration(usage) {
				continue
			}
			if !isDescendantOf(usage, param.Parent) {
				continue
			}
			if isPartOfAssignment(usage) || isInTypeContext(usage) {
				continue
			}
			if isUsageShadowedByValueDeclaration(usage, bindingInfo.definition, bindingInfo.name, allValueDeclarations) {
				continue
			}
			return true
		}
	}
	return false
}

func shouldIgnoreParameter(varName string, varInfo *VariableInfo, definition *ast.Node, param *ast.Node, opts Config, allUsages map[string][]*ast.Node, allValueDeclarations map[string][]*ast.Node, forcedUsedNames map[string]bool) bool {
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
		if index >= 0 && (definition == nil || definition.Kind != ast.KindBindingElement) {
			lastUsedIndex := -1
			for idx, sibling := range params {
				if isParameterUsed(sibling, allUsages, allValueDeclarations, forcedUsedNames) {
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
		return forInStatement != nil && forInStatement.Initializer == variableDeclarationList && forInOrOfBodyHasOnlyReturn(forInStatement)
	case ast.KindForOfStatement:
		forOfStatement := variableDeclarationList.Parent.AsForInOrOfStatement()
		return forOfStatement != nil && forOfStatement.Initializer == variableDeclarationList && forInOrOfBodyHasOnlyReturn(forOfStatement)
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

func isWriteInNestedFunction(writeNode *ast.Node, definition *ast.Node) bool {
	if writeNode == nil || definition == nil {
		return false
	}
	definitionScope := valueDeclarationScope(definition)
	if definitionScope == nil {
		return false
	}
	for current := writeNode.Parent; current != nil; current = current.Parent {
		if current == definitionScope {
			return false
		}
		if isFunctionLikeNode(current) {
			return true
		}
	}
	return false
}

func collectVariableUsages(node *ast.Node, usages map[string][]*ast.Node) {
	if node == nil {
		return
	}

	// Visit current node
	if ast.IsIdentifier(node) && !isPartOfDeclaration(node) && isIdentifierUsageCandidate(node) {
		if isUpdateExpressionTarget(node) && !isUsedUpdateExpressionTarget(node) {
			return
		}
		if forInOrOfStatement := forInOrOfStatementForInitializerNode(node); forInOrOfStatement != nil && !forInOrOfBodyHasOnlyReturn(forInOrOfStatement) {
			return
		}
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
	if !isExpressionValueConsumed(assignmentExpression) {
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

	if node.Kind == ast.KindBinaryExpression {
		binaryExpression := node.AsBinaryExpression()
		if binaryExpression != nil && isAssignmentOperator(binaryExpression.OperatorToken.Kind) {
			collectAssignmentTargetWrites(binaryExpression.Left, writes)
		}
	}

	if ast.IsIdentifier(node) {
		identifier := node.AsIdentifier()
		if identifier == nil {
			return
		}
		name := identifier.Text
		if isPartOfDeclaration(node) && node.Parent != nil && node.Parent.Kind == ast.KindVariableDeclaration {
			variableDeclaration := node.Parent.AsVariableDeclaration()
			if variableDeclaration != nil && (variableDeclaration.Initializer != nil || isForInOrOfInitializerVariableDeclaration(node.Parent)) {
				writes[name] = append(writes[name], node)
			}
		}
		if !isPartOfDeclaration(node) && isForInOrOfInitializerNode(node) {
			writes[name] = append(writes[name], node)
		}
		if !isPartOfDeclaration(node) && isUpdateExpressionTarget(node) {
			writes[name] = append(writes[name], node)
		}
	}

	node.ForEachChild(func(child *ast.Node) bool {
		collectVariableWrites(child, writes)
		return false
	})
}

func collectAssignmentTargetWrites(target *ast.Node, writes map[string][]*ast.Node) {
	if target == nil {
		return
	}
	switch target.Kind {
	case ast.KindIdentifier:
		identifier := target.AsIdentifier()
		if identifier != nil {
			writes[identifier.Text] = append(writes[identifier.Text], target)
		}
	case ast.KindArrayLiteralExpression:
		arrayLiteralExpression := target.AsArrayLiteralExpression()
		if arrayLiteralExpression == nil || arrayLiteralExpression.Elements == nil {
			return
		}
		for _, element := range arrayLiteralExpression.Elements.Nodes {
			if element == nil {
				continue
			}
			if element.Kind == ast.KindSpreadElement {
				spreadElement := element.AsSpreadElement()
				if spreadElement != nil {
					collectAssignmentTargetWrites(spreadElement.Expression, writes)
				}
				continue
			}
			collectAssignmentTargetWrites(element, writes)
		}
	case ast.KindObjectLiteralExpression:
		objectLiteralExpression := target.AsObjectLiteralExpression()
		if objectLiteralExpression == nil || objectLiteralExpression.Properties == nil {
			return
		}
		for _, property := range objectLiteralExpression.Properties.Nodes {
			if property == nil {
				continue
			}
			switch property.Kind {
			case ast.KindPropertyAssignment:
				propertyAssignment := property.AsPropertyAssignment()
				if propertyAssignment != nil {
					collectAssignmentTargetWrites(propertyAssignment.Initializer, writes)
				}
			case ast.KindShorthandPropertyAssignment:
				shorthandPropertyAssignment := property.AsShorthandPropertyAssignment()
				if shorthandPropertyAssignment != nil && shorthandPropertyAssignment.Name() != nil {
					collectAssignmentTargetWrites(shorthandPropertyAssignment.Name(), writes)
				}
			case ast.KindSpreadAssignment:
				spreadAssignment := property.AsSpreadAssignment()
				if spreadAssignment != nil {
					collectAssignmentTargetWrites(spreadAssignment.Expression, writes)
				}
			}
		}
	case ast.KindParenthesizedExpression:
		parenthesizedExpression := target.AsParenthesizedExpression()
		if parenthesizedExpression != nil {
			collectAssignmentTargetWrites(parenthesizedExpression.Expression, writes)
		}
	case ast.KindAsExpression:
		asExpression := target.AsAsExpression()
		if asExpression != nil {
			collectAssignmentTargetWrites(asExpression.Expression, writes)
		}
	case ast.KindTypeAssertionExpression:
		typeAssertionExpression := target.AsTypeAssertion()
		if typeAssertionExpression != nil {
			collectAssignmentTargetWrites(typeAssertionExpression.Expression, writes)
		}
	case ast.KindSatisfiesExpression:
		satisfiesExpression := target.AsSatisfiesExpression()
		if satisfiesExpression != nil {
			collectAssignmentTargetWrites(satisfiesExpression.Expression, writes)
		}
	case ast.KindNonNullExpression:
		nonNullExpression := target.AsNonNullExpression()
		if nonNullExpression != nil {
			collectAssignmentTargetWrites(nonNullExpression.Expression, writes)
		}
	}
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
		if current.Kind != ast.KindBinaryExpression {
			continue
		}
		binaryExpression := current.AsBinaryExpression()
		if binaryExpression == nil || !isAssignmentOperator(binaryExpression.OperatorToken.Kind) {
			continue
		}
		if binaryExpression.Left == nil || binaryExpression.Right == nil || binaryExpression.Left.Kind != ast.KindIdentifier {
			return false
		}
		if binaryExpression.Left.AsIdentifier().Text != name {
			return false
		}
		if usage == binaryExpression.Left || !isDescendantOf(usage, binaryExpression.Right) {
			return false
		}
		if binaryExpression.OperatorToken.Kind != ast.KindEqualsToken {
			return true
		}
		if functionLikeAncestor := functionLikeAncestorWithin(usage, binaryExpression.Right); functionLikeAncestor != nil {
			right := unwrapAssignmentTarget(binaryExpression.Right)
			if right == nil {
				return false
			}
			if functionLikeAncestor.Kind == ast.KindFunctionDeclaration && functionDeclarationHasExternalReference(functionLikeAncestor, binaryExpression.Right) {
				return false
			}
			if isFunctionLikePassedAsArgument(functionLikeAncestor, binaryExpression.Right) {
				return false
			}
			if isFunctionLikeWithinCommaExpression(functionLikeAncestor, right) {
				return true
			}
			if right.Kind == ast.KindFunctionExpression || right.Kind == ast.KindArrowFunction {
				return true
			}
			if isFunctionLikeImmediatelyInvoked(functionLikeAncestor, right) {
				return true
			}
			return false
		}
		return !isConditionalOrLogicalSelfAssignmentRead(usage, binaryExpression.Right) && !isInLoopContext(current)
	}
	return false
}

func isSelfReferenceInVariableInitializer(usage *ast.Node, definition *ast.Node, name string) bool {
	if usage == nil || definition == nil || definition.Kind != ast.KindVariableDeclaration || name == "" {
		return false
	}
	variableDeclaration := definition.AsVariableDeclaration()
	if variableDeclaration == nil || variableDeclaration.Initializer == nil || variableDeclaration.Name() == nil || variableDeclaration.Name().Kind != ast.KindIdentifier {
		return false
	}
	if variableDeclaration.Name().AsIdentifier().Text != name {
		return false
	}
	initializer := variableDeclaration.Initializer
	if usage == initializer || !isDescendantOf(usage, initializer) {
		return false
	}
	functionLikeAncestor := functionLikeAncestorWithin(usage, initializer)
	if functionLikeAncestor == nil && isFunctionLikeNode(initializer) {
		functionLikeAncestor = initializer
	}
	if functionLikeAncestor == nil {
		return false
	}
	right := unwrapAssignmentTarget(initializer)
	if right == nil {
		return false
	}
	if functionLikeAncestor.Kind == ast.KindFunctionDeclaration && functionDeclarationHasExternalReference(functionLikeAncestor, initializer) {
		return false
	}
	if isFunctionLikePassedAsArgument(functionLikeAncestor, initializer) {
		return false
	}
	if isFunctionLikeWithinCommaExpression(functionLikeAncestor, right) {
		return true
	}
	if right.Kind == ast.KindFunctionExpression || right.Kind == ast.KindArrowFunction {
		return true
	}
	if isFunctionLikeImmediatelyInvoked(functionLikeAncestor, right) {
		return true
	}
	return false
}

func functionLikeAncestorWithin(node *ast.Node, stop *ast.Node) *ast.Node {
	if node == nil || stop == nil {
		return nil
	}
	for current := node.Parent; current != nil && current != stop; current = current.Parent {
		switch current.Kind {
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return current
		}
	}
	return nil
}

func isFunctionLikeNode(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration,
		ast.KindFunctionExpression,
		ast.KindArrowFunction,
		ast.KindMethodDeclaration,
		ast.KindConstructor,
		ast.KindGetAccessor,
		ast.KindSetAccessor:
		return true
	default:
		return false
	}
}

func functionDeclarationHasExternalReference(functionDeclarationNode *ast.Node, stop *ast.Node) bool {
	if functionDeclarationNode == nil || stop == nil || functionDeclarationNode.Kind != ast.KindFunctionDeclaration {
		return false
	}
	functionDeclaration := functionDeclarationNode.AsFunctionDeclaration()
	if functionDeclaration == nil || functionDeclaration.Name() == nil || functionDeclaration.Name().Kind != ast.KindIdentifier {
		return false
	}
	name := functionDeclaration.Name().AsIdentifier().Text
	if name == "" {
		return false
	}
	found := false
	var visit func(node *ast.Node)
	visit = func(node *ast.Node) {
		if node == nil || found {
			return
		}
		if node.Kind == ast.KindIdentifier {
			identifier := node.AsIdentifier()
			if identifier != nil && identifier.Text == name {
				if functionDeclaration.Name() == nil || node.Pos() != functionDeclaration.Name().Pos() {
					if !isPartOfDeclaration(node) {
						found = true
						return
					}
				}
			}
		}
		node.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return found
		})
	}
	visit(stop)
	return found
}

func isFunctionLikePassedAsArgument(functionLikeAncestor *ast.Node, right *ast.Node) bool {
	if functionLikeAncestor == nil || right == nil {
		return false
	}
	for current := functionLikeAncestor; current != nil && current != right; current = current.Parent {
		parent := current.Parent
		if parent == nil {
			return false
		}
		switch parent.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			continue
		case ast.KindCallExpression:
			callExpression := parent.AsCallExpression()
			if callExpression == nil {
				return false
			}
			if callExpression.Expression == current || isDescendantOf(current, callExpression.Expression) {
				return false
			}
			if callExpression.Arguments != nil {
				for _, argument := range callExpression.Arguments.Nodes {
					if argument == nil {
						continue
					}
					if argument == current || isDescendantOf(current, argument) {
						return true
					}
				}
			}
			return false
		case ast.KindNewExpression:
			newExpression := parent.AsNewExpression()
			if newExpression == nil {
				return false
			}
			if newExpression.Expression == current || isDescendantOf(current, newExpression.Expression) {
				return false
			}
			if newExpression.Arguments != nil {
				for _, argument := range newExpression.Arguments.Nodes {
					if argument == nil {
						continue
					}
					if argument == current || isDescendantOf(current, argument) {
						return true
					}
				}
			}
			return false
		default:
			return false
		}
	}
	return false
}

func isFunctionLikeImmediatelyInvoked(functionLikeAncestor *ast.Node, right *ast.Node) bool {
	if functionLikeAncestor == nil || right == nil {
		return false
	}
	for current := functionLikeAncestor; current != nil && current != right; current = current.Parent {
		parent := current.Parent
		if parent == nil {
			return false
		}
		switch parent.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			continue
		case ast.KindCallExpression:
			callExpression := parent.AsCallExpression()
			return callExpression != nil && callExpression.Expression != nil && (callExpression.Expression == current || isDescendantOf(current, callExpression.Expression))
		case ast.KindNewExpression:
			newExpression := parent.AsNewExpression()
			return newExpression != nil && newExpression.Expression != nil && (newExpression.Expression == current || isDescendantOf(current, newExpression.Expression))
		default:
			return false
		}
	}
	return false
}

func isFunctionLikeWithinCommaExpression(functionLikeAncestor *ast.Node, right *ast.Node) bool {
	if functionLikeAncestor == nil || right == nil {
		return false
	}
	for current := functionLikeAncestor; current != nil && current != right; current = current.Parent {
		parent := current.Parent
		if parent == nil {
			return false
		}
		switch parent.Kind {
		case ast.KindParenthesizedExpression,
			ast.KindAsExpression,
			ast.KindTypeAssertionExpression,
			ast.KindSatisfiesExpression,
			ast.KindNonNullExpression:
			continue
		case ast.KindBinaryExpression:
			binaryExpression := parent.AsBinaryExpression()
			return binaryExpression != nil && binaryExpression.OperatorToken.Kind == ast.KindCommaToken
		default:
			return false
		}
	}
	return false
}

func isConditionalOrLogicalSelfAssignmentRead(usage *ast.Node, right *ast.Node) bool {
	if usage == nil || right == nil {
		return false
	}
	for current := usage.Parent; current != nil && current != right; current = current.Parent {
		switch current.Kind {
		case ast.KindConditionalExpression:
			return true
		case ast.KindBinaryExpression:
			binaryExpression := current.AsBinaryExpression()
			if binaryExpression == nil {
				continue
			}
			switch binaryExpression.OperatorToken.Kind {
			case ast.KindBarBarToken, ast.KindAmpersandAmpersandToken, ast.KindQuestionQuestionToken:
				return true
			}
		}
	}
	return false
}

func isInLoopContext(node *ast.Node) bool {
	if node == nil {
		return false
	}
	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindForStatement,
			ast.KindForInStatement,
			ast.KindForOfStatement,
			ast.KindWhileStatement,
			ast.KindDoStatement:
			return true
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return false
		}
	}
	return false
}

func forInOrOfStatementForInitializerNode(node *ast.Node) *ast.ForInOrOfStatement {
	if node == nil {
		return nil
	}
	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindForInStatement, ast.KindForOfStatement:
			forInOrOfStatement := current.AsForInOrOfStatement()
			if forInOrOfStatement == nil || forInOrOfStatement.Initializer == nil {
				return nil
			}
			if node == forInOrOfStatement.Initializer || isDescendantOf(node, forInOrOfStatement.Initializer) {
				return forInOrOfStatement
			}
			return nil
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindArrowFunction,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return nil
		}
	}
	return nil
}

func isForInOrOfInitializerNode(node *ast.Node) bool {
	return forInOrOfStatementForInitializerNode(node) != nil
}

func isForInOrOfInitializerVariableDeclaration(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindVariableDeclaration || node.Parent == nil || node.Parent.Kind != ast.KindVariableDeclarationList || node.Parent.Parent == nil {
		return false
	}
	switch node.Parent.Parent.Kind {
	case ast.KindForInStatement, ast.KindForOfStatement:
		forInOrOfStatement := node.Parent.Parent.AsForInOrOfStatement()
		return forInOrOfStatement != nil && forInOrOfStatement.Initializer == node.Parent
	default:
		return false
	}
}

func forInOrOfBodyHasOnlyReturn(statement *ast.ForInOrOfStatement) bool {
	if statement == nil || statement.Statement == nil {
		return false
	}
	if statement.Statement.Kind == ast.KindReturnStatement {
		return true
	}
	if statement.Statement.Kind != ast.KindBlock {
		return false
	}
	block := statement.Statement.AsBlock()
	if block == nil || block.Statements == nil || len(block.Statements.Nodes) != 1 {
		return false
	}
	return block.Statements.Nodes[0] != nil && block.Statements.Nodes[0].Kind == ast.KindReturnStatement
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
	for name := range parseGlobalCommentRanges(sourceText) {
		names[name] = true
	}
	return names
}

func parseGlobalCommentRanges(sourceText string) map[string]core.TextRange {
	ranges := map[string]core.TextRange{}
	if sourceText == "" {
		return ranges
	}

	addRanges := func(commentBody string, commentBodyStart int) {
		matchIndexes := globalCommentRe.FindStringSubmatchIndex(commentBody)
		if len(matchIndexes) < 4 {
			return
		}
		searchStart := matchIndexes[2]
		if searchStart >= len(commentBody) {
			return
		}
		rest := commentBody[searchStart:]
		for idx := 0; idx < len(rest); {
			for idx < len(rest) && isGlobalDirectiveDelimiter(rest[idx]) {
				idx++
			}
			if idx >= len(rest) {
				break
			}
			tokenStart := idx
			for idx < len(rest) && !isGlobalDirectiveDelimiter(rest[idx]) && rest[idx] != ':' {
				idx++
			}
			tokenEnd := idx
			if tokenEnd > tokenStart {
				start := searchStart + tokenStart
				end := searchStart + tokenEnd
				name := commentBody[start:end]
				absoluteStart := commentBodyStart + start
				absoluteEnd := commentBodyStart + end
				if absoluteStart >= 0 && absoluteEnd > absoluteStart && absoluteEnd <= len(sourceText) {
					if _, exists := ranges[name]; !exists {
						ranges[name] = core.NewTextRange(absoluteStart, absoluteEnd)
					}
				}
			}
			if idx < len(rest) && rest[idx] == ':' {
				idx++
				for idx < len(rest) && !isGlobalDirectiveDelimiter(rest[idx]) {
					idx++
				}
			}
		}
	}

	for i := 0; i < len(sourceText)-1; i++ {
		if sourceText[i] != '/' {
			continue
		}
		if sourceText[i+1] == '/' {
			commentBodyStart := i + 2
			j := commentBodyStart
			for j < len(sourceText) && sourceText[j] != '\n' && sourceText[j] != '\r' {
				j++
			}
			addRanges(sourceText[commentBodyStart:j], commentBodyStart)
			i = j
			continue
		}
		if sourceText[i+1] == '*' {
			commentBodyStart := i + 2
			j := commentBodyStart
			for j+1 < len(sourceText) && (sourceText[j] != '*' || sourceText[j+1] != '/') {
				j++
			}
			if j+1 >= len(sourceText) {
				break
			}
			addRanges(sourceText[commentBodyStart:j], commentBodyStart)
			i = j + 1
		}
	}

	return ranges
}

func isGlobalDirectiveDelimiter(ch byte) bool {
	switch ch {
	case ' ', '\t', '\r', '\n', ',', '*':
		return true
	default:
		return false
	}
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

func classDeclarationHasStaticBlock(ctx rule.RuleContext, definition *ast.Node) bool {
	if ctx.SourceFile == nil || definition == nil || definition.Kind != ast.KindClassDeclaration {
		return false
	}
	sourceText := ctx.SourceFile.Text()
	start := definition.Pos()
	end := definition.End()
	if start < 0 || end <= start || end > len(sourceText) {
		return false
	}
	return strings.Contains(sourceText[start:end], "static {")
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
			if isSelfReferenceInVariableInitializer(usage, definition, name) {
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
	if !varInfo.Used && classDeclarationHasStaticBlock(ctx, definition) {
		varInfo.Used = true
		varInfo.OnlyUsedAsType = false
	}

	// Check if we should report this variable
	if shouldIgnoreVariable(name, varInfo, opts, allUsages, allWrites, allValueDeclarations, exportedNames, forcedUsedNames) {
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
			hasNonDestructuringWrite := false
			for _, writeNode := range writeNodes {
				if writeNode == nil || isDestructuringAssignmentWrite(writeNode) {
					continue
				}
				hasNonDestructuringWrite = true
				break
			}
			hasNonNestedFunctionWrite := false
			for _, writeNode := range writeNodes {
				if writeNode == nil {
					continue
				}
				if !hasNonDestructuringWrite && isDestructuringAssignmentWrite(writeNode) {
					continue
				}
				if !isWriteInNestedFunction(writeNode, definition) {
					hasNonNestedFunctionWrite = true
					break
				}
			}
			for _, writeNode := range writeNodes {
				if writeNode == nil {
					continue
				}
				if !hasNonDestructuringWrite && isDestructuringAssignmentWrite(writeNode) {
					continue
				}
				if hasNonNestedFunctionWrite && isWriteInNestedFunction(writeNode, definition) {
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
		globalCommentRanges := map[string]core.TextRange{}
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
			globalCommentRanges = parseGlobalCommentRanges(sourceText)
			if hasUseEveryAComment(sourceText) {
				forcedUsedNames["a"] = true
			}
			if len(globalCommentNames) > 0 && opts.Vars != "local" {
				commentUsages := map[string][]*ast.Node{}
				collectVariableUsages(ctx.SourceFile.AsNode(), commentUsages)
				globalNames := make([]string, 0, len(globalCommentNames))
				for name := range globalCommentNames {
					globalNames = append(globalNames, name)
				}
				sort.Slice(globalNames, func(i, j int) bool {
					rangeI, okI := globalCommentRanges[globalNames[i]]
					rangeJ, okJ := globalCommentRanges[globalNames[j]]
					if okI && okJ {
						if rangeI.Pos() == rangeJ.Pos() {
							return globalNames[i] < globalNames[j]
						}
						return rangeI.Pos() < rangeJ.Pos()
					}
					if okI {
						return true
					}
					if okJ {
						return false
					}
					return globalNames[i] < globalNames[j]
				})
				for _, name := range globalNames {
					if usages, ok := commentUsages[name]; ok && len(usages) > 0 {
						continue
					}
					if opts.VarsIgnorePattern != "" {
						if matched, _ := regexp.MatchString(opts.VarsIgnorePattern, name); matched {
							continue
						}
					}
					reportRange, hasRange := globalCommentRanges[name]
					if hasRange {
						ctx.ReportRange(reportRange, buildUnusedVarMessage(name))
					} else {
						ctx.ReportRange(core.NewTextRange(0, 0), buildUnusedVarMessage(name))
					}
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
