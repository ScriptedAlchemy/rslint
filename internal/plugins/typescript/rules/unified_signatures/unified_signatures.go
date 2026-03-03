package unified_signatures

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type UnifiedSignaturesOptions struct {
	IgnoreDifferentlyNamedParameters  bool `json:"ignoreDifferentlyNamedParameters"`
	IgnoreOverloadsWithDifferentJSDoc bool `json:"ignoreOverloadsWithDifferentJSDoc"`
}

type unifyKind string

const (
	unifyKindSingleParameterDifference unifyKind = "single-parameter-difference"
	unifyKindExtraParameter            unifyKind = "extra-parameter"
)

type unifyResult struct {
	kind unifyKind

	p0 *ast.Node
	p1 *ast.Node

	extraParameter *ast.Node
	otherSignature *ast.Node
}

type failure struct {
	only2 bool
	unify unifyResult
}

var (
	messageSingleParameterDifference = rule.RuleMessage{
		Id:          "singleParameterDifference",
		Description: "These overloads can be combined into one signature taking a union parameter.",
	}
	messageOmittingSingleParameter = rule.RuleMessage{
		Id:          "omittingSingleParameter",
		Description: "These overloads can be combined into one signature with an optional parameter.",
	}
	messageOmittingRestParameter = rule.RuleMessage{
		Id:          "omittingRestParameter",
		Description: "These overloads can be combined into one signature with a rest parameter.",
	}
)

func parseOptions(options any) UnifiedSignaturesOptions {
	opts := UnifiedSignaturesOptions{
		IgnoreDifferentlyNamedParameters:  false,
		IgnoreOverloadsWithDifferentJSDoc: false,
	}
	if options == nil {
		return opts
	}

	raw := options
	if arr, ok := options.([]interface{}); ok {
		if len(arr) == 0 {
			return opts
		}
		raw = arr[0]
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return opts
	}
	_ = json.Unmarshal(encoded, &opts)
	return opts
}

func getScopeMembers(node *ast.Node) []*ast.Node {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case ast.KindSourceFile:
		source := node.AsSourceFile()
		if source == nil || source.Statements == nil {
			return nil
		}
		return source.Statements.Nodes
	case ast.KindModuleBlock:
		moduleBlock := node.AsModuleBlock()
		if moduleBlock == nil || moduleBlock.Statements == nil {
			return nil
		}
		return moduleBlock.Statements.Nodes
	case ast.KindClassDeclaration:
		classDecl := node.AsClassDeclaration()
		if classDecl == nil || classDecl.Members == nil {
			return nil
		}
		return classDecl.Members.Nodes
	case ast.KindClassExpression:
		classExpr := node.AsClassExpression()
		if classExpr == nil || classExpr.Members == nil {
			return nil
		}
		return classExpr.Members.Nodes
	case ast.KindInterfaceDeclaration:
		interfaceDecl := node.AsInterfaceDeclaration()
		if interfaceDecl == nil || interfaceDecl.Members == nil {
			return nil
		}
		return interfaceDecl.Members.Nodes
	case ast.KindTypeLiteral:
		typeLiteral := node.AsTypeLiteralNode()
		if typeLiteral == nil || typeLiteral.Members == nil {
			return nil
		}
		return typeLiteral.Members.Nodes
	default:
		return nil
	}
}

func scopeTypeParameterNames(node *ast.Node) map[string]struct{} {
	result := map[string]struct{}{}
	if node == nil {
		return result
	}

	switch node.Kind {
	case ast.KindClassDeclaration, ast.KindClassExpression, ast.KindInterfaceDeclaration:
		for _, typeParameter := range node.TypeParameters() {
			if typeParameter == nil || typeParameter.Kind != ast.KindTypeParameter {
				continue
			}
			typeParam := typeParameter.AsTypeParameter()
			if typeParam == nil || typeParam.Name() == nil || typeParam.Name().Kind != ast.KindIdentifier {
				continue
			}
			result[typeParam.Name().AsIdentifier().Text] = struct{}{}
		}
	}

	return result
}

func canBeOverloadInScope(scopeNode *ast.Node, node *ast.Node) bool {
	if scopeNode == nil || node == nil {
		return false
	}

	switch scopeNode.Kind {
	case ast.KindSourceFile, ast.KindModuleBlock:
		if node.Kind != ast.KindFunctionDeclaration {
			return false
		}
		return node.Body() == nil
	case ast.KindClassDeclaration, ast.KindClassExpression:
		switch node.Kind {
		case ast.KindMethodDeclaration:
			return node.Body() == nil
		case ast.KindConstructor:
			return node.Body() == nil
		default:
			return false
		}
	case ast.KindInterfaceDeclaration, ast.KindTypeLiteral:
		return node.Kind == ast.KindMethodSignature ||
			node.Kind == ast.KindCallSignature ||
			node.Kind == ast.KindConstructSignature
	default:
		return false
	}
}

func functionOverloadInfo(node *ast.Node) string {
	functionDecl := node.AsFunctionDeclaration()
	if functionDecl == nil {
		return ""
	}
	if functionDecl.Name() != nil {
		return functionDecl.Name().Text()
	}
	if ast.GetCombinedModifierFlags(node)&ast.ModifierFlagsDefault != 0 {
		return "default"
	}
	return "__anonymous__"
}

func overloadInfo(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}

	switch node.Kind {
	case ast.KindFunctionDeclaration:
		return functionOverloadInfo(node)
	case ast.KindConstructor, ast.KindConstructSignature:
		return "constructor"
	case ast.KindCallSignature:
		return "()"
	case ast.KindMethodDeclaration:
		method := node.AsMethodDeclaration()
		if method == nil || method.Name() == nil {
			return ""
		}
		name, nameType := utils.GetNameFromMember(ctx.SourceFile, method.Name())
		return fmt.Sprintf("%d:%s", nameType, name)
	case ast.KindMethodSignature:
		methodSignature := node.AsMethodSignatureDeclaration()
		if methodSignature == nil || methodSignature.Name() == nil {
			return ""
		}
		name, nameType := utils.GetNameFromMember(ctx.SourceFile, methodSignature.Name())
		return fmt.Sprintf("%d:%s", nameType, name)
	default:
		return ""
	}
}

func overloadKey(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}

	computedKey := "1"
	staticKey := "1"

	if (node.Kind == ast.KindMethodDeclaration || node.Kind == ast.KindMethodSignature) && node.Name() != nil {
		if node.Name().Kind == ast.KindComputedPropertyName {
			computedKey = "0"
		}
	}
	if ast.IsStatic(node) {
		staticKey = "0"
	}

	return computedKey + staticKey + ":" + overloadInfo(ctx, node)
}

func trimNodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	textRange := utils.TrimNodeTextRange(sourceFile, node)
	start := textRange.Pos()
	end := textRange.End()
	source := sourceFile.Text()
	if start < 0 || end > len(source) || start >= end {
		return ""
	}
	return source[start:end]
}

func typesAreEqual(sourceFile *ast.SourceFile, a *ast.Node, b *ast.Node) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return trimNodeText(sourceFile, a) == trimNodeText(sourceFile, b)
}

func constraintsAreEqual(a *ast.Node, b *ast.Node) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Kind == b.Kind
}

func typeParametersAreEqual(a *ast.Node, b *ast.Node) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Kind != ast.KindTypeParameter || b.Kind != ast.KindTypeParameter {
		return false
	}

	aTypeParam := a.AsTypeParameter()
	bTypeParam := b.AsTypeParameter()
	if aTypeParam == nil || bTypeParam == nil || aTypeParam.Name() == nil || bTypeParam.Name() == nil {
		return false
	}
	if aTypeParam.Name().Kind != ast.KindIdentifier || bTypeParam.Name().Kind != ast.KindIdentifier {
		return false
	}

	return aTypeParam.Name().AsIdentifier().Text == bTypeParam.Name().AsIdentifier().Text &&
		constraintsAreEqual(aTypeParam.Constraint, bTypeParam.Constraint)
}

func typeParameterListsAreEqual(a []*ast.Node, b []*ast.Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !typeParametersAreEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func parameterIsRest(param *ast.Node) bool {
	if param == nil || param.Kind != ast.KindParameter {
		return false
	}
	parameterDeclaration := param.AsParameterDeclaration()
	return parameterDeclaration != nil && parameterDeclaration.DotDotDotToken != nil
}

func parameterIsOptional(param *ast.Node) bool {
	if param == nil || param.Kind != ast.KindParameter {
		return false
	}
	parameterDeclaration := param.AsParameterDeclaration()
	return parameterDeclaration != nil && parameterDeclaration.QuestionToken != nil
}

func parameterMayBeMissing(param *ast.Node) bool {
	return parameterIsRest(param) || parameterIsOptional(param)
}

func parametersHaveEqualSigils(a *ast.Node, b *ast.Node) bool {
	return parameterIsRest(a) == parameterIsRest(b) &&
		parameterIsOptional(a) == parameterIsOptional(b)
}

func staticParameterName(param *ast.Node) string {
	if param == nil || param.Kind != ast.KindParameter {
		return ""
	}
	parameterDeclaration := param.AsParameterDeclaration()
	if parameterDeclaration == nil || parameterDeclaration.Name() == nil {
		return ""
	}
	if parameterDeclaration.Name().Kind == ast.KindIdentifier {
		return parameterDeclaration.Name().AsIdentifier().Text
	}
	return ""
}

func isThisParam(param *ast.Node) bool {
	if param == nil || param.Kind != ast.KindParameter {
		return false
	}
	parameterDeclaration := param.AsParameterDeclaration()
	if parameterDeclaration == nil || parameterDeclaration.Name() == nil {
		return false
	}
	return parameterDeclaration.Name().Kind == ast.KindIdentifier &&
		parameterDeclaration.Name().AsIdentifier().Text == "this"
}

func isThisVoidParam(param *ast.Node) bool {
	if !isThisParam(param) {
		return false
	}
	return param.Type() != nil && param.Type().Kind == ast.KindVoidKeyword
}

func parametersAreEqual(sourceFile *ast.SourceFile, a *ast.Node, b *ast.Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	return parametersHaveEqualSigils(a, b) &&
		typesAreEqual(sourceFile, a.Type(), b.Type())
}

func indexOfFirstParameterDifference(sourceFile *ast.SourceFile, a []*ast.Node, b []*ast.Node) (int, bool) {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := range limit {
		if !parametersAreEqual(sourceFile, a[i], b[i]) {
			return i, true
		}
	}
	return -1, false
}

func isIdentifierTypeName(node *ast.Node, typeParameterNames map[string]struct{}) bool {
	if node == nil {
		return false
	}
	if node.Kind != ast.KindIdentifier {
		return false
	}
	_, ok := typeParameterNames[node.AsIdentifier().Text]
	return ok
}

func typeContainsTypeParameter(typeNode *ast.Node, typeParameterNames map[string]struct{}) bool {
	if typeNode == nil || len(typeParameterNames) == 0 {
		return false
	}
	if typeNode.Kind == ast.KindTypeReference {
		typeReference := typeNode.AsTypeReferenceNode()
		if typeReference != nil && typeReference.TypeName != nil && isIdentifierTypeName(typeReference.TypeName, typeParameterNames) {
			return true
		}
	}

	found := false
	typeNode.ForEachChild(func(child *ast.Node) bool {
		if typeContainsTypeParameter(child, typeParameterNames) {
			found = true
			return true
		}
		return false
	})
	return found
}

func signatureUsesTypeParameter(signature *ast.Node, typeParameterNames map[string]struct{}) bool {
	if signature == nil || len(typeParameterNames) == 0 {
		return false
	}
	for _, parameter := range signature.Parameters() {
		if parameter == nil {
			continue
		}
		if typeContainsTypeParameter(parameter.Type(), typeParameterNames) {
			return true
		}
	}
	return false
}

func leadingBlockComment(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}

	sourceText := sourceFile.Text()
	tokenPos := utils.TrimNodeTextRange(sourceFile, node).Pos()
	if tokenPos <= 0 || tokenPos > len(sourceText) {
		return ""
	}
	prefix := sourceText[:tokenPos]

	commentEnd := strings.LastIndex(prefix, "*/")
	if commentEnd < 0 {
		return ""
	}
	commentEnd += 2
	commentStart := strings.LastIndex(prefix[:commentEnd-2], "/*")
	if commentStart < 0 || commentStart >= commentEnd {
		return ""
	}

	if hasCodeBetween(sourceText, commentEnd, tokenPos) {
		return ""
	}

	return strings.TrimSpace(sourceText[commentStart:commentEnd])
}

func hasCodeBetween(sourceText string, start int, end int) bool {
	if start < 0 {
		start = 0
	}
	if end > len(sourceText) {
		end = len(sourceText)
	}
	if start >= end {
		return false
	}

	i := start
	for i < end {
		ch := sourceText[i]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}

		if ch == '/' && i+1 < end {
			next := sourceText[i+1]
			if next == '/' {
				i += 2
				for i < end && sourceText[i] != '\n' {
					i++
				}
				continue
			}
			if next == '*' {
				i += 2
				for i+1 < end && (sourceText[i] != '*' || sourceText[i+1] != '/') {
					i++
				}
				if i+1 < end {
					i += 2
				}
				continue
			}
		}

		return true
	}

	return false
}

func signaturesCanBeUnified(
	ctx rule.RuleContext,
	options UnifiedSignaturesOptions,
	a *ast.Node,
	b *ast.Node,
	scopeTypeParameters map[string]struct{},
) bool {
	if a == nil || b == nil {
		return false
	}

	aParams := a.Parameters()
	bParams := b.Parameters()

	if options.IgnoreDifferentlyNamedParameters {
		commonLength := len(aParams)
		if len(bParams) < commonLength {
			commonLength = len(bParams)
		}
		for i := range commonLength {
			if staticParameterName(aParams[i]) != staticParameterName(bParams[i]) {
				return false
			}
		}
	}

	if options.IgnoreOverloadsWithDifferentJSDoc {
		if leadingBlockComment(ctx.SourceFile, a) != leadingBlockComment(ctx.SourceFile, b) {
			return false
		}
	}

	if !typesAreEqual(ctx.SourceFile, a.Type(), b.Type()) {
		return false
	}
	if !typeParameterListsAreEqual(a.TypeParameters(), b.TypeParameters()) {
		return false
	}

	return signatureUsesTypeParameter(a, scopeTypeParameters) == signatureUsesTypeParameter(b, scopeTypeParameters)
}

func signaturesDifferBySingleParameter(ctx rule.RuleContext, a *ast.Node, b *ast.Node) *unifyResult {
	aParams := a.Parameters()
	bParams := b.Parameters()

	if len(aParams) == 0 || len(bParams) == 0 {
		return nil
	}

	if isThisVoidParam(aParams[0]) || isThisVoidParam(bParams[0]) {
		return nil
	}

	index, found := indexOfFirstParameterDifference(ctx.SourceFile, aParams, bParams)
	if !found {
		return nil
	}

	for i := index + 1; i < len(aParams) && i < len(bParams); i++ {
		if !parametersAreEqual(ctx.SourceFile, aParams[i], bParams[i]) {
			return nil
		}
	}

	paramA := aParams[index]
	paramB := bParams[index]
	if !parametersHaveEqualSigils(paramA, paramB) || parameterIsRest(paramA) {
		return nil
	}

	return &unifyResult{
		kind: unifyKindSingleParameterDifference,
		p0:   paramA,
		p1:   paramB,
	}
}

func signaturesDifferByOptionalOrRestParameter(ctx rule.RuleContext, a *ast.Node, b *ast.Node) *unifyResult {
	sig1 := a.Parameters()
	sig2 := b.Parameters()

	if len(sig1) == 0 && len(sig2) == 0 {
		return nil
	}

	minLength := len(sig1)
	if len(sig2) < minLength {
		minLength = len(sig2)
	}

	longer := sig1
	shorter := sig2
	shorterSig := b
	if len(sig1) < len(sig2) {
		longer = sig2
		shorter = sig1
		shorterSig = a
	}

	var firstParam1 *ast.Node
	if len(sig1) > 0 {
		firstParam1 = sig1[0]
	}
	var firstParam2 *ast.Node
	if len(sig2) > 0 {
		firstParam2 = sig2[0]
	}

	if isThisParam(firstParam1) != isThisParam(firstParam2) {
		return nil
	}
	if isThisVoidParam(firstParam1) || isThisVoidParam(firstParam2) {
		return nil
	}

	for i := minLength + 1; i < len(longer); i++ {
		if !parameterMayBeMissing(longer[i]) {
			return nil
		}
	}

	for i := range minLength {
		if !typesAreEqual(ctx.SourceFile, sig1[i].Type(), sig2[i].Type()) {
			return nil
		}
	}

	if minLength > 0 && parameterIsRest(shorter[minLength-1]) {
		return nil
	}

	if len(longer) == 0 {
		return nil
	}

	return &unifyResult{
		kind:           unifyKindExtraParameter,
		extraParameter: longer[len(longer)-1],
		otherSignature: shorterSig,
	}
}

func compareSignatures(
	ctx rule.RuleContext,
	options UnifiedSignaturesOptions,
	a *ast.Node,
	b *ast.Node,
	scopeTypeParameters map[string]struct{},
) *unifyResult {
	if !signaturesCanBeUnified(ctx, options, a, b, scopeTypeParameters) {
		return nil
	}

	if len(a.Parameters()) == len(b.Parameters()) {
		return signaturesDifferBySingleParameter(ctx, a, b)
	}
	return signaturesDifferByOptionalOrRestParameter(ctx, a, b)
}

func checkOverloads(
	ctx rule.RuleContext,
	options UnifiedSignaturesOptions,
	signatures []*ast.Node,
	scopeTypeParameters map[string]struct{},
) []failure {
	failures := []failure{}
	for i := range signatures {
		for j := i + 1; j < len(signatures); j++ {
			unify := compareSignatures(ctx, options, signatures[i], signatures[j], scopeTypeParameters)
			if unify == nil {
				continue
			}
			failures = append(failures, failure{
				only2: len(signatures) == 2,
				unify: *unify,
			})
		}
	}
	return failures
}

func addFailures(ctx rule.RuleContext, failures []failure) {
	for _, failure := range failures {
		switch failure.unify.kind {
		case unifyKindSingleParameterDifference:
			if failure.unify.p1 != nil {
				ctx.ReportNode(failure.unify.p1, messageSingleParameterDifference)
			}
		case unifyKindExtraParameter:
			if failure.unify.extraParameter == nil {
				continue
			}
			if parameterIsRest(failure.unify.extraParameter) {
				ctx.ReportNode(failure.unify.extraParameter, messageOmittingRestParameter)
			} else {
				ctx.ReportNode(failure.unify.extraParameter, messageOmittingSingleParameter)
			}
		}
	}
}

func analyzeScope(ctx rule.RuleContext, options UnifiedSignaturesOptions, scopeNode *ast.Node) {
	if scopeNode == nil {
		return
	}

	members := getScopeMembers(scopeNode)
	if len(members) == 0 {
		return
	}

	scopeTypeParameters := scopeTypeParameterNames(scopeNode)
	overloads := map[string][]*ast.Node{}

	for _, member := range members {
		if member == nil || !canBeOverloadInScope(scopeNode, member) {
			continue
		}
		key := overloadKey(ctx, member)
		if key == "" {
			continue
		}
		overloads[key] = append(overloads[key], member)
	}

	for _, signatureGroup := range overloads {
		failures := checkOverloads(ctx, options, signatureGroup, scopeTypeParameters)
		addFailures(ctx, failures)
	}
}

func walkAndAnalyzeScopes(ctx rule.RuleContext, options UnifiedSignaturesOptions, node *ast.Node) {
	if node == nil {
		return
	}

	switch node.Kind {
	case ast.KindSourceFile,
		ast.KindModuleBlock,
		ast.KindClassDeclaration,
		ast.KindClassExpression,
		ast.KindInterfaceDeclaration,
		ast.KindTypeLiteral:
		analyzeScope(ctx, options, node)
	}

	node.ForEachChild(func(child *ast.Node) bool {
		walkAndAnalyzeScopes(ctx, options, child)
		return false
	})
}

var UnifiedSignaturesRule = rule.CreateRule(rule.Rule{
	Name: "unified-signatures",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		walkAndAnalyzeScopes(ctx, opts, &ctx.SourceFile.Node)
		return rule.RuleListeners{}
	},
})
