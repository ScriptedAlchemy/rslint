package no_redeclare

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type declarationKind string

const (
	declarationVariable          declarationKind = "variable"
	declarationFunction          declarationKind = "function"
	declarationFunctionSignature declarationKind = "function-signature"
	declarationClass             declarationKind = "class"
	declarationInterface         declarationKind = "interface"
	declarationTypeAlias         declarationKind = "type-alias"
	declarationEnum              declarationKind = "enum"
	declarationModule            declarationKind = "module"
	declarationBuiltin           declarationKind = "builtin"
	declarationComment           declarationKind = "comment"
)

var builtinGlobals = map[string]bool{
	"Object":     true,
	"NodeListOf": true,
}

type declarationInfo struct {
	name       string
	kind       declarationKind
	reportNode *ast.Node
}

type scope struct {
	decls map[string][]declarationInfo
}

func newScope() *scope {
	return &scope{decls: map[string][]declarationInfo{}}
}

type noRedeclareOptions struct {
	BuiltinGlobals         bool `json:"builtinGlobals"`
	IgnoreDeclarationMerge bool `json:"ignoreDeclarationMerge"`
}

func parseOptions(options any) noRedeclareOptions {
	opts := noRedeclareOptions{
		BuiltinGlobals:         true,
		IgnoreDeclarationMerge: true,
	}
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
	if v, ok := optsMap["builtinGlobals"].(bool); ok {
		opts.BuiltinGlobals = v
	}
	if v, ok := optsMap["ignoreDeclarationMerge"].(bool); ok {
		opts.IgnoreDeclarationMerge = v
	}
	return opts
}

func buildRedeclaredMessage(name, messageID string) rule.RuleMessage {
	description := "'" + name + "' is already defined."
	switch messageID {
	case "redeclaredAsBuiltin":
		description = "'" + name + "' is already defined as a built-in global variable."
	case "redeclaredBySyntax":
		description = "'" + name + "' is already defined by a variable declaration."
	}
	return rule.RuleMessage{
		Id:          messageID,
		Description: description,
	}
}

func isVarDeclaration(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindVariableDeclaration || node.Parent == nil || node.Parent.Kind != ast.KindVariableDeclarationList {
		return false
	}
	return node.Parent.AsVariableDeclarationList().Flags&ast.NodeFlagsBlockScoped == 0
}

func isScopeKind(kind ast.Kind) bool {
	switch kind {
	case ast.KindSourceFile, ast.KindBlock, ast.KindModuleBlock, ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindConstructor, ast.KindMethodDeclaration:
		return true
	}
	return false
}

func nearestScopeNode(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if isScopeKind(current.Kind) {
			return current
		}
	}
	return nil
}

func nearestVarScopeNode(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindSourceFile, ast.KindModuleBlock, ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction, ast.KindConstructor, ast.KindMethodDeclaration:
			return current
		}
	}
	return nil
}

func declarationScopeNode(declaration *ast.Node) *ast.Node {
	if declaration == nil {
		return nil
	}
	if declaration.Kind == ast.KindVariableDeclaration && isVarDeclaration(declaration) {
		return nearestVarScopeNode(declaration.Parent)
	}
	return nearestScopeNode(declaration.Parent)
}

func declarationNameNodeText(node *ast.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	switch node.Kind {
	case ast.KindIdentifier:
		return node.AsIdentifier().Text, true
	case ast.KindStringLiteral:
		return node.AsStringLiteral().Text, true
	case ast.KindNoSubstitutionTemplateLiteral:
		return node.AsNoSubstitutionTemplateLiteral().Text, true
	default:
		return "", false
	}
}

func collectBindingNameNodes(node *ast.Node, out *[]*ast.Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case ast.KindIdentifier:
		*out = append(*out, node)
	case ast.KindBindingElement:
		elem := node.AsBindingElement()
		if elem != nil {
			collectBindingNameNodes(elem.Name(), out)
		}
	case ast.KindArrayBindingPattern, ast.KindObjectBindingPattern:
		pattern := node.AsBindingPattern()
		if pattern == nil || pattern.Elements == nil {
			return
		}
		for _, element := range pattern.Elements.Nodes {
			if element == nil {
				continue
			}
			collectBindingNameNodes(element, out)
		}
	}
}

func declarationInfos(node *ast.Node) []declarationInfo {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		decl := node.AsVariableDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		nameNodes := []*ast.Node{}
		collectBindingNameNodes(decl.Name(), &nameNodes)
		result := make([]declarationInfo, 0, len(nameNodes))
		for _, nameNode := range nameNodes {
			if name, ok := declarationNameNodeText(nameNode); ok {
				result = append(result, declarationInfo{name: name, kind: declarationVariable, reportNode: nameNode})
			}
		}
		return result
	case ast.KindFunctionDeclaration:
		decl := node.AsFunctionDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		nameNode := decl.Name()
		if nameNode == nil {
			return nil
		}
		kind := declarationFunction
		if decl.Body == nil {
			kind = declarationFunctionSignature
		}
		return []declarationInfo{{name: nameNode.Text(), kind: kind, reportNode: nameNode.AsNode()}}
	case ast.KindClassDeclaration:
		decl := node.AsClassDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		return []declarationInfo{{name: decl.Name().Text(), kind: declarationClass, reportNode: decl.Name().AsNode()}}
	case ast.KindInterfaceDeclaration:
		decl := node.AsInterfaceDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		return []declarationInfo{{name: decl.Name().Text(), kind: declarationInterface, reportNode: decl.Name().AsNode()}}
	case ast.KindTypeAliasDeclaration:
		decl := node.AsTypeAliasDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		return []declarationInfo{{name: decl.Name().Text(), kind: declarationTypeAlias, reportNode: decl.Name().AsNode()}}
	case ast.KindEnumDeclaration:
		decl := node.AsEnumDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		return []declarationInfo{{name: decl.Name().Text(), kind: declarationEnum, reportNode: decl.Name().AsNode()}}
	case ast.KindModuleDeclaration:
		decl := node.AsModuleDeclaration()
		if decl == nil || decl.Name() == nil {
			return nil
		}
		name := strings.TrimSpace(decl.Name().Text())
		if name == "" {
			if parsedName, ok := declarationNameNodeText(decl.Name()); ok {
				name = parsedName
			}
		}
		if name != "" {
			return []declarationInfo{{name: name, kind: declarationModule, reportNode: decl.Name()}}
		}
	}
	return nil
}

func allKindsIn(decls []declarationInfo, allowed map[declarationKind]bool) bool {
	for _, decl := range decls {
		if !allowed[decl.kind] {
			return false
		}
	}
	return true
}

func countKind(decls []declarationInfo, kind declarationKind) int {
	count := 0
	for _, decl := range decls {
		if decl.kind == kind {
			count++
		}
	}
	return count
}

func shouldIgnoreRedeclare(decls []declarationInfo, opts noRedeclareOptions) bool {
	if len(decls) <= 1 {
		return true
	}
	if !opts.IgnoreDeclarationMerge {
		return false
	}

	if allKindsIn(decls, map[declarationKind]bool{declarationInterface: true}) {
		return true
	}
	if allKindsIn(decls, map[declarationKind]bool{declarationModule: true}) {
		return true
	}
	if allKindsIn(decls, map[declarationKind]bool{
		declarationClass:     true,
		declarationInterface: true,
		declarationModule:    true,
	}) && countKind(decls, declarationClass) <= 1 {
		return true
	}
	if allKindsIn(decls, map[declarationKind]bool{
		declarationFunction:          true,
		declarationFunctionSignature: true,
		declarationModule:            true,
	}) && countKind(decls, declarationFunction) <= 1 {
		return true
	}
	if allKindsIn(decls, map[declarationKind]bool{
		declarationEnum:   true,
		declarationModule: true,
	}) && countKind(decls, declarationEnum) <= 1 {
		return true
	}

	return false
}

func shouldSuppressMergeNonPrimary(decls []declarationInfo, current declarationInfo, opts noRedeclareOptions) bool {
	if !opts.IgnoreDeclarationMerge {
		return false
	}
	if allKindsIn(decls, map[declarationKind]bool{
		declarationClass:     true,
		declarationInterface: true,
		declarationModule:    true,
	}) && countKind(decls, declarationClass) > 1 && current.kind != declarationClass {
		return true
	}
	if allKindsIn(decls, map[declarationKind]bool{
		declarationFunction:          true,
		declarationFunctionSignature: true,
		declarationModule:            true,
	}) && countKind(decls, declarationFunction) > 1 && current.kind != declarationFunction {
		return true
	}
	if allKindsIn(decls, map[declarationKind]bool{
		declarationEnum:   true,
		declarationModule: true,
	}) && countKind(decls, declarationEnum) > 1 && current.kind != declarationEnum {
		return true
	}
	return false
}

func isTopLevelScriptScope(scopeNode *ast.Node, sourceFile *ast.SourceFile, parserOptions *rule.RuleParserOptions) bool {
	if scopeNode == nil || scopeNode.Kind != ast.KindSourceFile || sourceFile == nil {
		return false
	}
	if parserOptions != nil {
		if strings.EqualFold(parserOptions.SourceType, "module") {
			return false
		}
		if parserOptions.EcmaFeatures != nil && parserOptions.EcmaFeatures.GlobalReturn {
			return false
		}
	}
	return !ast.IsExternalModule(sourceFile)
}

func isBuiltinRedeclare(name string, scopeNode *ast.Node, sourceFile *ast.SourceFile, parserOptions *rule.RuleParserOptions, opts noRedeclareOptions) bool {
	if !opts.BuiltinGlobals {
		return false
	}
	if !builtinGlobals[name] {
		return false
	}
	return isTopLevelScriptScope(scopeNode, sourceFile, parserOptions)
}

var globalDirectiveRegex = regexp.MustCompile(`(?is)/\*\s*globals?\s+([^*]+)\*/`)

func parseGlobalDirectiveNames(sourceText string) map[string]bool {
	result := map[string]bool{}
	if sourceText == "" {
		return result
	}
	matches := globalDirectiveRegex.FindAllStringSubmatch(sourceText, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		parts := strings.Split(match[1], ",")
		for _, part := range parts {
			entry := strings.TrimSpace(part)
			if entry == "" {
				continue
			}
			name := entry
			if idx := strings.Index(entry, ":"); idx >= 0 {
				name = strings.TrimSpace(entry[:idx])
			}
			if name != "" {
				result[name] = true
			}
		}
	}
	return result
}

var NoRedeclareRule = rule.CreateRule(rule.Rule{
	Name: "no-redeclare",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		scopesByNode := map[*ast.Node]*scope{}
		explicitGlobalNames := parseGlobalDirectiveNames(ctx.SourceFile.Text())
		listeners := rule.RuleListeners{}

		declarationKinds := []ast.Kind{
			ast.KindVariableDeclaration,
			ast.KindFunctionDeclaration,
			ast.KindClassDeclaration,
			ast.KindInterfaceDeclaration,
			ast.KindTypeAliasDeclaration,
			ast.KindEnumDeclaration,
			ast.KindModuleDeclaration,
		}
		for _, kind := range declarationKinds {
			k := kind
			listeners[k] = func(node *ast.Node) {
				infos := declarationInfos(node)
				if len(infos) == 0 {
					return
				}
				scopeNode := declarationScopeNode(node)
				if scopeNode == nil {
					return
				}
				scopeObj, ok := scopesByNode[scopeNode]
				if !ok {
					scopeObj = newScope()
					scopesByNode[scopeNode] = scopeObj
				}

				for _, info := range infos {
					existing := scopeObj.decls[info.name]
					if len(existing) == 0 && explicitGlobalNames[info.name] {
						existing = append(existing, declarationInfo{name: info.name, kind: declarationComment})
					}
					if len(existing) == 0 && ctx.Globals != nil && ctx.Globals[info.name] {
						existing = append(existing, declarationInfo{name: info.name, kind: declarationBuiltin})
					}
					if len(existing) == 0 && isBuiltinRedeclare(info.name, scopeNode, ctx.SourceFile, ctx.ParserOptions, opts) {
						existing = append(existing, declarationInfo{name: info.name, kind: declarationBuiltin})
					}

					candidate := append(append([]declarationInfo{}, existing...), info)
					if shouldIgnoreRedeclare(candidate, opts) {
						scopeObj.decls[info.name] = candidate
						continue
					}
					if shouldSuppressMergeNonPrimary(candidate, info, opts) {
						scopeObj.decls[info.name] = candidate
						continue
					}

					messageID := "redeclared"
					if len(existing) > 0 && existing[0].kind == declarationBuiltin {
						messageID = "redeclaredAsBuiltin"
					} else if len(existing) > 0 && existing[0].kind == declarationComment {
						messageID = "redeclaredBySyntax"
					}
					if info.reportNode != nil {
						ctx.ReportNode(info.reportNode, buildRedeclaredMessage(info.name, messageID))
					}
					scopeObj.decls[info.name] = candidate
				}
			}
		}

		return listeners
	},
})
