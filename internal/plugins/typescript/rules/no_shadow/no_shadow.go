package no_shadow

import (
	"slices"
	"strconv"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type scopeInfo struct {
	Parent    *scopeInfo
	IsVar     bool
	Decls     map[string][]*declarationInfo
	ScopeNode *ast.Node
}

type declarationKind int

const (
	declarationUnknown declarationKind = iota
	declarationVar
	declarationLet
	declarationConst
	declarationParam
	declarationFunctionDeclaration
	declarationFunctionExpressionName
	declarationClassDeclaration
	declarationClassExpressionName
	declarationTypeAlias
	declarationInterface
	declarationEnum
	declarationTypeParameter
	declarationImport
)

type declarationInfo struct {
	Name        string
	Identifier  *ast.Node
	DeclNode    *ast.Node
	Scope       *scopeInfo
	Kind        declarationKind
	IsType      bool
	IsValue     bool
	IsThisParam bool
}

type noShadowOptions struct {
	Allow                                      map[string]bool
	BuiltinGlobals                             bool
	Hoist                                      string
	IgnoreFunctionTypeParameterNameValueShadow bool
	IgnoreOnInitialization                     bool
	IgnoreTypeValueShadow                      bool
}

func defaultOptions() noShadowOptions {
	return noShadowOptions{
		Allow:          map[string]bool{},
		BuiltinGlobals: false,
		Hoist:          "functions-and-types",
		IgnoreFunctionTypeParameterNameValueShadow: true,
		IgnoreOnInitialization:                     false,
		IgnoreTypeValueShadow:                      true,
	}
}

func parseOptions(options any) noShadowOptions {
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

	optionMap, ok := raw.(map[string]interface{})
	if !ok {
		return opts
	}

	if allowRaw, ok := optionMap["allow"].([]interface{}); ok {
		for _, item := range allowRaw {
			if name, ok := item.(string); ok {
				opts.Allow[name] = true
			}
		}
	}
	if builtinGlobals, ok := optionMap["builtinGlobals"].(bool); ok {
		opts.BuiltinGlobals = builtinGlobals
	}
	if hoist, ok := optionMap["hoist"].(string); ok {
		switch hoist {
		case "all", "functions", "functions-and-types", "never", "types":
			opts.Hoist = hoist
		}
	}
	if ignoreTypeValueShadow, ok := optionMap["ignoreTypeValueShadow"].(bool); ok {
		opts.IgnoreTypeValueShadow = ignoreTypeValueShadow
	}
	if ignoreFunctionTypeParameterNameValueShadow, ok := optionMap["ignoreFunctionTypeParameterNameValueShadow"].(bool); ok {
		opts.IgnoreFunctionTypeParameterNameValueShadow = ignoreFunctionTypeParameterNameValueShadow
	}
	if ignoreOnInitialization, ok := optionMap["ignoreOnInitialization"].(bool); ok {
		opts.IgnoreOnInitialization = ignoreOnInitialization
	}

	return opts
}

func buildNoShadowMessage(name string, line int, column int) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noShadow",
		Description: "'" + name + "' is already declared in the upper scope on line " + strconv.Itoa(line) + " column " + strconv.Itoa(column) + ".",
	}
}

func buildNoShadowGlobalMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noShadowGlobal",
		Description: "'" + name + "' is already a global variable.",
	}
}

func buildNoShadowMessageFromDecl(name string, decl *declarationInfo, sourceFile *ast.SourceFile) rule.RuleMessage {
	if decl == nil || decl.Identifier == nil || sourceFile == nil {
		return buildNoShadowMessage(name, 0, 0)
	}
	line, column := scanner.GetECMALineAndCharacterOfPosition(sourceFile, decl.Identifier.Pos())
	return buildNoShadowMessage(name, line+1, column+1)
}

func newScope(parent *scopeInfo, node *ast.Node, isVar bool) *scopeInfo {
	return &scopeInfo{
		Parent:    parent,
		IsVar:     isVar,
		Decls:     map[string][]*declarationInfo{},
		ScopeNode: node,
	}
}

func variableScope(scope *scopeInfo) *scopeInfo {
	current := scope
	for current != nil {
		if current.IsVar {
			return current
		}
		current = current.Parent
	}
	return scope
}

func declarationIdentifier(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		n := node.AsVariableDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindBindingElement:
		n := node.AsBindingElement()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindParameter:
		n := node.AsParameterDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindFunctionDeclaration:
		n := node.AsFunctionDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindFunctionExpression:
		n := node.AsFunctionExpression()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindClassDeclaration:
		n := node.AsClassDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindClassExpression:
		n := node.AsClassExpression()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindTypeAliasDeclaration:
		n := node.AsTypeAliasDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindInterfaceDeclaration:
		n := node.AsInterfaceDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindEnumDeclaration:
		n := node.AsEnumDeclaration()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindTypeParameter:
		n := node.AsTypeParameter()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindImportClause:
		n := node.AsImportClause()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindImportSpecifier:
		n := node.AsImportSpecifier()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	case ast.KindNamespaceImport:
		n := node.AsNamespaceImport()
		if n != nil && n.Name() != nil && n.Name().Kind == ast.KindIdentifier {
			return n.Name()
		}
	}
	return nil
}

func declarationInfoForNode(node *ast.Node, scope *scopeInfo, kind declarationKind) *declarationInfo {
	id := declarationIdentifier(node)
	if id == nil || id.Kind != ast.KindIdentifier {
		return nil
	}
	name := id.AsIdentifier().Text
	if name == "" {
		return nil
	}

	info := &declarationInfo{
		Name:       name,
		Identifier: id,
		DeclNode:   node,
		Scope:      scope,
		Kind:       kind,
	}

	switch kind {
	case declarationTypeAlias, declarationInterface, declarationTypeParameter:
		info.IsType = true
	case declarationEnum:
		info.IsType = true
		info.IsValue = true
	case declarationClassDeclaration, declarationClassExpressionName:
		info.IsType = true
		info.IsValue = true
	default:
		info.IsValue = true
	}
	return info
}

func isFunctionHoisted(kind declarationKind) bool {
	return kind == declarationFunctionDeclaration
}

func isTypeHoisted(kind declarationKind) bool {
	return kind == declarationTypeAlias || kind == declarationInterface
}

func hoistAllowsShadow(opts noShadowOptions, inner *declarationInfo, outer *declarationInfo) bool {
	if inner == nil || outer == nil || inner.Identifier == nil || outer.Identifier == nil {
		return true
	}
	if opts.Hoist == "all" {
		return true
	}
	if inner.Identifier.Pos() >= outer.Identifier.Pos() {
		return true
	}
	switch opts.Hoist {
	case "functions":
		return isFunctionHoisted(outer.Kind)
	case "types":
		return isTypeHoisted(outer.Kind)
	case "functions-and-types":
		return isFunctionHoisted(outer.Kind) || isTypeHoisted(outer.Kind)
	case "never":
		return false
	default:
		return isFunctionHoisted(outer.Kind) || isTypeHoisted(outer.Kind)
	}
}

func isTypeValueOnlyShadow(opts noShadowOptions, inner *declarationInfo, outer *declarationInfo) bool {
	if !opts.IgnoreTypeValueShadow || inner == nil || outer == nil {
		return false
	}
	shareType := inner.IsType && outer.IsType
	shareValue := inner.IsValue && outer.IsValue
	return !shareType && !shareValue
}

func isFunctionTypeParameterNameValueShadow(opts noShadowOptions, inner *declarationInfo, outer *declarationInfo) bool {
	if !opts.IgnoreFunctionTypeParameterNameValueShadow || inner == nil || outer == nil {
		return false
	}
	if inner.Kind != declarationTypeParameter || !outer.IsValue || inner.DeclNode == nil {
		return false
	}
	for current := inner.DeclNode.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindFunctionType, ast.KindCallSignature, ast.KindMethodSignature, ast.KindConstructSignature, ast.KindConstructorType:
			return true
		}
		return false
	}
	return false
}

func isOnInitializer(inner *declarationInfo, outer *declarationInfo) bool {
	if inner == nil || outer == nil || inner.Identifier == nil || inner.Scope == nil || outer.Scope == nil || outer.DeclNode == nil {
		return false
	}
	if outer.Kind != declarationVar && outer.Kind != declarationLet && outer.Kind != declarationConst && outer.Kind != declarationParam {
		return false
	}
	parentScope := inner.Scope.Parent
	isAncestor := false
	for scope := parentScope; scope != nil; scope = scope.Parent {
		if scope == outer.Scope {
			isAncestor = true
			break
		}
	}
	if !isAncestor {
		return false
	}
	if inner.Kind != declarationFunctionExpressionName && inner.Kind != declarationClassExpressionName {
		return false
	}
	var initializer *ast.Node
	switch outer.DeclNode.Kind {
	case ast.KindVariableDeclaration:
		if decl := outer.DeclNode.AsVariableDeclaration(); decl != nil {
			initializer = decl.Initializer
		}
	case ast.KindParameter:
		if decl := outer.DeclNode.AsParameterDeclaration(); decl != nil {
			initializer = decl.Initializer
		}
	case ast.KindBindingElement:
		if decl := outer.DeclNode.AsBindingElement(); decl != nil {
			initializer = decl.Initializer
		}
	}
	return initializer != nil && initializer == inner.DeclNode
}

func isBuiltinGlobalName(name string, globals map[string]bool) bool {
	if globals != nil && globals[name] {
		return true
	}
	_, ok := map[string]bool{
		"Object":     true,
		"Array":      true,
		"String":     true,
		"Number":     true,
		"Boolean":    true,
		"Function":   true,
		"Promise":    true,
		"Map":        true,
		"Set":        true,
		"WeakMap":    true,
		"WeakSet":    true,
		"Reflect":    true,
		"Math":       true,
		"JSON":       true,
		"RegExp":     true,
		"Date":       true,
		"console":    true,
		"globalThis": true,
	}[name]
	return ok
}

func findShadowedDeclaration(inner *declarationInfo, opts noShadowOptions) *declarationInfo {
	if inner == nil || inner.Scope == nil {
		return nil
	}
	for scope := inner.Scope.Parent; scope != nil; scope = scope.Parent {
		candidates := scope.Decls[inner.Name]
		if len(candidates) == 0 {
			continue
		}
		for i := len(candidates) - 1; i >= 0; i-- {
			outer := candidates[i]
			if outer == nil {
				continue
			}
			if isOnInitializer(inner, outer) {
				continue
			}
			if isTypeValueOnlyShadow(opts, inner, outer) {
				continue
			}
			if isFunctionTypeParameterNameValueShadow(opts, inner, outer) {
				continue
			}
			if !hoistAllowsShadow(opts, inner, outer) {
				continue
			}
			return outer
		}
	}
	return nil
}

var NoShadowRule = rule.CreateRule(rule.Rule{
	Name: "no-shadow",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		if ctx.SourceFile == nil {
			return rule.RuleListeners{}
		}

		rootScope := newScope(nil, ctx.SourceFile.AsNode(), true)
		currentScope := rootScope
		declarations := make([]*declarationInfo, 0)

		registerDeclaration := func(scope *scopeInfo, info *declarationInfo) {
			if scope == nil || info == nil || info.Name == "" {
				return
			}
			scope.Decls[info.Name] = append(scope.Decls[info.Name], info)
			declarations = append(declarations, info)
		}

		var walk func(node *ast.Node)
		walk = func(node *ast.Node) {
			if node == nil {
				return
			}

			switch node.Kind {
			case ast.KindFunctionDeclaration:
				registerDeclaration(variableScope(currentScope), declarationInfoForNode(node, variableScope(currentScope), declarationFunctionDeclaration))
				nextScope := newScope(currentScope, node, true)
				prev := currentScope
				currentScope = nextScope
				node.ForEachChild(func(child *ast.Node) bool {
					walk(child)
					return false
				})
				currentScope = prev
				return
			case ast.KindFunctionExpression:
				prev := currentScope
				nameScope := newScope(currentScope, node, false)
				currentScope = nameScope
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationFunctionExpressionName))
				functionScope := newScope(currentScope, node, true)
				currentScope = functionScope
				node.ForEachChild(func(child *ast.Node) bool {
					walk(child)
					return false
				})
				currentScope = prev
				return
			case ast.KindArrowFunction, ast.KindMethodDeclaration, ast.KindConstructor:
				nextScope := newScope(currentScope, node, true)
				prev := currentScope
				currentScope = nextScope
				node.ForEachChild(func(child *ast.Node) bool {
					walk(child)
					return false
				})
				currentScope = prev
				return
			case ast.KindClassExpression:
				nextScope := newScope(currentScope, node, false)
				prev := currentScope
				currentScope = nextScope
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationClassExpressionName))
				node.ForEachChild(func(child *ast.Node) bool {
					walk(child)
					return false
				})
				currentScope = prev
				return
			case ast.KindBlock, ast.KindModuleBlock, ast.KindForStatement, ast.KindForInStatement, ast.KindForOfStatement, ast.KindCatchClause:
				nextScope := newScope(currentScope, node, false)
				prev := currentScope
				currentScope = nextScope
				node.ForEachChild(func(child *ast.Node) bool {
					walk(child)
					return false
				})
				currentScope = prev
				return
			case ast.KindVariableDeclaration:
				if id := declarationIdentifier(node); id != nil {
					targetScope := currentScope
					if node.Parent != nil && node.Parent.Kind == ast.KindVariableDeclarationList {
						flags := node.Parent.AsVariableDeclarationList().Flags
						if flags&ast.NodeFlagsBlockScoped == 0 {
							targetScope = variableScope(currentScope)
							registerDeclaration(targetScope, declarationInfoForNode(node, targetScope, declarationVar))
						} else if flags&ast.NodeFlagsConst != 0 {
							registerDeclaration(targetScope, declarationInfoForNode(node, targetScope, declarationConst))
						} else {
							registerDeclaration(targetScope, declarationInfoForNode(node, targetScope, declarationLet))
						}
					}
				}
			case ast.KindBindingElement:
				id := declarationIdentifier(node)
				if id != nil {
					container := node.Parent
					for container != nil {
						if container.Kind == ast.KindVariableDeclaration || container.Kind == ast.KindParameter {
							break
						}
						container = container.Parent
					}
					if container != nil && container.Kind == ast.KindVariableDeclaration {
						targetScope := currentScope
						if container.Parent != nil && container.Parent.Kind == ast.KindVariableDeclarationList {
							flags := container.Parent.AsVariableDeclarationList().Flags
							if flags&ast.NodeFlagsBlockScoped == 0 {
								targetScope = variableScope(currentScope)
								registerDeclaration(targetScope, declarationInfoForNode(node, targetScope, declarationVar))
							} else if flags&ast.NodeFlagsConst != 0 {
								registerDeclaration(targetScope, declarationInfoForNode(node, targetScope, declarationConst))
							} else {
								registerDeclaration(targetScope, declarationInfoForNode(node, targetScope, declarationLet))
							}
						}
					} else if container != nil && container.Kind == ast.KindParameter {
						info := declarationInfoForNode(node, currentScope, declarationParam)
						if info != nil && info.Name == "this" {
							info.IsThisParam = true
						}
						registerDeclaration(currentScope, info)
					}
				}
			case ast.KindParameter:
				info := declarationInfoForNode(node, currentScope, declarationParam)
				if info != nil && info.Name == "this" {
					info.IsThisParam = true
				}
				registerDeclaration(currentScope, info)
			case ast.KindClassDeclaration:
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationClassDeclaration))
			case ast.KindTypeAliasDeclaration:
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationTypeAlias))
			case ast.KindInterfaceDeclaration:
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationInterface))
			case ast.KindEnumDeclaration:
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationEnum))
			case ast.KindTypeParameter:
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationTypeParameter))
			case ast.KindImportClause, ast.KindImportSpecifier, ast.KindNamespaceImport:
				registerDeclaration(currentScope, declarationInfoForNode(node, currentScope, declarationImport))
			}

			node.ForEachChild(func(child *ast.Node) bool {
				walk(child)
				return false
			})
		}

		walk(ctx.SourceFile.AsNode())

		slices.SortFunc(declarations, func(a, b *declarationInfo) int {
			if a == nil || b == nil || a.Identifier == nil || b.Identifier == nil {
				return 0
			}
			return a.Identifier.Pos() - b.Identifier.Pos()
		})

		for _, decl := range declarations {
			if decl == nil || decl.Identifier == nil || decl.Name == "" {
				continue
			}
			if decl.IsThisParam || opts.Allow[decl.Name] {
				continue
			}

			shadowed := findShadowedDeclaration(decl, opts)
			if shadowed != nil {
				ctx.ReportNode(decl.Identifier, buildNoShadowMessageFromDecl(decl.Name, shadowed, ctx.SourceFile))
				continue
			}
			if opts.BuiltinGlobals && isBuiltinGlobalName(decl.Name, ctx.Globals) {
				ctx.ReportNode(decl.Identifier, buildNoShadowGlobalMessage(decl.Name))
			}
		}

		return rule.RuleListeners{}
	},
})
