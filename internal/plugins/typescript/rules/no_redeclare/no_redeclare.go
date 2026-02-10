package no_redeclare

import (
	"slices"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type redeclareDeclKind int

const (
	redeclareDeclUnknown redeclareDeclKind = iota
	redeclareDeclVariable
	redeclareDeclFunction
	redeclareDeclClass
	redeclareDeclInterface
	redeclareDeclNamespace
	redeclareDeclEnum
	redeclareDeclTypeAlias
)

type declarationInfo struct {
	decl       *ast.Node
	name       *ast.Node
	kind       redeclareDeclKind
	hasBody    bool
	sourceFile *ast.SourceFile
}

type noRedeclareOptions struct {
	builtinGlobals         bool
	ignoreDeclarationMerge bool
}

func parseNoRedeclareOptions(options any) noRedeclareOptions {
	parsed := noRedeclareOptions{
		builtinGlobals:         true,
		ignoreDeclarationMerge: true,
	}
	if options == nil {
		return parsed
	}
	var optMap map[string]interface{}
	switch typed := options.(type) {
	case []interface{}:
		if len(typed) > 0 {
			optMap, _ = typed[0].(map[string]interface{})
		}
	case map[string]interface{}:
		optMap = typed
	}
	if optMap == nil {
		return parsed
	}
	if builtinGlobals, ok := optMap["builtinGlobals"].(bool); ok {
		parsed.builtinGlobals = builtinGlobals
	}
	if ignoreDeclarationMerge, ok := optMap["ignoreDeclarationMerge"].(bool); ok {
		parsed.ignoreDeclarationMerge = ignoreDeclarationMerge
	}
	return parsed
}

func buildRedeclaredMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "redeclared",
		Description: "'" + name + "' is already defined.",
	}
}

func buildRedeclaredAsBuiltinMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "redeclaredAsBuiltin",
		Description: "'" + name + "' is already defined as a built-in global variable.",
	}
}

func buildRedeclaredBySyntaxMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "redeclaredBySyntax",
		Description: "'" + name + "' is already defined by syntax annotation.",
	}
}

func declarationInfoFromNode(decl *ast.Node) (declarationInfo, bool) {
	if decl == nil {
		return declarationInfo{}, false
	}
	info := declarationInfo{decl: decl, kind: redeclareDeclUnknown, sourceFile: ast.GetSourceFileOfNode(decl)}
	switch decl.Kind {
	case ast.KindVariableDeclaration:
		varDecl := decl.AsVariableDeclaration()
		if varDecl == nil || varDecl.Name() == nil || varDecl.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = varDecl.Name()
		info.kind = redeclareDeclVariable
	case ast.KindBindingElement:
		element := decl.AsBindingElement()
		if element == nil || element.Name() == nil || element.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = element.Name()
		info.kind = redeclareDeclVariable
	case ast.KindFunctionDeclaration:
		functionDecl := decl.AsFunctionDeclaration()
		if functionDecl == nil || functionDecl.Name() == nil || functionDecl.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = functionDecl.Name()
		info.kind = redeclareDeclFunction
		info.hasBody = functionDecl.Body != nil
	case ast.KindClassDeclaration:
		classDecl := decl.AsClassDeclaration()
		if classDecl == nil || classDecl.Name() == nil || classDecl.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = classDecl.Name()
		info.kind = redeclareDeclClass
	case ast.KindInterfaceDeclaration:
		interfaceDecl := decl.AsInterfaceDeclaration()
		if interfaceDecl == nil || interfaceDecl.Name() == nil || interfaceDecl.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = interfaceDecl.Name()
		info.kind = redeclareDeclInterface
	case ast.KindTypeAliasDeclaration:
		typeAlias := decl.AsTypeAliasDeclaration()
		if typeAlias == nil || typeAlias.Name() == nil || typeAlias.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = typeAlias.Name()
		info.kind = redeclareDeclTypeAlias
	case ast.KindEnumDeclaration:
		enumDecl := decl.AsEnumDeclaration()
		if enumDecl == nil || enumDecl.Name() == nil || enumDecl.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = enumDecl.Name()
		info.kind = redeclareDeclEnum
	case ast.KindModuleDeclaration:
		moduleDecl := decl.AsModuleDeclaration()
		if moduleDecl == nil || moduleDecl.Name() == nil || moduleDecl.Name().Kind != ast.KindIdentifier {
			return declarationInfo{}, false
		}
		info.name = moduleDecl.Name()
		info.kind = redeclareDeclNamespace
	default:
		return declarationInfo{}, false
	}
	return info, true
}

func hasFunctionOverloadConflict(existing []declarationInfo, candidate declarationInfo) bool {
	if candidate.kind != redeclareDeclFunction {
		return true
	}
	for _, info := range existing {
		if info.kind != redeclareDeclFunction {
			return true
		}
	}
	implementationCount := 0
	for _, info := range existing {
		if info.hasBody {
			implementationCount++
		}
	}
	if candidate.hasBody {
		implementationCount++
	}
	return implementationCount > 1
}

func allowsDeclarationMerge(existing []declarationInfo, candidate declarationInfo) bool {
	isNamespaceCompatible := func(kind redeclareDeclKind) bool {
		return kind == redeclareDeclNamespace || kind == redeclareDeclClass || kind == redeclareDeclFunction || kind == redeclareDeclEnum || kind == redeclareDeclInterface
	}
	switch candidate.kind {
	case redeclareDeclInterface:
		for _, info := range existing {
			if info.kind != redeclareDeclInterface && info.kind != redeclareDeclClass {
				return false
			}
		}
		return true
	case redeclareDeclClass:
		for _, info := range existing {
			if info.kind != redeclareDeclInterface && info.kind != redeclareDeclNamespace {
				return false
			}
		}
		return true
	case redeclareDeclNamespace:
		for _, info := range existing {
			if !isNamespaceCompatible(info.kind) {
				return false
			}
		}
		return true
	case redeclareDeclEnum:
		for _, info := range existing {
			if info.kind != redeclareDeclNamespace {
				return false
			}
		}
		return true
	case redeclareDeclFunction:
		for _, info := range existing {
			if info.kind != redeclareDeclNamespace {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func shouldUseSyntaxRedeclareMessage(sourceText string) bool {
	return strings.Contains(sourceText, "/*global") || strings.Contains(sourceText, "/* globals")
}

var NoRedeclareRule = rule.CreateRule(rule.Rule{
	Name: "no-redeclare",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		parsedOptions := parseNoRedeclareOptions(options)
		processedSymbols := map[*ast.Symbol]bool{}
		reportedDeclarationNodes := map[*ast.Node]bool{}

		processSymbol := func(symbol *ast.Symbol) {
			if symbol == nil || processedSymbols[symbol] {
				return
			}
			processedSymbols[symbol] = true

			localInfos := []declarationInfo{}
			hasNonLocalDeclarations := false
			for _, decl := range symbol.Declarations {
				info, ok := declarationInfoFromNode(decl)
				if !ok || info.name == nil {
					continue
				}
				if info.sourceFile == ctx.SourceFile {
					localInfos = append(localInfos, info)
				} else {
					hasNonLocalDeclarations = true
				}
			}
			if len(localInfos) == 0 {
				return
			}
			slices.SortFunc(localInfos, func(a, b declarationInfo) int {
				if a.decl.Pos() < b.decl.Pos() {
					return -1
				}
				if a.decl.Pos() > b.decl.Pos() {
					return 1
				}
				return 0
			})

			if parsedOptions.builtinGlobals && (utils.IsSymbolFromDefaultLibrary(ctx.Program, symbol) || hasNonLocalDeclarations) {
				for _, info := range localInfos {
					if reportedDeclarationNodes[info.name] {
						continue
					}
					reportedDeclarationNodes[info.name] = true
					name := info.name.AsIdentifier().Text
					if !utils.IsSymbolFromDefaultLibrary(ctx.Program, symbol) && shouldUseSyntaxRedeclareMessage(ctx.SourceFile.Text()) {
						ctx.ReportNode(info.name, buildRedeclaredBySyntaxMessage(name))
						continue
					}
					ctx.ReportNode(info.name, buildRedeclaredAsBuiltinMessage(name))
				}
				return
			}

			if len(localInfos) <= 1 {
				return
			}

			accepted := []declarationInfo{localInfos[0]}
			for _, info := range localInfos[1:] {
				if info.kind == redeclareDeclFunction && !hasFunctionOverloadConflict(accepted, info) {
					accepted = append(accepted, info)
					continue
				}
				if parsedOptions.ignoreDeclarationMerge && allowsDeclarationMerge(accepted, info) {
					accepted = append(accepted, info)
					continue
				}
				if !reportedDeclarationNodes[info.name] {
					reportedDeclarationNodes[info.name] = true
					ctx.ReportNode(info.name, buildRedeclaredMessage(info.name.AsIdentifier().Text))
				}
			}
		}

		processDeclaration := func(node *ast.Node) {
			if ctx.TypeChecker == nil || node == nil {
				return
			}
			info, ok := declarationInfoFromNode(node)
			if !ok || info.name == nil || info.name.Kind != ast.KindIdentifier {
				return
			}
			symbol := ctx.TypeChecker.GetSymbolAtLocation(info.name)
			processSymbol(symbol)
		}

		return rule.RuleListeners{
			ast.KindVariableDeclaration:  processDeclaration,
			ast.KindBindingElement:       processDeclaration,
			ast.KindFunctionDeclaration:  processDeclaration,
			ast.KindClassDeclaration:     processDeclaration,
			ast.KindInterfaceDeclaration: processDeclaration,
			ast.KindTypeAliasDeclaration: processDeclaration,
			ast.KindEnumDeclaration:      processDeclaration,
			ast.KindModuleDeclaration:    processDeclaration,
		}
	},
})
