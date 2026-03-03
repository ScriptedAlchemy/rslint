package consistent_type_exports

import (
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ConsistentTypeExportsOptions struct {
	FixMixedExportsWithInlineTypeSpecifier bool `json:"fixMixedExportsWithInlineTypeSpecifier"`
}

func nodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	text := sourceFile.Text()
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	if trimmed.Pos() < 0 || trimmed.End() > len(text) || trimmed.Pos() >= trimmed.End() {
		return ""
	}
	return text[trimmed.Pos():trimmed.End()]
}

func hasSemicolon(sourceFile *ast.SourceFile, node *ast.Node) bool {
	return strings.HasSuffix(strings.TrimSpace(nodeText(sourceFile, node)), ";")
}

func findFirstToken(node *ast.Node, kind ast.Kind, sourceFile *ast.SourceFile) *ast.Node {
	var matched *ast.Node
	utils.ForEachToken(node, func(token *ast.Node) {
		if matched != nil || token == nil || token.Kind != kind {
			return
		}
		matched = token
	}, sourceFile)
	return matched
}

func tokenRange(sourceFile *ast.SourceFile, token *ast.Node) core.TextRange {
	return utils.TrimNodeTextRange(sourceFile, token)
}

func exportSpecifierText(sourceFile *ast.SourceFile, specifierNode *ast.Node) string {
	if sourceFile == nil || specifierNode == nil {
		return ""
	}
	specifier := specifierNode.AsExportSpecifier()
	if specifier == nil || specifier.Name() == nil {
		return ""
	}
	exported := strings.TrimSpace(nodeText(sourceFile, specifier.Name()))
	if exported == "" {
		return ""
	}
	if specifier.PropertyName == nil {
		return exported
	}
	local := strings.TrimSpace(nodeText(sourceFile, specifier.PropertyName))
	if local == "" || local == exported {
		return exported
	}
	return local + " as " + exported
}

func typeKeywordRemovalRangeForExportSpecifier(sourceFile *ast.SourceFile, specifierNode *ast.Node) (core.TextRange, bool) {
	if sourceFile == nil || specifierNode == nil {
		return core.NewTextRange(0, 0), false
	}
	typeKeyword := findFirstToken(specifierNode, ast.KindTypeKeyword, sourceFile)
	if typeKeyword == nil {
		return core.NewTextRange(0, 0), false
	}

	typeRange := tokenRange(sourceFile, typeKeyword)
	sourceText := sourceFile.Text()
	end := typeRange.End()
	for end < len(sourceText) {
		if !unicode.IsSpace(rune(sourceText[end])) {
			break
		}
		end++
	}
	return core.NewTextRange(typeRange.Pos(), end), true
}

// ConsistentTypeExportsRule enforces consistent type exports
var ConsistentTypeExportsRule = rule.CreateRule(rule.Rule{
	Name: "consistent-type-exports",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := ConsistentTypeExportsOptions{
		FixMixedExportsWithInlineTypeSpecifier: false,
	}

	// Parse options
	if options != nil {
		if optArray, isArray := options.([]interface{}); isArray && len(optArray) > 0 {
			if optMap, ok := optArray[0].(map[string]interface{}); ok {
				if fixMixed, ok := optMap["fixMixedExportsWithInlineTypeSpecifier"].(bool); ok {
					opts.FixMixedExportsWithInlineTypeSpecifier = fixMixed
				}
			}
		} else if optMap, ok := options.(map[string]interface{}); ok {
			if fixMixed, ok := optMap["fixMixedExportsWithInlineTypeSpecifier"].(bool); ok {
				opts.FixMixedExportsWithInlineTypeSpecifier = fixMixed
			}
		}
	}

	// Helper to check if a symbol is type-only
	// Returns: true = type-only, false = value-based, nil = unknown/unresolved
	isSymbolTypeBased := func(symbol *ast.Symbol) *bool {
		if symbol == nil {
			return nil
		}

		// Follow alias chain
		for symbol != nil && (symbol.Flags&ast.SymbolFlagsAlias) != 0 {
			symbol = ctx.TypeChecker.GetAliasedSymbol(symbol)
			if symbol == nil {
				return nil
			}

			// Check if any declaration in the chain is type-only
			declarations := symbol.Declarations
			for _, decl := range declarations {
				// Use the Node's IsTypeOnly() method which handles all type-only checks
				if decl.IsTypeOnly() {
					trueVal := true
					return &trueVal
				}
			}
		}

		// Check if the symbol is unknown
		if symbol == nil || ctx.TypeChecker.IsUnknownSymbol(symbol) {
			return nil
		}

		// Check if symbol has Value flag - if not, it's type-only
		hasValue := (symbol.Flags & ast.SymbolFlagsValue) != 0
		isType := !hasValue
		return &isType
	}

	checkExportDeclaration := func(node *ast.Node) {
		exportDecl := node.AsExportDeclaration()
		if exportDecl == nil {
			return
		}

		// Skip if already marked as type-only
		if exportDecl.IsTypeOnly {
			return
		}

		reportTypeOverValueForStarExport := func() {
			message := rule.RuleMessage{
				Id:          "typeOverValue",
				Description: "All exports in the declaration are only used as types. Use `export type`.",
			}
			asterisk := findFirstToken(node, ast.KindAsteriskToken, ctx.SourceFile)
			if asterisk == nil {
				ctx.ReportNode(node, message)
				return
			}
			asteriskRange := tokenRange(ctx.SourceFile, asterisk)
			ctx.ReportNodeWithFixes(node, message, rule.RuleFixReplaceRange(core.NewTextRange(asteriskRange.Pos(), asteriskRange.Pos()), "type "))
		}

		if exportDecl.ModuleSpecifier != nil && (exportDecl.ExportClause == nil || ast.IsNamespaceExport(exportDecl.ExportClause)) {
			moduleSpecifier := exportDecl.ModuleSpecifier
			moduleSymbol := ctx.TypeChecker.GetSymbolAtLocation(moduleSpecifier)

			if moduleSymbol == nil {
				return
			}

			moduleType := ctx.TypeChecker.GetTypeOfSymbolAtLocation(moduleSymbol, moduleSpecifier)
			if moduleType == nil {
				return
			}

			exportedProperties := checker.Checker_getPropertiesOfType(ctx.TypeChecker, moduleType)
			if len(exportedProperties) == 0 {
				reportTypeOverValueForStarExport()
				return
			}

			// Mirror upstream behavior: properties returned by getPropertiesOfType can include
			// type-only star exports; getPropertyOfType returns nil for those.
			for _, propertySymbol := range exportedProperties {
				if checker.Checker_getPropertyOfType(ctx.TypeChecker, moduleType, propertySymbol.Name) != nil {
					return
				}
			}

			reportTypeOverValueForStarExport()
			return
		}

		buildAllTypeExportFixes := func(inlineTypeSpecifiers []*ast.Node) []rule.RuleFix {
			fixes := []rule.RuleFix{}
			trimmed := utils.TrimNodeTextRange(ctx.SourceFile, node)
			sourceText := ctx.SourceFile.Text()
			if trimmed.Pos() >= 0 && trimmed.End() <= len(sourceText) && trimmed.Pos() < trimmed.End() {
				nodeSource := sourceText[trimmed.Pos():trimmed.End()]
				exportIndex := strings.Index(nodeSource, "export")
				if exportIndex >= 0 {
					insertPos := trimmed.Pos() + exportIndex + len("export")
					fixes = append(fixes, rule.RuleFixReplaceRange(core.NewTextRange(insertPos, insertPos), " type"))
				}
			}
			for _, inlineSpecifier := range inlineTypeSpecifiers {
				removeRange, ok := typeKeywordRemovalRangeForExportSpecifier(ctx.SourceFile, inlineSpecifier)
				if !ok {
					continue
				}
				fixes = append(fixes, rule.RuleFixRemoveRange(removeRange))
			}
			return fixes
		}

		buildInlineTypeSpecifierFixes := func(typeSpecifiers []*ast.Node) []rule.RuleFix {
			fixes := []rule.RuleFix{}
			for _, specifierNode := range typeSpecifiers {
				if specifierNode == nil {
					continue
				}
				fixes = append(fixes, rule.RuleFixInsertBefore(ctx.SourceFile, specifierNode, "type "))
			}
			return fixes
		}

		buildSeparateNamedExportFixes := func(namedExports *ast.NamedExports, typeSpecifiers []*ast.Node, inlineTypeSpecifiers []*ast.Node) []rule.RuleFix {
			if namedExports == nil || namedExports.Elements == nil {
				return nil
			}

			typeSpecifierSet := map[*ast.Node]bool{}
			for _, specifier := range typeSpecifiers {
				typeSpecifierSet[specifier] = true
			}
			for _, specifier := range inlineTypeSpecifiers {
				typeSpecifierSet[specifier] = true
			}

			typeNames := []string{}
			valueNames := []string{}
			for _, element := range namedExports.Elements.Nodes {
				if element == nil {
					continue
				}
				specifierText := exportSpecifierText(ctx.SourceFile, element)
				if specifierText == "" {
					continue
				}
				if typeSpecifierSet[element] {
					typeNames = append(typeNames, specifierText)
				} else {
					valueNames = append(valueNames, specifierText)
				}
			}
			if len(typeNames) == 0 || len(valueNames) == 0 {
				return nil
			}

			openBrace := findFirstToken(node, ast.KindOpenBraceToken, ctx.SourceFile)
			closeBrace := findFirstToken(node, ast.KindCloseBraceToken, ctx.SourceFile)
			moduleSpecifierText := ""
			if exportDecl.ModuleSpecifier != nil {
				moduleSpecifierText = nodeText(ctx.SourceFile, exportDecl.ModuleSpecifier)
			}
			if openBrace == nil || closeBrace == nil {
				return nil
			}

			openBraceRange := tokenRange(ctx.SourceFile, openBrace)
			closeBraceRange := tokenRange(ctx.SourceFile, closeBrace)
			nodeRange := utils.TrimNodeTextRange(ctx.SourceFile, node)

			typeExportText := "export type { " + strings.Join(typeNames, ", ") + " }"
			if moduleSpecifierText != "" {
				typeExportText += " from " + moduleSpecifierText
			}
			if hasSemicolon(ctx.SourceFile, node) {
				typeExportText += ";"
			}
			typeExportText += "\n"

			return []rule.RuleFix{
				rule.RuleFixReplaceRange(core.NewTextRange(openBraceRange.End(), closeBraceRange.Pos()), " "+strings.Join(valueNames, ", ")+" "),
				rule.RuleFixReplaceRange(core.NewTextRange(nodeRange.Pos(), nodeRange.Pos()), typeExportText),
			}
		}

		// Handle named exports: export { x, y, z } or export { x, y, z } from 'module'
		if exportDecl.ExportClause != nil && exportDecl.ExportClause.Kind == ast.KindNamedExports {
			namedExports := exportDecl.ExportClause.AsNamedExports()
			if namedExports == nil || len(namedExports.Elements.Nodes) == 0 {
				return
			}

			var typeSpecifiers []*ast.Node
			var valueSpecifiers []*ast.Node
			var inlineTypeSpecifiers []*ast.Node
			var unknownSpecifiers []*ast.Node

			for _, element := range namedExports.Elements.Nodes {
				exportSpecifier := element.AsExportSpecifier()
				if exportSpecifier == nil {
					continue
				}

				// Check if this specifier is already marked as type-only (inline type)
				if exportSpecifier.IsTypeOnly {
					inlineTypeSpecifiers = append(inlineTypeSpecifiers, element)
					continue
				}

				// Align with upstream: inspect the exported binding symbol.
				symbol := ctx.TypeChecker.GetSymbolAtLocation(exportSpecifier.Name())
				if symbol == nil && exportSpecifier.PropertyName != nil {
					symbol = ctx.TypeChecker.GetSymbolAtLocation(exportSpecifier.PropertyName)
				}

				isType := isSymbolTypeBased(symbol)
				if isType == nil {
					unknownSpecifiers = append(unknownSpecifiers, element)
					continue
				}

				if *isType {
					typeSpecifiers = append(typeSpecifiers, element)
				} else {
					valueSpecifiers = append(valueSpecifiers, element)
				}
			}

			// All specifiers are type-only (including inline type specifiers)
			if len(unknownSpecifiers) == 0 && (len(typeSpecifiers) > 0 || len(inlineTypeSpecifiers) > 0) && len(valueSpecifiers) == 0 {
				message := rule.RuleMessage{
					Id:          "typeOverValue",
					Description: "All exports in the declaration are only used as types. Use `export type`.",
				}
				fixes := buildAllTypeExportFixes(inlineTypeSpecifiers)
				if len(fixes) == 0 {
					ctx.ReportNode(node, message)
					return
				}
				ctx.ReportNodeWithFixes(node, message, fixes...)
				return
			}

			// Mixed: some types, some values
			if len(typeSpecifiers) > 0 && (len(valueSpecifiers) > 0 || len(unknownSpecifiers) > 0) {
				message := rule.RuleMessage{
					Id:          "multipleExportsAreTypes",
					Description: "Type exports should use `export type`.",
				}
				if len(typeSpecifiers) == 1 {
					message = rule.RuleMessage{
						Id:          "singleExportIsType",
						Description: "Type export should use `export type`.",
					}
				}

				if opts.FixMixedExportsWithInlineTypeSpecifier {
					fixes := buildInlineTypeSpecifierFixes(typeSpecifiers)
					if len(fixes) == 0 {
						ctx.ReportNode(node, message)
						return
					}
					ctx.ReportNodeWithFixes(node, message, fixes...)
					return
				}

				fixes := buildSeparateNamedExportFixes(namedExports, typeSpecifiers, inlineTypeSpecifiers)
				if len(fixes) == 0 {
					ctx.ReportNode(node, message)
					return
				}
				ctx.ReportNodeWithFixes(node, message, fixes...)
			}
		}
	}

	return rule.RuleListeners{
		ast.KindExportDeclaration: checkExportDeclaration,
	}
}
