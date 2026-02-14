package no_import_type_side_effects

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildUseTopLevelQualifierMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "useTopLevelQualifier",
		Description: "Use a top-level `import type` qualifier for this import.",
	}
}

func nodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	text := sourceFile.Text()
	if trimmed.Pos() < 0 || trimmed.End() > len(text) || trimmed.Pos() >= trimmed.End() {
		return ""
	}
	return text[trimmed.Pos():trimmed.End()]
}

func buildTopLevelTypeImportText(sourceFile *ast.SourceFile, importDecl *ast.ImportDeclaration, namedImports *ast.NamedImports) (string, bool) {
	if sourceFile == nil || importDecl == nil || importDecl.ModuleSpecifier == nil || namedImports == nil || namedImports.Elements == nil {
		return "", false
	}

	specifierTexts := make([]string, 0, len(namedImports.Elements.Nodes))
	for _, specifierNode := range namedImports.Elements.Nodes {
		specifier := specifierNode.AsImportSpecifier()
		if specifier == nil || specifier.Name() == nil {
			return "", false
		}

		localNameText := nodeText(sourceFile, specifier.Name())
		if localNameText == "" {
			return "", false
		}

		if specifier.PropertyName != nil {
			importedNameText := nodeText(sourceFile, specifier.PropertyName)
			if importedNameText == "" {
				return "", false
			}
			specifierTexts = append(specifierTexts, importedNameText+" as "+localNameText)
			continue
		}

		specifierTexts = append(specifierTexts, localNameText)
	}

	moduleSpecifierText := nodeText(sourceFile, importDecl.ModuleSpecifier)
	if moduleSpecifierText == "" {
		return "", false
	}

	replacement := "import type { " + strings.Join(specifierTexts, ", ") + " } from " + moduleSpecifierText
	importDeclText := nodeText(sourceFile, importDecl.AsNode())
	if strings.HasSuffix(strings.TrimSpace(importDeclText), ";") {
		replacement += ";"
	}

	return replacement, true
}

var NoImportTypeSideEffectsRule = rule.CreateRule(rule.Rule{
	Name: "no-import-type-side-effects",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindImportDeclaration: func(node *ast.Node) {
				importDecl := node.AsImportDeclaration()
				if importDecl == nil || importDecl.ImportClause == nil {
					return
				}

				importClause := importDecl.ImportClause.AsImportClause()
				if importClause == nil || importClause.IsTypeOnly() {
					return
				}

				// `import T, { type U } from 'mod'` cannot be converted to top-level type import.
				if importClause.Name() != nil {
					return
				}

				if importClause.NamedBindings == nil || importClause.NamedBindings.Kind != ast.KindNamedImports {
					return
				}

				namedImports := importClause.NamedBindings.AsNamedImports()
				if namedImports == nil || namedImports.Elements == nil || len(namedImports.Elements.Nodes) == 0 {
					return
				}

				for _, specifier := range namedImports.Elements.Nodes {
					if !specifier.IsTypeOnly() {
						return
					}
				}

				replacement, ok := buildTopLevelTypeImportText(ctx.SourceFile, importDecl, namedImports)
				if !ok {
					ctx.ReportNode(node, buildUseTopLevelQualifierMessage())
					return
				}

				ctx.ReportNodeWithFixes(node, buildUseTopLevelQualifierMessage(), rule.RuleFixReplace(ctx.SourceFile, node, replacement))
			},
		}
	},
})
