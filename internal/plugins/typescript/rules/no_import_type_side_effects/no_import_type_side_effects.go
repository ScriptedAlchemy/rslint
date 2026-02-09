package no_import_type_side_effects

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUseTopLevelQualifierMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "useTopLevelQualifier",
		Description: "Use a top-level `import type` qualifier for this import.",
	}
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

				ctx.ReportNode(node, buildUseTopLevelQualifierMessage())
			},
		}
	},
})
