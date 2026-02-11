package consistent_type_imports

import (
	"encoding/json"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ConsistentTypeImportsOptions struct {
	Prefer                  string `json:"prefer"`
	DisallowTypeAnnotations bool   `json:"disallowTypeAnnotations"`
	FixStyle                string `json:"fixStyle"`
}

type importedBinding struct {
	localName    string
	symbol       *ast.Symbol
	importDecl   *ast.Node
	isInlineType bool
	isTypeImport bool
	usedAsType   bool
	usedAsValue  bool
}

// ConsistentTypeImportsRule enforces consistent type imports
var ConsistentTypeImportsRule = rule.CreateRule(rule.Rule{
	Name: "consistent-type-imports",
	Run:  run,
})

func parseOptions(options any) ConsistentTypeImportsOptions {
	opts := ConsistentTypeImportsOptions{
		Prefer:                  "type-imports",
		DisallowTypeAnnotations: true,
		FixStyle:                "separate-type-imports",
	}

	if options == nil {
		return opts
	}

	raw := options
	if optArray, isArray := options.([]interface{}); isArray {
		if len(optArray) == 0 {
			return opts
		}
		raw = optArray[0]
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return opts
	}
	_ = json.Unmarshal(encoded, &opts)
	return opts
}

func isImportDeclarationIdentifier(node *ast.Node) bool {
	for current := node; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindImportDeclaration:
			return true
		case ast.KindSourceFile:
			return false
		}
	}
	return false
}

func walk(node *ast.Node, visit func(n *ast.Node)) {
	if node == nil {
		return
	}
	visit(node)
	node.ForEachChild(func(child *ast.Node) bool {
		walk(child, visit)
		return false
	})
}

func localBindingNodeFromImportClause(importClause *ast.ImportClause) *ast.Node {
	if importClause == nil {
		return nil
	}
	if importClause.Name() != nil {
		return importClause.Name().AsNode()
	}
	return nil
}

func addBinding(bindings *[]*importedBinding, ctx rule.RuleContext, importDecl *ast.Node, localNode *ast.Node, isInlineType bool, isTypeImport bool) {
	if localNode == nil || localNode.Kind != ast.KindIdentifier {
		return
	}
	binding := &importedBinding{
		localName:    localNode.AsIdentifier().Text,
		importDecl:   importDecl,
		isInlineType: isInlineType,
		isTypeImport: isTypeImport,
	}
	if ctx.TypeChecker != nil {
		binding.symbol = ctx.TypeChecker.GetSymbolAtLocation(localNode)
	}
	*bindings = append(*bindings, binding)
}

func isTypeOnlyImportDeclaration(sourceFile *ast.SourceFile, importDeclNode *ast.Node, importClause *ast.ImportClause) bool {
	if importClause != nil && importClause.IsTypeOnly() {
		return true
	}
	if sourceFile == nil || importDeclNode == nil {
		return false
	}
	r := utils.TrimNodeTextRange(sourceFile, importDeclNode)
	start := r.Pos()
	end := r.End()
	sourceText := sourceFile.Text()
	if start < 0 || end > len(sourceText) || start >= end {
		return false
	}
	importText := strings.TrimSpace(sourceText[start:end])
	return strings.HasPrefix(importText, "import type ")
}

func collectImportBindings(ctx rule.RuleContext) ([]*importedBinding, map[*ast.Node][]*importedBinding) {
	bindings := []*importedBinding{}
	perImport := map[*ast.Node][]*importedBinding{}

	sourceFile := ctx.SourceFile
	if sourceFile == nil || sourceFile.Statements == nil {
		return bindings, perImport
	}

	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindImportDeclaration {
			continue
		}
		importDecl := statement.AsImportDeclaration()
		if importDecl == nil || importDecl.ImportClause == nil {
			continue
		}
		importClause := importDecl.ImportClause.AsImportClause()
		if importClause == nil {
			continue
		}

		isTypeImportDecl := isTypeOnlyImportDeclaration(ctx.SourceFile, statement, importClause)

		if defaultLocal := localBindingNodeFromImportClause(importClause); defaultLocal != nil {
			addBinding(&bindings, ctx, statement, defaultLocal, false, isTypeImportDecl)
		}

		if importClause.NamedBindings == nil {
			continue
		}
		switch importClause.NamedBindings.Kind {
		case ast.KindNamespaceImport:
			namespaceImport := importClause.NamedBindings.AsNamespaceImport()
			if namespaceImport != nil && namespaceImport.Name() != nil {
				addBinding(&bindings, ctx, statement, namespaceImport.Name(), false, isTypeImportDecl)
			}
		case ast.KindNamedImports:
			namedImports := importClause.NamedBindings.AsNamedImports()
			if namedImports == nil || namedImports.Elements == nil {
				continue
			}
			for _, element := range namedImports.Elements.Nodes {
				if element == nil || element.Kind != ast.KindImportSpecifier {
					continue
				}
				importSpecifier := element.AsImportSpecifier()
				if importSpecifier == nil || importSpecifier.Name() == nil {
					continue
				}
				addBinding(&bindings, ctx, statement, importSpecifier.Name(), importSpecifier.IsTypeOnly, isTypeImportDecl)
			}
		}
	}

	for _, binding := range bindings {
		perImport[binding.importDecl] = append(perImport[binding.importDecl], binding)
	}
	return bindings, perImport
}

func markBindingUsages(ctx rule.RuleContext, bindings []*importedBinding) {
	if len(bindings) == 0 {
		return
	}

	symbolBindings := map[*ast.Symbol][]*importedBinding{}
	nameBindings := map[string][]*importedBinding{}
	for _, binding := range bindings {
		if binding.symbol != nil {
			symbolBindings[binding.symbol] = append(symbolBindings[binding.symbol], binding)
		}
		nameBindings[binding.localName] = append(nameBindings[binding.localName], binding)
	}

	walk(ctx.SourceFile.AsNode(), func(n *ast.Node) {
		if n == nil || n.Kind != ast.KindIdentifier || isImportDeclarationIdentifier(n) {
			return
		}
		identifier := n.AsIdentifier()
		if identifier == nil {
			return
		}

		matched := []*importedBinding{}
		if ctx.TypeChecker != nil {
			if symbol := ctx.TypeChecker.GetSymbolAtLocation(n); symbol != nil {
				matched = append(matched, symbolBindings[symbol]...)
			}
		}
		if len(matched) == 0 {
			matched = append(matched, nameBindings[identifier.Text]...)
		}
		if len(matched) == 0 {
			return
		}

		isTypeUse := ast.IsPartOfTypeNode(n) || ast.IsPartOfTypeQuery(n)
		for _, binding := range matched {
			if isTypeUse {
				binding.usedAsType = true
			} else {
				binding.usedAsValue = true
			}
		}
	})
}

func reportPreferNoTypeImports(ctx rule.RuleContext) {
	sourceFile := ctx.SourceFile
	if sourceFile == nil || sourceFile.Statements == nil {
		return
	}

	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindImportDeclaration {
			continue
		}
		importDecl := statement.AsImportDeclaration()
		if importDecl == nil || importDecl.ImportClause == nil {
			continue
		}
		importClause := importDecl.ImportClause.AsImportClause()
		if importClause == nil {
			continue
		}
		if isTypeOnlyImportDeclaration(ctx.SourceFile, statement, importClause) {
			ctx.ReportNode(statement, rule.RuleMessage{
				Id:          "avoidImportType",
				Description: "Use an `import` instead of an `import type`.",
			})
		}
		if importClause.NamedBindings == nil || importClause.NamedBindings.Kind != ast.KindNamedImports {
			continue
		}
		namedImports := importClause.NamedBindings.AsNamedImports()
		if namedImports == nil || namedImports.Elements == nil {
			continue
		}
		for _, element := range namedImports.Elements.Nodes {
			if element == nil || element.Kind != ast.KindImportSpecifier {
				continue
			}
			importSpecifier := element.AsImportSpecifier()
			if importSpecifier == nil || !importSpecifier.IsTypeOnly {
				continue
			}
			ctx.ReportNode(element, rule.RuleMessage{
				Id:          "avoidImportType",
				Description: "Use an `import` instead of an `import type`.",
			})
		}
	}
}

func reportPreferTypeImports(ctx rule.RuleContext, perImport map[*ast.Node][]*importedBinding) {
	for importDecl, importBindings := range perImport {
		if importDecl == nil {
			continue
		}

		typeOnlyCount := 0
		valueCount := 0
		unusedCount := 0
		partialTypeOnlyNames := []string{}

		for _, binding := range importBindings {
			if binding == nil || binding.isTypeImport || binding.isInlineType {
				continue
			}
			if binding.usedAsValue {
				valueCount++
				continue
			}
			if binding.usedAsType {
				typeOnlyCount++
				partialTypeOnlyNames = append(partialTypeOnlyNames, binding.localName)
			} else {
				unusedCount++
			}
		}

		if typeOnlyCount == 0 {
			continue
		}

		message := rule.RuleMessage{
			Id:          "typeOverValue",
			Description: "All imports in the declaration are only used as types. Use `import type`.",
		}

		if valueCount > 0 {
			message = rule.RuleMessage{
				Id:          "someImportsAreOnlyTypes",
				Description: "Some imports are only used as types.",
			}
		}
		if valueCount == 0 && typeOnlyCount > 0 && unusedCount > 0 {
			// upstream still reports in many unused scenarios; keep typeOverValue by default.
			message.Id = "typeOverValue"
		}

		_ = partialTypeOnlyNames
		ctx.ReportNode(importDecl, message)
	}
}

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := parseOptions(options)
	if opts.Prefer == "no-type-imports" {
		reportPreferNoTypeImports(ctx)
	} else if ctx.TypeChecker != nil {
		bindings, perImport := collectImportBindings(ctx)
		if len(bindings) > 0 {
			markBindingUsages(ctx, bindings)
			reportPreferTypeImports(ctx, perImport)
		}
	}

	return rule.RuleListeners{
		ast.KindImportType: func(node *ast.Node) {
			if !opts.DisallowTypeAnnotations {
				return
			}
			if node.AsImportTypeNode() != nil {
				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "noImportTypeAnnotations",
					Description: "`import()` type annotations are forbidden.",
				})
			}
		},
	}
}
