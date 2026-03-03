package prefer_namespace_keyword

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUseNamespaceMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "useNamespace",
		Description: "Use the namespace keyword instead of module.",
	}
}

func findModuleKeywordRange(sourceFile *ast.SourceFile, moduleDecl *ast.ModuleDeclaration) (core.TextRange, bool) {
	if moduleDecl == nil {
		return core.TextRange{}, false
	}

	scan := scanner.GetScannerForSourceFile(sourceFile, moduleDecl.Pos())
	for {
		token := scan.Token()
		if token == ast.KindModuleKeyword {
			return scan.TokenRange(), true
		}
		if scan.TokenEnd() >= moduleDecl.End() {
			break
		}
		scan.Scan()
	}

	return core.TextRange{}, false
}

var PreferNamespaceKeywordRule = rule.CreateRule(rule.Rule{
	Name: "prefer-namespace-keyword",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindModuleDeclaration: func(node *ast.Node) {
				moduleDecl := node.AsModuleDeclaration()
				if moduleDecl == nil || moduleDecl.Keyword != ast.KindModuleKeyword {
					return
				}

				name := moduleDecl.Name()
				if !ast.IsIdentifier(name) {
					return
				}
				if name.AsIdentifier().Text == "global" {
					return
				}

				keywordRange, ok := findModuleKeywordRange(ctx.SourceFile, moduleDecl)
				if !ok {
					return
				}

				fix := rule.RuleFixReplaceRange(keywordRange, "namespace")
				ctx.ReportNodeWithFixes(node, buildUseNamespaceMessage(), fix)
			},
		}
	},
})
