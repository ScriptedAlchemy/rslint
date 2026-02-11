package no_namespace

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

// build the message for no-namespace rule
func buildNoNamespaceMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "moduleSyntaxIsPreferred",
		Description: "Namespace is not allowed.",
	}
}

// rule options
type NoNamespaceOptions struct {
	AllowDeclarations    *bool `json:"allowDeclarations"`
	AllowDefinitionFiles *bool `json:"allowDefinitionFiles"`
}

// default options
var defaultNoNamespaceOptions = NoNamespaceOptions{
	AllowDeclarations:    utils.Ref(false),
	AllowDefinitionFiles: utils.Ref(true),
}

func moduleDeclarationNameText(moduleDecl *ast.ModuleDeclaration) string {
	if moduleDecl == nil || moduleDecl.Name() == nil {
		return ""
	}
	name := moduleDecl.Name()
	switch name.Kind {
	case ast.KindIdentifier:
		id := name.AsIdentifier()
		if id != nil {
			return id.Text
		}
	case ast.KindStringLiteral:
		lit := name.AsStringLiteral()
		if lit != nil {
			return lit.Text
		}
	}
	return ""
}

func isExternalModuleDeclaration(moduleDecl *ast.ModuleDeclaration) bool {
	if moduleDecl == nil || moduleDecl.Name() == nil {
		return false
	}
	return moduleDecl.Name().Kind == ast.KindStringLiteral
}

func isDeclareModuleDeclaration(node *ast.Node) bool {
	return utils.IncludesModifier(node, ast.KindDeclareKeyword)
}

func isInAllowedDeclarationContext(node *ast.Node) bool {
	current := node
	for current != nil {
		if current.Kind == ast.KindModuleDeclaration && isDeclareModuleDeclaration(current) {
			return true
		}
		current = current.Parent
	}
	return false
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
	if start < 0 || end < 0 || end < start || end > ctx.SourceFile.End() {
		return false
	}
	return strings.Contains(ctx.SourceFile.Text()[start:end], ".")
}

func reportModuleKeyword(ctx rule.RuleContext, node *ast.Node, moduleDecl *ast.ModuleDeclaration) {
	if node == nil || moduleDecl == nil {
		return
	}
	if isDeclareModuleDeclaration(node) {
		ctx.ReportNode(node, buildNoNamespaceMessage())
		return
	}
	keywordText := "namespace"
	if moduleDecl.Keyword == ast.KindModuleKeyword {
		keywordText = "module"
	}

	text := ctx.SourceFile.Text()[node.Pos():node.End()]
	if idx := strings.Index(text, keywordText); idx >= 0 {
		start := node.Pos() + idx
		ctx.ReportRange(core.NewTextRange(start, start+len(keywordText)), buildNoNamespaceMessage())
		return
	}
	ctx.ReportNode(node, buildNoNamespaceMessage())
}

// rule instance
// check if the namespace is used
var NoNamespaceRule = rule.CreateRule(rule.Rule{
	Name: "no-namespace",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := defaultNoNamespaceOptions

		// Parse options with dual-format support (handles both array and object formats)
		if options != nil {
			var optsMap map[string]interface{}
			var ok bool

			// Handle array format: [{ option: value }]
			if optArray, isArray := options.([]interface{}); isArray && len(optArray) > 0 {
				optsMap, ok = optArray[0].(map[string]interface{})
			} else {
				// Handle direct object format: { option: value }
				optsMap, ok = options.(map[string]interface{})
			}

			if ok {
				if allowDeclarations, ok := optsMap["allowDeclarations"].(bool); ok {
					opts.AllowDeclarations = utils.Ref(allowDeclarations)
				}
				if allowDefinitionFiles, ok := optsMap["allowDefinitionFiles"].(bool); ok {
					opts.AllowDefinitionFiles = utils.Ref(allowDefinitionFiles)
				}
			}
		}

		return rule.RuleListeners{
			ast.KindModuleDeclaration: func(node *ast.Node) {
				moduleDecl := node.AsModuleDeclaration()
				if moduleDecl == nil {
					return
				}

				// Only script-style `module` / `namespace` declarations are restricted.
				if moduleDecl.Keyword != ast.KindNamespaceKeyword && moduleDecl.Keyword != ast.KindModuleKeyword {
					return
				}

				if isExternalModuleDeclaration(moduleDecl) {
					// `declare module 'foo' {}` is valid.
					return
				}

				if moduleDeclarationNameText(moduleDecl) == "global" {
					// `declare global {}` is valid.
					return
				}

				// Check if we're in a .d.ts file and allowDefinitionFiles is true
				if opts.AllowDefinitionFiles != nil && *opts.AllowDefinitionFiles && strings.HasSuffix(ctx.SourceFile.FileName(), ".d.ts") {
					return
				}

				// Allow ambient declaration-style namespaces/modules when requested.
				if opts.AllowDeclarations != nil && *opts.AllowDeclarations && isInAllowedDeclarationContext(node) {
					return
				}

				// `namespace Foo.Bar {}` should only report the outer declaration.
				if isDottedNamespaceContinuation(ctx, node) {
					return
				}

				// Report the namespace usage on the keyword token.
				reportModuleKeyword(ctx, node, moduleDecl)
			},
		}
	},
})
