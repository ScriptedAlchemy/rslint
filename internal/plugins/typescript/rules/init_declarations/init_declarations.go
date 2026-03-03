package init_declarations

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type InitDeclarationsOptions struct {
	Mode              string
	IgnoreForLoopInit bool
}

// InitDeclarationsRule requires or disallows variable initialization.
var InitDeclarationsRule = rule.CreateRule(rule.Rule{
	Name: "init-declarations",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := parseOptions(options)

	return rule.RuleListeners{
		ast.KindVariableDeclaration: func(node *ast.Node) {
			decl := node.AsVariableDeclaration()
			if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
				return
			}

			if opts.Mode == "always" {
				if decl.Initializer != nil {
					return
				}
				if isDeclareVariable(node) || isInDeclareNamespace(node) {
					return
				}
				if isForInOrOfInitializer(node) {
					return
				}
				ctx.ReportRange(utils.TrimNodeTextRange(ctx.SourceFile, decl.Name()), rule.RuleMessage{
					Id:          "initialized",
					Description: "Variable '{{idName}}' should be initialized on declaration.",
				})
				return
			}

			// mode === "never"
			hasInitialization := decl.Initializer != nil || isForInOrOfInitializer(node)
			if !hasInitialization {
				return
			}
			if isConstDeclaration(node) {
				return
			}
			if opts.IgnoreForLoopInit && isForLoopInitializer(node) {
				return
			}
			ctx.ReportRange(utils.TrimNodeTextRange(ctx.SourceFile, node), rule.RuleMessage{
				Id:          "notInitialized",
				Description: "Variable '{{idName}}' should not be initialized on declaration.",
			})
		},
	}
}

func parseOptions(options any) InitDeclarationsOptions {
	opts := InitDeclarationsOptions{
		Mode:              "always",
		IgnoreForLoopInit: false,
	}
	if options == nil {
		return opts
	}

	if arr, ok := options.([]interface{}); ok {
		if len(arr) > 0 {
			if mode, ok := arr[0].(string); ok && (mode == "always" || mode == "never") {
				opts.Mode = mode
			}
		}
		if len(arr) > 1 {
			if optMap, ok := arr[1].(map[string]interface{}); ok {
				if ignore, ok := optMap["ignoreForLoopInit"].(bool); ok {
					opts.IgnoreForLoopInit = ignore
				}
			}
		}
		return opts
	}

	if mode, ok := options.(string); ok && (mode == "always" || mode == "never") {
		opts.Mode = mode
	}
	return opts
}

func isConstDeclaration(node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Kind != ast.KindVariableDeclarationList {
		return false
	}
	declList := node.Parent.AsVariableDeclarationList()
	if declList == nil {
		return false
	}
	return (declList.Flags & ast.NodeFlagsConst) != 0
}

func isDeclareVariable(node *ast.Node) bool {
	if node == nil || node.Parent == nil || node.Parent.Parent == nil {
		return false
	}
	if node.Parent.Kind != ast.KindVariableDeclarationList || node.Parent.Parent.Kind != ast.KindVariableStatement {
		return false
	}
	varStmt := node.Parent.Parent.AsVariableStatement()
	if varStmt == nil {
		return false
	}
	return utils.IncludesModifier(varStmt, ast.KindDeclareKeyword)
}

func isInDeclareNamespace(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		if current.Kind == ast.KindModuleDeclaration {
			moduleDecl := current.AsModuleDeclaration()
			if moduleDecl != nil && utils.IncludesModifier(moduleDecl, ast.KindDeclareKeyword) {
				return true
			}
		}
		current = current.Parent
	}
	return false
}

func isForInOrOfInitializer(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	declList := node.Parent
	if declList.Kind != ast.KindVariableDeclarationList || declList.Parent == nil {
		return false
	}
	parent := declList.Parent
	if parent.Kind == ast.KindForInStatement {
		forIn := parent.AsForInOrOfStatement()
		return forIn != nil && forIn.Initializer == declList
	}
	if parent.Kind == ast.KindForOfStatement {
		forOf := parent.AsForInOrOfStatement()
		return forOf != nil && forOf.Initializer == declList
	}
	return false
}

func isForLoopInitializer(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	declList := node.Parent
	if declList.Kind != ast.KindVariableDeclarationList || declList.Parent == nil {
		return false
	}
	parent := declList.Parent
	if parent.Kind == ast.KindForStatement {
		forStmt := parent.AsForStatement()
		return forStmt != nil && forStmt.Initializer == declList
	}
	return isForInOrOfInitializer(node)
}
