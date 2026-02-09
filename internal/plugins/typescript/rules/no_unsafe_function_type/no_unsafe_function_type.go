package no_unsafe_function_type

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildBannedFunctionTypeMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "bannedFunctionType",
		Description: "The `Function` type accepts any function-like value and is unsafe.",
	}
}

func hasLocalDeclarationInFile(symbol *ast.Symbol, sourceFile *ast.SourceFile) bool {
	if symbol == nil || sourceFile == nil {
		return false
	}
	for _, decl := range symbol.Declarations {
		if ast.GetSourceFileOfNode(decl) == sourceFile {
			return true
		}
	}
	return false
}

var NoUnsafeFunctionTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-unsafe-function-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		isUnsafeFunctionIdentifier := func(node *ast.Node) bool {
			if node == nil || node.Kind != ast.KindIdentifier || node.AsIdentifier().Text != "Function" {
				return false
			}
			if ctx.TypeChecker == nil || ctx.Program == nil {
				return true
			}
			symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
			if hasLocalDeclarationInFile(symbol, ctx.SourceFile) {
				return false
			}
			return symbol != nil && utils.IsSymbolFromDefaultLibrary(ctx.Program, symbol)
		}

		return rule.RuleListeners{
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil {
					return
				}
				if isUnsafeFunctionIdentifier(typeRef.TypeName) {
					ctx.ReportNode(typeRef.TypeName, buildBannedFunctionTypeMessage())
				}
			},
			ast.KindExpressionWithTypeArguments: func(node *ast.Node) {
				exprWithTypeArgs := node.AsExpressionWithTypeArguments()
				if exprWithTypeArgs == nil || exprWithTypeArgs.Expression == nil {
					return
				}
				if isUnsafeFunctionIdentifier(exprWithTypeArgs.Expression) {
					ctx.ReportNode(exprWithTypeArgs.Expression, buildBannedFunctionTypeMessage())
				}
			},
		}
	},
})
