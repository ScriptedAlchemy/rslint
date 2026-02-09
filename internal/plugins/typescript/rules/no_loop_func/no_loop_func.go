package no_loop_func

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnsafeRefsMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeRefs",
		Description: "Function declared in a loop contains unsafe references to variable(s).",
	}
}

func isInsideLoop(node *ast.Node) bool {
	current := node.Parent
	for current != nil {
		switch current.Kind {
		case ast.KindForStatement, ast.KindForInStatement, ast.KindForOfStatement, ast.KindWhileStatement, ast.KindDoStatement:
			return true
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction:
			return false
		}
		current = current.Parent
	}
	return false
}

var NoLoopFuncRule = rule.CreateRule(rule.Rule{
	Name: "no-loop-func",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		check := func(node *ast.Node) {
			if !isInsideLoop(node) {
				return
			}
			ctx.ReportNode(node, buildUnsafeRefsMessage())
		}
		return rule.RuleListeners{
			ast.KindFunctionDeclaration: check,
			ast.KindFunctionExpression:  check,
			ast.KindArrowFunction:       check,
		}
	},
})
