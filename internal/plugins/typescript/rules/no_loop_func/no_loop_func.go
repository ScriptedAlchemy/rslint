package no_loop_func

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnsafeRefsMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeRefs",
		Description: "Function declared in a loop contains unsafe references to loop variables.",
	}
}

func isFunctionLikeNode(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction:
		return true
	default:
		return false
	}
}

func collectBindingIdentifiers(name *ast.Node, out *[]*ast.Node) {
	if name == nil {
		return
	}
	switch name.Kind {
	case ast.KindIdentifier:
		*out = append(*out, name)
	case ast.KindArrayBindingPattern, ast.KindObjectBindingPattern:
		pattern := name.AsBindingPattern()
		if pattern == nil || pattern.Elements == nil {
			return
		}
		for _, elementNode := range pattern.Elements.Nodes {
			element := elementNode.AsBindingElement()
			if element == nil {
				continue
			}
			collectBindingIdentifiers(element.Name(), out)
		}
	}
}

func collectLoopVariableSymbols(ctx rule.RuleContext, loopNode *ast.Node) map[*ast.Symbol]bool {
	result := map[*ast.Symbol]bool{}
	if ctx.TypeChecker == nil || loopNode == nil {
		return result
	}

	addIdentifier := func(identifier *ast.Node) {
		if identifier == nil || identifier.Kind != ast.KindIdentifier {
			return
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(identifier)
		if symbol != nil {
			result[symbol] = true
		}
	}

	collectFromVarDeclList := func(node *ast.Node) {
		if node == nil || node.Kind != ast.KindVariableDeclarationList {
			return
		}
		declList := node.AsVariableDeclarationList()
		if declList == nil || declList.Declarations == nil {
			return
		}
		// `var` declarations are loop-closure hazards. `let`/`const` are block-scoped.
		if node.Flags&(ast.NodeFlagsLet|ast.NodeFlagsConst) != 0 {
			return
		}
		for _, declNode := range declList.Declarations.Nodes {
			decl := declNode.AsVariableDeclaration()
			if decl == nil || decl.Name() == nil {
				continue
			}
			identifiers := []*ast.Node{}
			collectBindingIdentifiers(decl.Name(), &identifiers)
			for _, identifier := range identifiers {
				addIdentifier(identifier)
			}
		}
	}

	switch loopNode.Kind {
	case ast.KindForStatement:
		forStmt := loopNode.AsForStatement()
		if forStmt != nil && forStmt.Initializer != nil {
			collectFromVarDeclList(forStmt.Initializer)
		}
	case ast.KindForInStatement:
		forInStmt := loopNode.AsForInOrOfStatement()
		if forInStmt != nil && forInStmt.Initializer != nil {
			if forInStmt.Initializer.Kind == ast.KindVariableDeclarationList {
				collectFromVarDeclList(forInStmt.Initializer)
			} else if forInStmt.Initializer.Kind == ast.KindIdentifier {
				addIdentifier(forInStmt.Initializer)
			}
		}
	case ast.KindForOfStatement:
		forOfStmt := loopNode.AsForInOrOfStatement()
		if forOfStmt != nil && forOfStmt.Initializer != nil {
			if forOfStmt.Initializer.Kind == ast.KindVariableDeclarationList {
				collectFromVarDeclList(forOfStmt.Initializer)
			} else if forOfStmt.Initializer.Kind == ast.KindIdentifier {
				addIdentifier(forOfStmt.Initializer)
			}
		}
	}
	return result
}

func isIdentifierReference(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindIdentifier {
		return false
	}
	parent := node.Parent
	if parent == nil {
		return true
	}
	switch parent.Kind {
	case ast.KindVariableDeclaration:
		varDecl := parent.AsVariableDeclaration()
		return varDecl == nil || varDecl.Name() != node
	case ast.KindParameter:
		param := parent.AsParameterDeclaration()
		return param == nil || param.Name() != node
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindClassDeclaration, ast.KindClassExpression, ast.KindInterfaceDeclaration, ast.KindTypeAliasDeclaration, ast.KindEnumDeclaration:
		return false
	case ast.KindPropertyAccessExpression:
		access := parent.AsPropertyAccessExpression()
		return access == nil || access.Name() != node
	case ast.KindPropertyAssignment:
		prop := parent.AsPropertyAssignment()
		return prop == nil || prop.Name() != node
	case ast.KindImportSpecifier, ast.KindExportSpecifier:
		return false
	default:
		return true
	}
}

func functionUsesLoopVar(ctx rule.RuleContext, fnNode *ast.Node, loopVarSymbols map[*ast.Symbol]bool) bool {
	if fnNode == nil || len(loopVarSymbols) == 0 {
		return false
	}
	unsafe := false
	var visit func(*ast.Node)
	visit = func(current *ast.Node) {
		if current == nil || unsafe {
			return
		}
		if isFunctionLikeNode(current) && current != fnNode {
			return
		}
		if current.Kind == ast.KindIdentifier && isIdentifierReference(current) {
			symbol := ctx.TypeChecker.GetSymbolAtLocation(current)
			if symbol != nil && loopVarSymbols[symbol] {
				unsafe = true
				return
			}
		}
		current.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return false
		})
	}
	visit(fnNode)
	return unsafe
}

func checkLoopNode(ctx rule.RuleContext, loopNode *ast.Node) {
	if ctx.TypeChecker == nil || loopNode == nil {
		return
	}
	loopVarSymbols := collectLoopVariableSymbols(ctx, loopNode)
	if len(loopVarSymbols) == 0 {
		return
	}

	loopNode.ForEachChild(func(child *ast.Node) bool {
		if child == nil {
			return false
		}
		if isFunctionLikeNode(child) && functionUsesLoopVar(ctx, child, loopVarSymbols) {
			ctx.ReportNode(child, buildUnsafeRefsMessage())
			return false
		}
		child.ForEachChild(func(grandChild *ast.Node) bool {
			if isFunctionLikeNode(grandChild) && functionUsesLoopVar(ctx, grandChild, loopVarSymbols) {
				ctx.ReportNode(grandChild, buildUnsafeRefsMessage())
			}
			return false
		})
		return false
	})
}

var NoLoopFuncRule = rule.CreateRule(rule.Rule{
	Name: "no-loop-func",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options
		return rule.RuleListeners{
			ast.KindForStatement:   func(node *ast.Node) { checkLoopNode(ctx, node) },
			ast.KindForInStatement: func(node *ast.Node) { checkLoopNode(ctx, node) },
			ast.KindForOfStatement: func(node *ast.Node) { checkLoopNode(ctx, node) },
		}
	},
})
