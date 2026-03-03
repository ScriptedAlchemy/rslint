package no_loop_func

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type symbolRef struct {
	pos       int
	scopeNode *ast.Node
}

func buildUnsafeRefsMessage(varNames []string) rule.RuleMessage {
	suffix := ""
	if len(varNames) > 0 {
		suffix = " " + strings.Join(varNames, ", ")
	}
	return rule.RuleMessage{
		Id:          "unsafeRefs",
		Description: "Function declared in a loop contains unsafe references to variable(s)." + suffix,
	}
}

func isFunctionLike(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction:
		return true
	}
	return false
}

func isVariableScopeBoundary(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == ast.KindSourceFile {
		return true
	}
	return isFunctionLike(node)
}

func variableScopeNode(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if isVariableScopeBoundary(current) {
			return current
		}
	}
	return nil
}

func inNodeRange(node *ast.Node, rangeNode *ast.Node) bool {
	if node == nil || rangeNode == nil {
		return false
	}
	return node.Pos() >= rangeNode.Pos() && node.End() <= rangeNode.End()
}

func isDeclarationIdentifier(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindIdentifier || node.Parent == nil {
		return false
	}
	switch node.Parent.Kind {
	case ast.KindVariableDeclaration:
		parent := node.Parent.AsVariableDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindBindingElement:
		parent := node.Parent.AsBindingElement()
		return parent != nil && parent.Name() == node
	case ast.KindFunctionDeclaration:
		parent := node.Parent.AsFunctionDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindFunctionExpression:
		parent := node.Parent.AsFunctionExpression()
		return parent != nil && parent.Name() == node
	case ast.KindClassDeclaration:
		parent := node.Parent.AsClassDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindClassExpression:
		parent := node.Parent.AsClassExpression()
		return parent != nil && parent.Name() == node
	case ast.KindParameter:
		parent := node.Parent.AsParameterDeclaration()
		return parent != nil && parent.Name() == node
	case ast.KindImportClause:
		parent := node.Parent.AsImportClause()
		return parent != nil && parent.Name() == node
	case ast.KindImportSpecifier:
		parent := node.Parent.AsImportSpecifier()
		return parent != nil && parent.Name() == node
	case ast.KindNamespaceImport:
		parent := node.Parent.AsNamespaceImport()
		return parent != nil && parent.Name() == node
	}
	return false
}

func isAssignmentTarget(node *ast.Node, target *ast.Node) bool {
	return target != nil && inNodeRange(node, target)
}

func isWriteReference(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindIdentifier || node.Parent == nil {
		return false
	}
	if isDeclarationIdentifier(node) {
		return true
	}

	switch node.Parent.Kind {
	case ast.KindBinaryExpression:
		parent := node.Parent.AsBinaryExpression()
		if parent != nil && ast.IsAssignmentOperator(parent.OperatorToken.Kind) && isAssignmentTarget(node, parent.Left) {
			return true
		}
	case ast.KindPrefixUnaryExpression:
		parent := node.Parent.AsPrefixUnaryExpression()
		if parent != nil && (parent.Operator == ast.KindPlusPlusToken || parent.Operator == ast.KindMinusMinusToken) && isAssignmentTarget(node, parent.Operand) {
			return true
		}
	case ast.KindPostfixUnaryExpression:
		parent := node.Parent.AsPostfixUnaryExpression()
		if parent != nil && (parent.Operator == ast.KindPlusPlusToken || parent.Operator == ast.KindMinusMinusToken) && isAssignmentTarget(node, parent.Operand) {
			return true
		}
	}
	return false
}

func resolveAliasSymbol(typeChecker *checker.Checker, symbol *ast.Symbol) *ast.Symbol {
	if typeChecker == nil || symbol == nil {
		return nil
	}
	if symbol.Flags&ast.SymbolFlagsAlias == 0 {
		return symbol
	}
	if resolved, found := typeChecker.ResolveAlias(symbol); found && resolved != nil {
		return resolved
	}
	return symbol
}

func isAsyncOrGeneratorFunction(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if node.ModifierFlags()&ast.ModifierFlagsAsync != 0 {
		return true
	}
	switch node.Kind {
	case ast.KindFunctionDeclaration:
		fn := node.AsFunctionDeclaration()
		return fn != nil && fn.AsteriskToken != nil
	case ast.KindFunctionExpression:
		fn := node.AsFunctionExpression()
		return fn != nil && fn.AsteriskToken != nil
	}
	return false
}

func isIIFE(node *ast.Node) bool {
	if node == nil {
		return false
	}
	expr := node
	for expr.Parent != nil && expr.Parent.Kind == ast.KindParenthesizedExpression {
		parent := expr.Parent.AsParenthesizedExpression()
		if parent == nil || parent.Expression != expr {
			break
		}
		expr = expr.Parent
	}
	if expr.Parent == nil || expr.Parent.Kind != ast.KindCallExpression {
		return false
	}
	call := expr.Parent.AsCallExpression()
	return call != nil && call.Expression == expr
}

func isNodeInsideLoopInitializer(current *ast.Node, loop *ast.Node) bool {
	if current == nil || loop == nil {
		return false
	}
	switch loop.Kind {
	case ast.KindForStatement:
		forStmt := loop.AsForStatement()
		if forStmt != nil && forStmt.Initializer != nil {
			return current.Pos() >= forStmt.Initializer.Pos() && current.End() <= forStmt.Initializer.End()
		}
	case ast.KindForInStatement:
		forIn := loop.AsForInOrOfStatement()
		if forIn != nil && forIn.Expression != nil {
			return current.Pos() >= forIn.Expression.Pos() && current.End() <= forIn.Expression.End()
		}
	case ast.KindForOfStatement:
		forOf := loop.AsForInOrOfStatement()
		if forOf != nil && forOf.Expression != nil {
			return current.Pos() >= forOf.Expression.Pos() && current.End() <= forOf.Expression.End()
		}
	}
	return false
}

func getContainingLoopNode(node *ast.Node, skippedIIFEs map[*ast.Node]bool) *ast.Node {
	if node == nil {
		return nil
	}
	current := node
	for current != nil {
		parent := current.Parent
		if parent == nil {
			return nil
		}
		switch parent.Kind {
		case ast.KindForStatement, ast.KindForInStatement, ast.KindForOfStatement, ast.KindWhileStatement, ast.KindDoStatement:
			if !isNodeInsideLoopInitializer(current, parent) {
				return parent
			}
		case ast.KindFunctionDeclaration, ast.KindFunctionExpression, ast.KindArrowFunction:
			if skippedIIFEs[parent] {
				break
			}
			return nil
		}
		current = parent
	}
	return nil
}

func getTopLoopNode(loopNode *ast.Node, excludedNode *ast.Node, skippedIIFEs map[*ast.Node]bool) *ast.Node {
	border := 0
	if excludedNode != nil {
		border = excludedNode.End()
	}
	result := loopNode
	current := loopNode
	for current != nil && current.Pos() >= border {
		result = current
		current = getContainingLoopNode(current, skippedIIFEs)
	}
	return result
}

func symbolDeclaredInFunction(symbol *ast.Symbol, functionNode *ast.Node) bool {
	if symbol == nil || functionNode == nil {
		return false
	}
	if symbol.ValueDeclaration != nil && inNodeRange(symbol.ValueDeclaration, functionNode) {
		return true
	}
	for _, decl := range symbol.Declarations {
		if inNodeRange(decl, functionNode) {
			return true
		}
	}
	return false
}

func symbolDeclarationInfo(symbol *ast.Symbol) (kind string, declarationNode *ast.Node) {
	if symbol == nil {
		return "", nil
	}

	getDeclParent := func(decl *ast.Node) *ast.Node {
		if decl == nil {
			return nil
		}
		if decl.Parent != nil {
			return decl.Parent
		}
		return decl
	}

	if symbol.ValueDeclaration != nil {
		declarationNode = getDeclParent(symbol.ValueDeclaration)
	}
	if declarationNode == nil {
		for _, decl := range symbol.Declarations {
			declarationNode = getDeclParent(decl)
			if declarationNode != nil {
				break
			}
		}
	}
	if declarationNode == nil {
		return "", nil
	}

	if declarationNode.Kind == ast.KindIdentifier && declarationNode.Parent != nil {
		declarationNode = declarationNode.Parent
	}
	if declarationNode.Kind == ast.KindForStatement {
		forStmt := declarationNode.AsForStatement()
		if forStmt != nil && forStmt.Initializer != nil {
			declarationNode = forStmt.Initializer
		}
	}
	if declarationNode.Kind == ast.KindForInStatement || declarationNode.Kind == ast.KindForOfStatement {
		forInOrOf := declarationNode.AsForInOrOfStatement()
		if forInOrOf != nil && forInOrOf.Initializer != nil {
			declarationNode = forInOrOf.Initializer
		}
	}

	switch declarationNode.Kind {
	case ast.KindVariableDeclaration:
		if declarationNode.Parent != nil && declarationNode.Parent.Kind == ast.KindVariableDeclarationList {
			flags := declarationNode.Parent.AsVariableDeclarationList().Flags
			if flags&ast.NodeFlagsConst != 0 {
				return "const", declarationNode
			}
			if flags&ast.NodeFlagsBlockScoped != 0 {
				return "let", declarationNode
			}
			return "var", declarationNode
		}
		return "var", declarationNode
	case ast.KindVariableDeclarationList:
		flags := declarationNode.AsVariableDeclarationList().Flags
		if flags&ast.NodeFlagsConst != 0 {
			return "const", declarationNode
		}
		if flags&ast.NodeFlagsBlockScoped != 0 {
			return "let", declarationNode
		}
		return "var", declarationNode
	case ast.KindParameter:
		return "var", declarationNode
	case ast.KindFunctionDeclaration, ast.KindFunctionExpression:
		return "function", declarationNode
	case ast.KindClassDeclaration, ast.KindClassExpression:
		return "class", declarationNode
	case ast.KindImportClause, ast.KindImportSpecifier, ast.KindNamespaceImport:
		return "const", declarationNode
	}
	return "", declarationNode
}

func isLetDeclaredInLoop(loopNode *ast.Node, declarationNode *ast.Node) bool {
	if loopNode == nil || declarationNode == nil {
		return false
	}
	return declarationNode.Pos() > loopNode.Pos() && declarationNode.End() < loopNode.End()
}

func collectIdentifierNodes(root *ast.Node, visit func(node *ast.Node)) {
	if root == nil {
		return
	}
	if root.Kind == ast.KindIdentifier {
		visit(root)
	}
	root.ForEachChild(func(child *ast.Node) bool {
		collectIdentifierNodes(child, visit)
		return false
	})
}

func isSafeSymbolReference(
	loopNode *ast.Node,
	symbol *ast.Symbol,
	referencePos int,
	symbolWrites map[ast.SymbolId][]symbolRef,
	skippedIIFEs map[*ast.Node]bool,
) bool {
	kind, declarationNode := symbolDeclarationInfo(symbol)
	if declarationNode != nil && declarationNode.Pos() > referencePos {
		return true
	}

	if kind == "const" {
		return true
	}
	if kind == "let" && isLetDeclaredInLoop(loopNode, declarationNode) {
		return true
	}
	if kind == "var" && isLetDeclaredInLoop(loopNode, declarationNode) {
		return false
	}

	borderLoop := getTopLoopNode(loopNode, nil, skippedIIFEs)
	if kind == "let" {
		borderLoop = getTopLoopNode(loopNode, declarationNode, skippedIIFEs)
	}
	border := borderLoop.Pos()

	symbolID := ast.GetSymbolId(symbol)
	writes := symbolWrites[symbolID]
	if len(writes) == 0 {
		return true
	}

	declScope := variableScopeNode(declarationNode)
	for _, write := range writes {
		if write.scopeNode == declScope && write.pos < border {
			continue
		}
		return false
	}
	return true
}

var NoLoopFuncRule = rule.CreateRule(rule.Rule{
	Name: "no-loop-func",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		skippedIIFEs := map[*ast.Node]bool{}
		symbolWrites := map[ast.SymbolId][]symbolRef{}

		if ctx.SourceFile != nil {
			collectIdentifierNodes(ctx.SourceFile.AsNode(), func(identifier *ast.Node) {
				symbol := resolveAliasSymbol(ctx.TypeChecker, ctx.TypeChecker.GetSymbolAtLocation(identifier))
				if symbol == nil || !isWriteReference(identifier) {
					return
				}
				symbolID := ast.GetSymbolId(symbol)
				if symbolID == 0 {
					return
				}
				symbolWrites[symbolID] = append(symbolWrites[symbolID], symbolRef{
					pos:       identifier.Pos(),
					scopeNode: variableScopeNode(identifier),
				})
			})
		}

		checkFunction := func(node *ast.Node) {
			loopNode := getContainingLoopNode(node, skippedIIFEs)
			if loopNode == nil {
				return
			}

			if !isAsyncOrGeneratorFunction(node) && isIIFE(node) {
				skippedIIFEs[node] = true
				return
			}

			seenNames := map[string]bool{}
			unsafeNames := make([]string, 0)

			collectIdentifierNodes(node, func(identifier *ast.Node) {
				if isDeclarationIdentifier(identifier) || ast.IsPartOfTypeNode(identifier) {
					return
				}

				symbol := resolveAliasSymbol(ctx.TypeChecker, ctx.TypeChecker.GetSymbolAtLocation(identifier))
				if symbol == nil || symbolDeclaredInFunction(symbol, node) {
					return
				}
				safe := isSafeSymbolReference(loopNode, symbol, identifier.Pos(), symbolWrites, skippedIIFEs)
				if safe {
					return
				}

				name := identifier.AsIdentifier().Text
				if name == "" || seenNames[name] {
					return
				}
				seenNames[name] = true
				unsafeNames = append(unsafeNames, "'"+name+"'")
			})

			if len(unsafeNames) > 0 {
				ctx.ReportNode(node, buildUnsafeRefsMessage(unsafeNames))
			}
		}

		return rule.RuleListeners{
			ast.KindFunctionDeclaration: checkFunction,
			ast.KindFunctionExpression:  checkFunction,
			ast.KindArrowFunction:       checkFunction,
		}
	},
})
