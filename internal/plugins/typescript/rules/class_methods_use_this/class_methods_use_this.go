package class_methods_use_this

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type classMethodsUseThisOptions struct {
	exceptMethods                       map[string]bool
	enforceForClassFields               bool
	ignoreOverrideMethods               bool
	ignoreClassesThatImplementInterface string
}

func buildMissingThisMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingThis",
		Description: "Expected 'this' to be used by class method.",
	}
}

func parseOptions(options any) classMethodsUseThisOptions {
	opts := classMethodsUseThisOptions{
		exceptMethods:                       map[string]bool{},
		enforceForClassFields:               true,
		ignoreOverrideMethods:               false,
		ignoreClassesThatImplementInterface: "none",
	}

	parseMap := func(m map[string]interface{}) {
		if m == nil {
			return
		}
		if exceptMethods, ok := m["exceptMethods"].([]interface{}); ok {
			for _, value := range exceptMethods {
				if methodName, ok := value.(string); ok {
					opts.exceptMethods[methodName] = true
				}
			}
		}
		if enforceForClassFields, ok := m["enforceForClassFields"].(bool); ok {
			opts.enforceForClassFields = enforceForClassFields
		}
		if ignoreOverrideMethods, ok := m["ignoreOverrideMethods"].(bool); ok {
			opts.ignoreOverrideMethods = ignoreOverrideMethods
		}
		switch value := m["ignoreClassesThatImplementAnInterface"].(type) {
		case bool:
			if value {
				opts.ignoreClassesThatImplementInterface = "all"
			} else {
				opts.ignoreClassesThatImplementInterface = "none"
			}
		case string:
			if value == "public-fields" {
				opts.ignoreClassesThatImplementInterface = "public-fields"
			}
		}
	}

	switch value := options.(type) {
	case []interface{}:
		if len(value) > 0 {
			if m, ok := value[0].(map[string]interface{}); ok {
				parseMap(m)
			}
		}
	case map[string]interface{}:
		parseMap(value)
	}

	return opts
}

func getMemberName(node *ast.Node) string {
	if node == nil || node.Name() == nil {
		return ""
	}
	nameNode := node.Name()
	switch nameNode.Kind {
	case ast.KindIdentifier:
		return nameNode.AsIdentifier().Text
	case ast.KindPrivateIdentifier:
		privateName := nameNode.AsPrivateIdentifier().Text
		if strings.HasPrefix(privateName, "#") {
			return privateName
		}
		return "#" + privateName
	case ast.KindStringLiteral:
		return nameNode.AsStringLiteral().Text
	case ast.KindNumericLiteral:
		return nameNode.AsNumericLiteral().Text
	case ast.KindComputedPropertyName:
		computed := nameNode.AsComputedPropertyName()
		if computed == nil || computed.Expression == nil {
			return ""
		}
		switch computed.Expression.Kind {
		case ast.KindStringLiteral:
			return computed.Expression.AsStringLiteral().Text
		case ast.KindNumericLiteral:
			return computed.Expression.AsNumericLiteral().Text
		}
	}
	return ""
}

func getMemberBody(node *ast.Node, enforceForClassFields bool) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindMethodDeclaration:
		methodDecl := node.AsMethodDeclaration()
		if methodDecl == nil {
			return nil
		}
		return methodDecl.Body
	case ast.KindGetAccessor:
		getAccessor := node.AsGetAccessorDeclaration()
		if getAccessor == nil {
			return nil
		}
		return getAccessor.Body
	case ast.KindSetAccessor:
		setAccessor := node.AsSetAccessorDeclaration()
		if setAccessor == nil {
			return nil
		}
		return setAccessor.Body
	case ast.KindPropertyDeclaration:
		if !enforceForClassFields {
			return nil
		}
		propertyDecl := node.AsPropertyDeclaration()
		if propertyDecl == nil || propertyDecl.Initializer == nil {
			return nil
		}
		switch propertyDecl.Initializer.Kind {
		case ast.KindArrowFunction:
			arrow := propertyDecl.Initializer.AsArrowFunction()
			if arrow != nil {
				return arrow.Body
			}
		case ast.KindFunctionExpression:
			functionExpr := propertyDecl.Initializer.AsFunctionExpression()
			if functionExpr != nil {
				return functionExpr.Body
			}
		}
	}
	return nil
}

func containsThisOrSuper(node *ast.Node) bool {
	if node == nil {
		return false
	}

	found := false
	var visit func(current *ast.Node)
	visit = func(current *ast.Node) {
		if current == nil || found {
			return
		}
		switch current.Kind {
		case ast.KindThisKeyword, ast.KindSuperKeyword:
			found = true
			return
		case ast.KindFunctionDeclaration,
			ast.KindFunctionExpression,
			ast.KindMethodDeclaration,
			ast.KindConstructor,
			ast.KindGetAccessor,
			ast.KindSetAccessor:
			return
		case ast.KindClassDeclaration, ast.KindClassExpression:
			heritageClauses := utils.GetHeritageClauses(current)
			if heritageClauses != nil {
				for _, heritageClauseNode := range heritageClauses.Nodes {
					heritageClause := heritageClauseNode.AsHeritageClause()
					if heritageClause == nil || heritageClause.Types == nil {
						continue
					}
					for _, heritageType := range heritageClause.Types.Nodes {
						visit(heritageType)
						if found {
							return
						}
					}
				}
			}
			for _, member := range current.Members() {
				if member == nil || member.Name() == nil || member.Name().Kind != ast.KindComputedPropertyName {
					continue
				}
				computedName := member.Name().AsComputedPropertyName()
				if computedName == nil || computedName.Expression == nil {
					continue
				}
				visit(computedName.Expression)
				if found {
					return
				}
			}
			return
		}
		current.ForEachChild(func(child *ast.Node) bool {
			visit(child)
			return found
		})
	}

	visit(node)
	return found
}

func classNode(node *ast.Node) *ast.Node {
	for current := node; current != nil; current = current.Parent {
		if current.Kind == ast.KindClassDeclaration || current.Kind == ast.KindClassExpression {
			return current
		}
	}
	return nil
}

func classImplementsInterface(node *ast.Node) bool {
	heritageClauses := utils.GetHeritageClauses(node)
	if heritageClauses == nil || len(heritageClauses.Nodes) == 0 {
		return false
	}
	for _, heritageClauseNode := range heritageClauses.Nodes {
		heritageClause := heritageClauseNode.AsHeritageClause()
		if heritageClause == nil || heritageClause.Token != ast.KindImplementsKeyword || heritageClause.Types == nil {
			continue
		}
		if len(heritageClause.Types.Nodes) > 0 {
			return true
		}
	}
	return false
}

func isPublicMember(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if name := node.Name(); name != nil && name.Kind == ast.KindPrivateIdentifier {
		return false
	}
	if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected) {
		return false
	}
	return true
}

func shouldIgnoreForImplementsOption(classNode *ast.Node, member *ast.Node, option string) bool {
	if option == "none" || classNode == nil || !classImplementsInterface(classNode) {
		return false
	}
	if option == "all" {
		return true
	}
	if option == "public-fields" {
		return isPublicMember(member)
	}
	return false
}

func keywordStart(sourceFile *ast.SourceFile, node *ast.Node, keyword string, beforePos int) (int, bool) {
	if sourceFile == nil || node == nil {
		return 0, false
	}
	text := sourceFile.Text()
	start := utils.TrimNodeTextRange(sourceFile, node).Pos()
	if beforePos <= start || beforePos > len(text) {
		return 0, false
	}
	segment := text[start:beforePos]
	index := strings.Index(segment, keyword)
	if index < 0 {
		return 0, false
	}
	return start + index, true
}

func reportRangeForMember(sourceFile *ast.SourceFile, node *ast.Node) (core.TextRange, bool) {
	if sourceFile == nil || node == nil {
		return core.NewTextRange(0, 0), false
	}

	switch node.Kind {
	case ast.KindMethodDeclaration:
		methodDecl := node.AsMethodDeclaration()
		name := node.Name()
		if name == nil {
			return core.NewTextRange(0, 0), false
		}
		nameRange := utils.TrimNodeTextRange(sourceFile, name)
		if nameRange.End() <= nameRange.Pos() {
			return core.NewTextRange(0, 0), false
		}
		start := nameRange.Pos()
		end := nameRange.End()
		if name.Kind == ast.KindIdentifier {
			end++
		}
		if methodDecl != nil && methodDecl.AsteriskToken != nil {
			starRange := utils.TrimNodeTextRange(sourceFile, methodDecl.AsteriskToken)
			if starRange.Pos() < start {
				start = starRange.Pos()
			}
		}
		return core.NewTextRange(start, end), true
	case ast.KindGetAccessor:
		name := node.Name()
		if name == nil {
			return core.NewTextRange(0, 0), false
		}
		nameRange := utils.TrimNodeTextRange(sourceFile, name)
		start, ok := keywordStart(sourceFile, node, "get", nameRange.Pos())
		if !ok {
			return core.NewTextRange(0, 0), false
		}
		return core.NewTextRange(start, nameRange.End()), true
	case ast.KindSetAccessor:
		name := node.Name()
		if name == nil {
			return core.NewTextRange(0, 0), false
		}
		nameRange := utils.TrimNodeTextRange(sourceFile, name)
		start, ok := keywordStart(sourceFile, node, "set", nameRange.Pos())
		if !ok {
			return core.NewTextRange(0, 0), false
		}
		return core.NewTextRange(start, nameRange.End()), true
	case ast.KindPropertyDeclaration:
		propertyDecl := node.AsPropertyDeclaration()
		if propertyDecl == nil || propertyDecl.Name() == nil || propertyDecl.Initializer == nil {
			return core.NewTextRange(0, 0), false
		}
		nameRange := utils.TrimNodeTextRange(sourceFile, propertyDecl.Name())
		if nameRange.End() <= nameRange.Pos() {
			return core.NewTextRange(0, 0), false
		}
		switch propertyDecl.Initializer.Kind {
		case ast.KindArrowFunction:
			start := nameRange.Pos()
			end := propertyDecl.Initializer.Pos() + 1
			if end > start {
				return core.NewTextRange(start, end), true
			}
		case ast.KindFunctionExpression:
			functionExpr := propertyDecl.Initializer.AsFunctionExpression()
			if functionExpr != nil && functionExpr.Parameters != nil {
				start := nameRange.Pos()
				end := functionExpr.Parameters.Pos()
				if end > start {
					end--
				}
				if end > start {
					return core.NewTextRange(start, end), true
				}
			}
		}
	}

	return core.NewTextRange(0, 0), false
}

func checkMember(node *ast.Node, ctx rule.RuleContext, opts classMethodsUseThisOptions) {
	if node == nil || ast.IsStatic(node) {
		return
	}

	memberName := getMemberName(node)
	if memberName != "" && opts.exceptMethods[memberName] {
		return
	}
	if opts.ignoreOverrideMethods && ast.HasSyntacticModifier(node, ast.ModifierFlagsOverride) {
		return
	}

	parentClass := classNode(node.Parent)
	if parentClass == nil {
		return
	}
	if shouldIgnoreForImplementsOption(parentClass, node, opts.ignoreClassesThatImplementInterface) {
		return
	}

	body := getMemberBody(node, opts.enforceForClassFields)
	if body == nil {
		return
	}
	if containsThisOrSuper(body) {
		return
	}

	if reportRange, ok := reportRangeForMember(ctx.SourceFile, node); ok {
		ctx.ReportRange(reportRange, buildMissingThisMessage())
		return
	}
	ctx.ReportNode(node, buildMissingThisMessage())
}

var ClassMethodsUseThisRule = rule.CreateRule(rule.Rule{
	Name: "class-methods-use-this",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindMethodDeclaration: func(node *ast.Node) {
				checkMember(node, ctx, opts)
			},
			ast.KindGetAccessor: func(node *ast.Node) {
				checkMember(node, ctx, opts)
			},
			ast.KindSetAccessor: func(node *ast.Node) {
				checkMember(node, ctx, opts)
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				checkMember(node, ctx, opts)
			},
		}
	},
})
