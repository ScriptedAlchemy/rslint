package class_methods_use_this

import (
	"github.com/microsoft/typescript-go/shim/ast"
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
		return "#" + nameNode.AsPrivateIdentifier().Text
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
			ast.KindSetAccessor,
			ast.KindClassDeclaration,
			ast.KindClassExpression:
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
