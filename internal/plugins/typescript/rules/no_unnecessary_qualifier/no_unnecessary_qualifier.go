package no_unnecessary_qualifier

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryQualifierMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryQualifier",
		Description: "Qualifier is unnecessary since it can be removed.",
	}
}

type namespaceScope struct {
	name         string
	declarations map[string]bool
}

type enumScope struct {
	name    string
	members map[string]bool
}

func declarationName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindVariableDeclaration:
		v := node.AsVariableDeclaration()
		if v != nil && v.Name() != nil && v.Name().Kind == ast.KindIdentifier {
			return v.Name().AsIdentifier().Text
		}
	case ast.KindFunctionDeclaration:
		v := node.AsFunctionDeclaration()
		if v != nil && v.Name() != nil {
			return v.Name().Text()
		}
	case ast.KindClassDeclaration:
		v := node.AsClassDeclaration()
		if v != nil && v.Name() != nil {
			return v.Name().Text()
		}
	case ast.KindInterfaceDeclaration:
		v := node.AsInterfaceDeclaration()
		if v != nil && v.Name() != nil {
			return v.Name().Text()
		}
	case ast.KindTypeAliasDeclaration:
		v := node.AsTypeAliasDeclaration()
		if v != nil && v.Name() != nil {
			return v.Name().Text()
		}
	case ast.KindEnumDeclaration:
		v := node.AsEnumDeclaration()
		if v != nil && v.Name() != nil {
			return v.Name().Text()
		}
	case ast.KindModuleDeclaration:
		v := node.AsModuleDeclaration()
		if v != nil && v.Name() != nil && v.Name().Kind == ast.KindIdentifier {
			return v.Name().AsIdentifier().Text
		}
	}
	return ""
}

func qualifierChainFromQualifiedName(node *ast.Node) ([]string, string) {
	if node == nil || node.Kind != ast.KindQualifiedName {
		return nil, ""
	}
	q := node.AsQualifiedName()
	if q == nil || q.Left == nil || q.Right == nil {
		return nil, ""
	}

	chain := []string{}
	var walkLeft func(*ast.Node)
	walkLeft = func(n *ast.Node) {
		if n == nil {
			return
		}
		if n.Kind == ast.KindIdentifier {
			chain = append(chain, n.AsIdentifier().Text)
			return
		}
		if n.Kind == ast.KindQualifiedName {
			nq := n.AsQualifiedName()
			if nq == nil {
				return
			}
			walkLeft(nq.Left)
			if nq.Right != nil {
				chain = append(chain, nq.Right.Text())
			}
		}
	}
	walkLeft(q.Left)
	return chain, q.Right.Text()
}

func qualifierChainFromPropertyAccess(node *ast.Node) ([]string, string) {
	if node == nil || node.Kind != ast.KindPropertyAccessExpression {
		return nil, ""
	}
	pa := node.AsPropertyAccessExpression()
	if pa == nil || pa.Expression == nil || pa.Name() == nil {
		return nil, ""
	}
	chain := []string{}
	current := pa.Expression
	for current != nil {
		if current.Kind == ast.KindIdentifier {
			chain = append([]string{current.AsIdentifier().Text}, chain...)
			break
		}
		if current.Kind != ast.KindPropertyAccessExpression {
			return nil, ""
		}
		next := current.AsPropertyAccessExpression()
		if next == nil || next.Name() == nil {
			return nil, ""
		}
		chain = append([]string{next.Name().Text()}, chain...)
		current = next.Expression
	}
	return chain, pa.Name().Text()
}

func isPrefix(path []string, qualifier []string) bool {
	if len(qualifier) == 0 || len(qualifier) > len(path) {
		return false
	}
	for i := range qualifier {
		if path[i] != qualifier[i] {
			return false
		}
	}
	return true
}

var NoUnnecessaryQualifierRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-qualifier",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		namespaceStack := []*namespaceScope{}
		enumStack := []*enumScope{}
		moduleAugmentationStack := []string{}
		namespaceImportAliases := map[string]string{}
		addDeclarationToCurrentNamespace := func(name string) {
			if name == "" || len(namespaceStack) == 0 {
				return
			}
			namespaceStack[len(namespaceStack)-1].declarations[name] = true
		}

		currentPath := func() []string {
			out := make([]string, 0, len(namespaceStack))
			for _, ns := range namespaceStack {
				out = append(out, ns.name)
			}
			return out
		}

		shouldReport := func(qualifier []string, finalName string) bool {
			if len(moduleAugmentationStack) > 0 && len(qualifier) > 0 {
				if moduleName, ok := namespaceImportAliases[qualifier[0]]; ok && moduleName == moduleAugmentationStack[len(moduleAugmentationStack)-1] {
					return true
				}
			}

			if len(enumStack) > 0 {
				currentEnum := enumStack[len(enumStack)-1]
				if currentEnum.members[finalName] {
					if len(qualifier) == 1 && qualifier[0] == currentEnum.name {
						return true
					}
					if len(qualifier) == len(namespaceStack)+1 {
						path := currentPath()
						allMatch := true
						for i := range path {
							if qualifier[i] != path[i] {
								allMatch = false
								break
							}
						}
						if allMatch && qualifier[len(qualifier)-1] == currentEnum.name {
							return true
						}
					}
				}
			}

			if len(namespaceStack) == 0 || finalName == "" {
				return false
			}
			path := currentPath()
			if !isPrefix(path, qualifier) {
				return false
			}
			targetDepth := len(qualifier) - 1
			if targetDepth < 0 || targetDepth >= len(namespaceStack) {
				return false
			}
			if !namespaceStack[targetDepth].declarations[finalName] {
				return false
			}
			// If the same name is redeclared in a nested namespace, the qualifier is necessary.
			for i := targetDepth + 1; i < len(namespaceStack); i++ {
				if namespaceStack[i].declarations[finalName] {
					return false
				}
			}
			return true
		}

		listeners := rule.RuleListeners{
			ast.KindImportDeclaration: func(node *ast.Node) {
				importDecl := node.AsImportDeclaration()
				if importDecl == nil || importDecl.ImportClause == nil || importDecl.ModuleSpecifier == nil || importDecl.ModuleSpecifier.Kind != ast.KindStringLiteral {
					return
				}
				importClause := importDecl.ImportClause.AsImportClause()
				if importClause == nil || importClause.NamedBindings == nil || importClause.NamedBindings.Kind != ast.KindNamespaceImport {
					return
				}
				namespaceImport := importClause.NamedBindings.AsNamespaceImport()
				if namespaceImport == nil || namespaceImport.Name() == nil {
					return
				}
				namespaceImportAliases[namespaceImport.Name().Text()] = importDecl.ModuleSpecifier.AsStringLiteral().Text
			},
			ast.KindModuleDeclaration: func(node *ast.Node) {
				mod := node.AsModuleDeclaration()
				if mod == nil || mod.Name() == nil {
					return
				}
				if mod.Name().Kind == ast.KindStringLiteral {
					moduleAugmentationStack = append(moduleAugmentationStack, mod.Name().AsStringLiteral().Text)
					return
				}
				if mod.Keyword != ast.KindNamespaceKeyword || mod.Name().Kind != ast.KindIdentifier {
					return
				}
				name := mod.Name().AsIdentifier().Text
				addDeclarationToCurrentNamespace(name)
				namespaceStack = append(namespaceStack, &namespaceScope{
					name:         name,
					declarations: map[string]bool{},
				})
			},
			rule.ListenerOnExit(ast.KindModuleDeclaration): func(node *ast.Node) {
				mod := node.AsModuleDeclaration()
				if mod == nil || mod.Name() == nil {
					return
				}
				if mod.Name().Kind == ast.KindStringLiteral {
					if len(moduleAugmentationStack) > 0 {
						moduleAugmentationStack = moduleAugmentationStack[:len(moduleAugmentationStack)-1]
					}
					return
				}
				if mod.Keyword != ast.KindNamespaceKeyword || mod.Name().Kind != ast.KindIdentifier {
					return
				}
				if len(namespaceStack) > 0 {
					namespaceStack = namespaceStack[:len(namespaceStack)-1]
				}
			},
			ast.KindEnumDeclaration: func(node *ast.Node) {
				enumDecl := node.AsEnumDeclaration()
				if enumDecl == nil || enumDecl.Name() == nil {
					return
				}
				scope := &enumScope{name: enumDecl.Name().Text(), members: map[string]bool{}}
				if enumDecl.Members != nil {
					for _, memberNode := range enumDecl.Members.Nodes {
						member := memberNode.AsEnumMember()
						if member == nil || member.Name() == nil {
							continue
						}
						if member.Name().Kind == ast.KindIdentifier {
							scope.members[member.Name().AsIdentifier().Text] = true
						}
					}
				}
				enumStack = append(enumStack, scope)
				addDeclarationToCurrentNamespace(enumDecl.Name().Text())
			},
			rule.ListenerOnExit(ast.KindEnumDeclaration): func(node *ast.Node) {
				if len(enumStack) > 0 {
					enumStack = enumStack[:len(enumStack)-1]
				}
			},
			ast.KindVariableDeclaration: func(node *ast.Node) {
				addDeclarationToCurrentNamespace(declarationName(node))
			},
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				addDeclarationToCurrentNamespace(declarationName(node))
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				addDeclarationToCurrentNamespace(declarationName(node))
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				addDeclarationToCurrentNamespace(declarationName(node))
			},
			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				addDeclarationToCurrentNamespace(declarationName(node))
			},
			ast.KindQualifiedName: func(node *ast.Node) {
				if node.Parent != nil && node.Parent.Kind == ast.KindQualifiedName {
					return
				}
				qualifier, finalName := qualifierChainFromQualifiedName(node)
				if shouldReport(qualifier, finalName) {
					ctx.ReportNode(node, buildUnnecessaryQualifierMessage())
				}
			},
			ast.KindPropertyAccessExpression: func(node *ast.Node) {
				if node.Parent != nil && node.Parent.Kind == ast.KindPropertyAccessExpression {
					return
				}
				qualifier, finalName := qualifierChainFromPropertyAccess(node)
				if shouldReport(qualifier, finalName) {
					ctx.ReportNode(node, buildUnnecessaryQualifierMessage())
				}
			},
		}
		return listeners
	},
})
