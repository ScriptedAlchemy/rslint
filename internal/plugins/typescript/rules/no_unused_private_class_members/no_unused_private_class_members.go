package no_unused_private_class_members

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnusedPrivateClassMemberMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unusedPrivateClassMember",
		Description: "Private class member '" + name + "' is declared but never used.",
	}
}

func classMembers(classNode *ast.Node) []*ast.Node {
	if classNode == nil {
		return nil
	}
	switch classNode.Kind {
	case ast.KindClassDeclaration:
		classDecl := classNode.AsClassDeclaration()
		if classDecl != nil && classDecl.Members != nil {
			return classDecl.Members.Nodes
		}
	case ast.KindClassExpression:
		classExpr := classNode.AsClassExpression()
		if classExpr != nil && classExpr.Members != nil {
			return classExpr.Members.Nodes
		}
	}
	return nil
}

var NoUnusedPrivateClassMembersRule = rule.CreateRule(rule.Rule{
	Name: "no-unused-private-class-members",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		checkClass := func(node *ast.Node) {
			declarations := map[string]*ast.Node{}
			for _, member := range classMembers(node) {
				if member == nil {
					continue
				}
				name := member.Name()
				if name == nil || name.Kind != ast.KindPrivateIdentifier {
					continue
				}
				declarations[name.AsPrivateIdentifier().Text] = name
			}
			if len(declarations) == 0 {
				return
			}

			referenceCounts := map[string]int{}
			var visit func(*ast.Node)
			visit = func(current *ast.Node) {
				if current == nil {
					return
				}
				if (current.Kind == ast.KindClassDeclaration || current.Kind == ast.KindClassExpression) && current != node {
					return
				}
				if current.Kind == ast.KindPrivateIdentifier {
					text := current.AsPrivateIdentifier().Text
					if _, tracked := declarations[text]; tracked {
						referenceCounts[text]++
					}
				}
				current.ForEachChild(func(child *ast.Node) bool {
					visit(child)
					return false
				})
			}
			visit(node)

			for name, decl := range declarations {
				// Declaration occurrence counts as one reference; anything more means used.
				if referenceCounts[name] <= 1 {
					ctx.ReportNode(decl, buildUnusedPrivateClassMemberMessage(name))
				}
			}
		}

		return rule.RuleListeners{
			ast.KindClassDeclaration: checkClass,
			ast.KindClassExpression:  checkClass,
		}
	},
})
