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

func memberName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	if node.Kind == ast.KindPrivateIdentifier {
		return "#" + node.AsPrivateIdentifier().Text
	}
	if node.Kind == ast.KindIdentifier {
		return node.AsIdentifier().Text
	}
	return ""
}

func isPrivateMemberDeclaration(node *ast.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	switch node.Kind {
	case ast.KindPropertyDeclaration:
		decl := node.AsPropertyDeclaration()
		if decl == nil || decl.Name() == nil {
			return "", false
		}
		if decl.Name().Kind == ast.KindPrivateIdentifier || ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) {
			return memberName(decl.Name()), true
		}
	case ast.KindMethodDeclaration:
		decl := node.AsMethodDeclaration()
		if decl == nil || decl.Name() == nil {
			return "", false
		}
		if decl.Name().Kind == ast.KindPrivateIdentifier || ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) {
			return memberName(decl.Name()), true
		}
	case ast.KindGetAccessor, ast.KindSetAccessor:
		if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) {
			return memberName(node.Name()), true
		}
	}
	return "", false
}

func walk(node *ast.Node, visitor func(*ast.Node)) {
	if node == nil {
		return
	}
	visitor(node)
	node.ForEachChild(func(child *ast.Node) bool {
		walk(child, visitor)
		return false
	})
}

func isDeclarationNameNode(node *ast.Node) bool {
	if node == nil || node.Parent == nil {
		return false
	}
	parent := node.Parent
	switch parent.Kind {
	case ast.KindPropertyDeclaration:
		decl := parent.AsPropertyDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindMethodDeclaration:
		decl := parent.AsMethodDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindGetAccessor:
		decl := parent.AsGetAccessorDeclaration()
		return decl != nil && decl.Name() == node
	case ast.KindSetAccessor:
		decl := parent.AsSetAccessorDeclaration()
		return decl != nil && decl.Name() == node
	}
	return false
}

var NoUnusedPrivateClassMembersRule = rule.CreateRule(rule.Rule{
	Name: "no-unused-private-class-members",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindClassDeclaration: func(node *ast.Node) {
				privateMembers := map[string]*ast.Node{}
				used := map[string]bool{}

				walk(node, func(n *ast.Node) {
					if name, ok := isPrivateMemberDeclaration(n); ok && name != "" {
						privateMembers[name] = n
						return
					}
					if n.Kind == ast.KindPrivateIdentifier && !isDeclarationNameNode(n) {
						used["#"+n.AsPrivateIdentifier().Text] = true
						return
					}
					if n.Kind == ast.KindPropertyAccessExpression {
						pa := n.AsPropertyAccessExpression()
						if pa != nil && pa.Name() != nil && pa.Name().Kind == ast.KindIdentifier {
							used[pa.Name().AsIdentifier().Text] = true
						}
					}
				})

				for name, decl := range privateMembers {
					if used[name] {
						continue
					}
					ctx.ReportNode(decl, buildUnusedPrivateClassMemberMessage(name))
				}
			},
		}
	},
})
