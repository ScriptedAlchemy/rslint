package no_dupe_class_members

import (
	"fmt"
	"strconv"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type memberKind uint8

const (
	memberKindMethod memberKind = iota
	memberKindProperty
	memberKindGetter
	memberKindSetter
)

type memberState struct {
	hasMethod   bool
	hasProperty bool
	hasGetter   bool
	hasSetter   bool
}

func buildDuplicateMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpected",
		Description: fmt.Sprintf("Duplicate name %q.", name),
	}
}

func parseNumericName(text string) string {
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return text
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func getMemberName(nameNode *ast.Node) (string, bool) {
	if nameNode == nil {
		return "", false
	}

	switch nameNode.Kind {
	case ast.KindIdentifier:
		return nameNode.AsIdentifier().Text, true
	case ast.KindPrivateIdentifier:
		return "#" + nameNode.AsPrivateIdentifier().Text, true
	case ast.KindStringLiteral:
		return nameNode.AsStringLiteral().Text, true
	case ast.KindNumericLiteral:
		return parseNumericName(nameNode.AsNumericLiteral().Text), true
	case ast.KindComputedPropertyName:
		expr := nameNode.AsComputedPropertyName().Expression
		if expr == nil {
			return "", false
		}
		switch expr.Kind {
		case ast.KindStringLiteral:
			return expr.AsStringLiteral().Text, true
		case ast.KindNoSubstitutionTemplateLiteral:
			return expr.AsNoSubstitutionTemplateLiteral().Text, true
		case ast.KindNumericLiteral:
			return parseNumericName(expr.AsNumericLiteral().Text), true
		default:
			return "", false
		}
	}

	return "", false
}

func memberKindFromNode(node *ast.Node) (memberKind, bool) {
	switch node.Kind {
	case ast.KindMethodDeclaration:
		return memberKindMethod, true
	case ast.KindPropertyDeclaration:
		return memberKindProperty, true
	case ast.KindGetAccessor:
		return memberKindGetter, true
	case ast.KindSetAccessor:
		return memberKindSetter, true
	default:
		return memberKindMethod, false
	}
}

func shouldSkipOverloadSignature(member *ast.Node) bool {
	if member.Kind != ast.KindMethodDeclaration {
		return false
	}
	method := member.AsMethodDeclaration()
	return method != nil && method.Body == nil
}

func reportDuplicate(ctx rule.RuleContext, node *ast.Node, name string) {
	ctx.ReportNode(node, buildDuplicateMessage(name))
}

func checkClassMembers(ctx rule.RuleContext, members []*ast.Node) {
	seen := make(map[string]*memberState)

	for _, member := range members {
		if member == nil {
			continue
		}

		if shouldSkipOverloadSignature(member) {
			continue
		}

		nameNode := member.Name()
		name, ok := getMemberName(nameNode)
		if !ok {
			continue
		}

		kind, ok := memberKindFromNode(member)
		if !ok {
			continue
		}

		isStatic := ast.HasSyntacticModifier(member, ast.ModifierFlagsStatic)
		key := fmt.Sprintf("%t:%s", isStatic, name)

		state, exists := seen[key]
		if !exists {
			state = &memberState{}
			seen[key] = state
		}

		duplicate := false
		switch kind {
		case memberKindMethod:
			duplicate = state.hasMethod || state.hasProperty || state.hasGetter || state.hasSetter
			state.hasMethod = true
		case memberKindProperty:
			duplicate = state.hasMethod || state.hasProperty || state.hasGetter || state.hasSetter
			state.hasProperty = true
		case memberKindGetter:
			duplicate = state.hasGetter || state.hasMethod || state.hasProperty
			state.hasGetter = true
		case memberKindSetter:
			duplicate = state.hasSetter || state.hasMethod || state.hasProperty
			state.hasSetter = true
		}

		if duplicate {
			reportDuplicate(ctx, member, name)
		}
	}
}

var NoDupeClassMembersRule = rule.CreateRule(rule.Rule{
	Name: "no-dupe-class-members",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindClassDeclaration: func(node *ast.Node) {
				classDecl := node.AsClassDeclaration()
				if classDecl == nil || classDecl.Members == nil {
					return
				}
				checkClassMembers(ctx, classDecl.Members.Nodes)
			},
			ast.KindClassExpression: func(node *ast.Node) {
				classExpr := node.AsClassExpression()
				if classExpr == nil || classExpr.Members == nil {
					return
				}
				checkClassMembers(ctx, classExpr.Members.Nodes)
			},
		}
	},
})
