package naming_convention

import (
	"regexp"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

var camelCaseRe = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
var pascalCaseRe = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`)

func buildDoesNotMatchFormatMessage(name string, format string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "doesNotMatchFormat",
		Description: "Identifier '" + name + "' does not match the expected " + format + " format.",
	}
}

func variableName(node *ast.Node) string {
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
	case ast.KindPropertyDeclaration:
		v := node.AsPropertyDeclaration()
		if v != nil && v.Name() != nil && v.Name().Kind == ast.KindIdentifier {
			return v.Name().AsIdentifier().Text
		}
	}
	return ""
}

func typeName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
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
	}
	return ""
}

var NamingConventionRule = rule.CreateRule(rule.Rule{
	Name: "naming-convention",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindVariableDeclaration: func(node *ast.Node) {
				name := variableName(node)
				if name == "" || camelCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "camelCase"))
			},
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				name := variableName(node)
				if name == "" || camelCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "camelCase"))
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				name := variableName(node)
				if name == "" || camelCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "camelCase"))
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				name := typeName(node)
				if name == "" || pascalCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "PascalCase"))
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				name := typeName(node)
				if name == "" || pascalCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "PascalCase"))
			},
			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				name := typeName(node)
				if name == "" || pascalCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "PascalCase"))
			},
			ast.KindEnumDeclaration: func(node *ast.Node) {
				name := typeName(node)
				if name == "" || pascalCaseRe.MatchString(name) {
					return
				}
				ctx.ReportNode(node, buildDoesNotMatchFormatMessage(name, "PascalCase"))
			},
		}
	},
})
