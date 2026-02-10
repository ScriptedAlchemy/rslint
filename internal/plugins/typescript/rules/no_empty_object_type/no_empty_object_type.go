package no_empty_object_type

import (
	"regexp"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type noEmptyObjectTypeOptions struct {
	AllowInterfaces  string
	AllowObjectTypes string
	AllowWithName    *regexp.Regexp
}

func parseOptions(options any) noEmptyObjectTypeOptions {
	opts := noEmptyObjectTypeOptions{
		AllowInterfaces:  "never",
		AllowObjectTypes: "never",
		AllowWithName:    nil,
	}
	if options == nil {
		return opts
	}
	var m map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			m = first
		}
	} else if direct, ok := options.(map[string]interface{}); ok {
		m = direct
	}
	if m == nil {
		return opts
	}

	if v, ok := m["allowInterfaces"].(string); ok {
		opts.AllowInterfaces = v
	}
	if v, ok := m["allowObjectTypes"].(string); ok {
		opts.AllowObjectTypes = v
	}
	if v, ok := m["allowWithName"].(string); ok && v != "" {
		if re, err := regexp.Compile(v); err == nil {
			opts.AllowWithName = re
		}
	}
	return opts
}

func matchesAllowedName(re *regexp.Regexp, nameNode *ast.Node) bool {
	if re == nil || nameNode == nil || nameNode.Kind != ast.KindIdentifier {
		return false
	}
	return re.MatchString(nameNode.AsIdentifier().Text)
}

func countExtendsClauses(interfaceDecl *ast.InterfaceDeclaration) int {
	if interfaceDecl == nil || interfaceDecl.HeritageClauses == nil {
		return 0
	}
	for _, clauseNode := range interfaceDecl.HeritageClauses.Nodes {
		clause := clauseNode.AsHeritageClause()
		if clause == nil || clause.Token != ast.KindExtendsKeyword || clause.Types == nil {
			continue
		}
		return len(clause.Types.Nodes)
	}
	return 0
}

var NoEmptyObjectTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-empty-object-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				interfaceDecl := node.AsInterfaceDeclaration()
				if interfaceDecl == nil || interfaceDecl.Members == nil || len(interfaceDecl.Members.Nodes) != 0 {
					return
				}
				if opts.AllowInterfaces == "always" {
					return
				}
				if matchesAllowedName(opts.AllowWithName, interfaceDecl.Name()) {
					return
				}

				extendsCount := countExtendsClauses(interfaceDecl)
				if opts.AllowInterfaces == "with-single-extends" && extendsCount == 1 {
					return
				}

				msg := rule.RuleMessage{
					Id:          "noEmptyInterface",
					Description: "An empty interface is equivalent to `{}`.",
				}
				if extendsCount > 0 {
					msg = rule.RuleMessage{
						Id:          "noEmptyInterfaceWithSuper",
						Description: "An interface declaring no members is equivalent to its supertype.",
					}
				}
				ctx.ReportNode(interfaceDecl.Name(), msg)
			},
			ast.KindTypeLiteral: func(node *ast.Node) {
				typeLiteral := node.AsTypeLiteralNode()
				if typeLiteral == nil || typeLiteral.Members == nil || len(typeLiteral.Members.Nodes) != 0 {
					return
				}
				if opts.AllowObjectTypes == "always" {
					return
				}

				// Allow named aliases configured by allowWithName.
				if node.Parent != nil && node.Parent.Kind == ast.KindTypeAliasDeclaration {
					if matchesAllowedName(opts.AllowWithName, node.Parent.Name()) {
						return
					}
				}

				ctx.ReportNode(node, rule.RuleMessage{
					Id:          "noEmptyObject",
					Description: "The `{}` (\"empty object\") type allows any non-nullish value.",
				})
			},
		}
	},
})
