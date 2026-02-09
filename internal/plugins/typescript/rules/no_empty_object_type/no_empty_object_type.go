package no_empty_object_type

import (
	"regexp"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type NoEmptyObjectTypeOptions struct {
	AllowInterfaces  string `json:"allowInterfaces"`
	AllowObjectTypes string `json:"allowObjectTypes"`
	AllowWithName    string `json:"allowWithName"`
}

func parseOptions(options any) NoEmptyObjectTypeOptions {
	opts := NoEmptyObjectTypeOptions{
		AllowInterfaces:  "never",
		AllowObjectTypes: "never",
		AllowWithName:    "",
	}

	if options == nil {
		return opts
	}

	var optsMap map[string]interface{}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		optsMap, _ = arr[0].(map[string]interface{})
	} else {
		optsMap, _ = options.(map[string]interface{})
	}

	if optsMap == nil {
		return opts
	}

	if v, ok := optsMap["allowInterfaces"].(string); ok {
		opts.AllowInterfaces = v
	}
	if v, ok := optsMap["allowObjectTypes"].(string); ok {
		opts.AllowObjectTypes = v
	}
	if v, ok := optsMap["allowWithName"].(string); ok {
		opts.AllowWithName = v
	}

	return opts
}

func buildNoEmptyInterfaceMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noEmptyInterface",
		Description: "An empty interface declaration allows any non-nullish value.",
	}
}

func buildNoEmptyInterfaceWithSuperMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noEmptyInterfaceWithSuper",
		Description: "An interface declaring no members is equivalent to its supertype.",
	}
}

func buildNoEmptyObjectMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "noEmptyObject",
		Description: "The `{}` (\"empty object\") type allows any non-nullish value.",
	}
}

func buildReplaceEmptyInterfaceMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "replaceEmptyInterface",
		Description: "Replace empty interface.",
	}
}

func buildReplaceEmptyInterfaceWithSuperMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "replaceEmptyInterfaceWithSuper",
		Description: "Replace empty interface with a type alias.",
	}
}

func buildReplaceEmptyObjectTypeMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "replaceEmptyObjectType",
		Description: "Replace `{}` type.",
	}
}

func getAllowNameRegex(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return r
}

func interfaceName(interfaceDecl *ast.InterfaceDeclaration) string {
	if interfaceDecl == nil || interfaceDecl.Name() == nil || interfaceDecl.Name().Kind != ast.KindIdentifier {
		return ""
	}
	return interfaceDecl.Name().AsIdentifier().Text
}

func hasMergedClassDeclaration(typeChecker *ast.Symbol, name string) bool {
	if typeChecker == nil || len(typeChecker.Declarations) == 0 {
		return false
	}
	for _, decl := range typeChecker.Declarations {
		if decl.Kind == ast.KindClassDeclaration {
			return true
		}
	}
	return false
}

func getExtendsTypes(node *ast.InterfaceDeclaration) []*ast.Node {
	if node == nil || node.HeritageClauses == nil {
		return nil
	}
	for _, clause := range node.HeritageClauses.Nodes {
		h := clause.AsHeritageClause()
		if h != nil && h.Token == ast.KindExtendsKeyword && h.Types != nil {
			return h.Types.Nodes
		}
	}
	return nil
}

func getTypeParametersText(sourceFile *ast.SourceFile, typeParams *ast.NodeList) string {
	if typeParams == nil || len(typeParams.Nodes) == 0 {
		return ""
	}
	first := typeParams.Nodes[0]
	last := typeParams.Nodes[len(typeParams.Nodes)-1]
	r := utils.TrimNodeTextRange(sourceFile, first).WithEnd(utils.TrimNodeTextRange(sourceFile, last).End())
	return sourceFile.Text()[r.Pos()-1 : r.End()+1]
}

func getNodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	r := utils.TrimNodeTextRange(sourceFile, node)
	return sourceFile.Text()[r.Pos():r.End()]
}

var NoEmptyObjectTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-empty-object-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		allowNameRe := getAllowNameRegex(opts.AllowWithName)

		return rule.RuleListeners{
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				if opts.AllowInterfaces == "always" {
					return
				}

				interfaceDecl := node.AsInterfaceDeclaration()
				if interfaceDecl == nil || interfaceDecl.Members == nil || len(interfaceDecl.Members.Nodes) > 0 {
					return
				}

				name := interfaceName(interfaceDecl)
				if allowNameRe != nil && allowNameRe.MatchString(name) {
					return
				}

				extendsTypes := getExtendsTypes(interfaceDecl)
				extendsCount := len(extendsTypes)
				if extendsCount > 1 {
					return
				}
				if extendsCount == 1 && opts.AllowInterfaces == "with-single-extends" {
					return
				}

				if extendsCount == 0 {
					ctx.ReportNode(interfaceDecl.Name(), buildNoEmptyInterfaceMessage())
					return
				}

				ctx.ReportNode(interfaceDecl.Name(), buildNoEmptyInterfaceWithSuperMessage())
			},

			ast.KindTypeLiteral: func(node *ast.Node) {
				if opts.AllowObjectTypes == "always" {
					return
				}

				typeLiteral := node.AsTypeLiteralNode()
				if typeLiteral == nil || typeLiteral.Members == nil || len(typeLiteral.Members.Nodes) > 0 {
					return
				}

				if node.Parent != nil && node.Parent.Kind == ast.KindIntersectionType {
					return
				}

				if allowNameRe != nil && node.Parent != nil && node.Parent.Kind == ast.KindTypeAliasDeclaration {
					typeAlias := node.Parent.AsTypeAliasDeclaration()
					if typeAlias != nil && typeAlias.Name() != nil && typeAlias.Name().Kind == ast.KindIdentifier {
						if allowNameRe.MatchString(typeAlias.Name().AsIdentifier().Text) {
							return
						}
					}
				}

				ctx.ReportNode(node, buildNoEmptyObjectMessage())
			},
		}
	},
})
