package explicit_module_boundary_types

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type ExplicitModuleBoundaryTypesOptions struct {
	AllowArgumentsExplicitlyTypedAsAny bool     `json:"allowArgumentsExplicitlyTypedAsAny"`
	AllowedNames                       []string `json:"allowedNames"`
}

func parseOptions(options any) ExplicitModuleBoundaryTypesOptions {
	opts := ExplicitModuleBoundaryTypesOptions{
		AllowArgumentsExplicitlyTypedAsAny: false,
		AllowedNames:                       []string{},
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
	if v, ok := optsMap["allowArgumentsExplicitlyTypedAsAny"].(bool); ok {
		opts.AllowArgumentsExplicitlyTypedAsAny = v
	}
	if v, ok := optsMap["allowedNames"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				opts.AllowedNames = append(opts.AllowedNames, s)
			}
		}
	}
	return opts
}

func buildMissingReturnTypeMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingReturnType",
		Description: "Missing return type on function.",
	}
}

func buildMissingArgTypeMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingArgType",
		Description: "Argument '" + name + "' should be typed.",
	}
}

func buildAnyTypedArgMessage(name string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "anyTypedArg",
		Description: "Argument '" + name + "' should be typed with a non-any type.",
	}
}

func isAllowedName(name string, allowed []string) bool {
	for _, n := range allowed {
		if n == name {
			return true
		}
	}
	return false
}

func checkParameters(ctx rule.RuleContext, params []*ast.Node, opts ExplicitModuleBoundaryTypesOptions) {
	for _, p := range params {
		if p == nil || !ast.IsParameter(p) {
			continue
		}
		param := p.AsParameterDeclaration()
		if param == nil || param.Name() == nil || param.Name().Kind != ast.KindIdentifier {
			continue
		}
		name := param.Name().AsIdentifier().Text
		if param.Type == nil {
			ctx.ReportNode(p, buildMissingArgTypeMessage(name))
			continue
		}
		if !opts.AllowArgumentsExplicitlyTypedAsAny && param.Type.Kind == ast.KindAnyKeyword {
			ctx.ReportNode(p, buildAnyTypedArgMessage(name))
		}
	}
}

func isExportedFunction(node *ast.Node) bool {
	return ast.HasSyntacticModifier(node, ast.ModifierFlagsExport) || ast.HasSyntacticModifier(node, ast.ModifierFlagsDefault)
}

var ExplicitModuleBoundaryTypesRule = rule.CreateRule(rule.Rule{
	Name: "explicit-module-boundary-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		return rule.RuleListeners{
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				fn := node.AsFunctionDeclaration()
				if fn == nil || fn.Name() == nil || !isExportedFunction(node) {
					return
				}
				name := fn.Name().Text()
				if isAllowedName(name, opts.AllowedNames) {
					return
				}
				if fn.Type == nil {
					ctx.ReportNode(node, buildMissingReturnTypeMessage())
				}
				if fn.Parameters != nil {
					checkParameters(ctx, fn.Parameters.Nodes, opts)
				}
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				method := node.AsMethodDeclaration()
				if method == nil || method.Name() == nil {
					return
				}
				if ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate) {
					return
				}
				if node.Parent == nil || node.Parent.Parent == nil || !ast.IsClassLike(node.Parent.Parent) {
					return
				}
				classNode := node.Parent.Parent
				if !isExportedFunction(classNode) {
					return
				}
				if method.Type == nil {
					ctx.ReportNode(node, buildMissingReturnTypeMessage())
				}
				if method.Parameters != nil {
					checkParameters(ctx, method.Parameters.Nodes, opts)
				}
			},
			ast.KindArrowFunction: func(node *ast.Node) {
				arrow := node.AsArrowFunction()
				if arrow == nil || arrow.Parent == nil {
					return
				}
				if arrow.Parent.Kind != ast.KindVariableDeclaration {
					return
				}
				decl := arrow.Parent.AsVariableDeclaration()
				if decl == nil || decl.Name() == nil || decl.Name().Kind != ast.KindIdentifier {
					return
				}
				name := decl.Name().AsIdentifier().Text
				if !isAllowedName(name, opts.AllowedNames) {
					if decl.Parent != nil && decl.Parent.Parent != nil && decl.Parent.Parent.Parent != nil && decl.Parent.Parent.Parent.Kind == ast.KindVariableStatement {
						stmt := decl.Parent.Parent.Parent
						if isExportedFunction(stmt) && arrow.Type == nil {
							ctx.ReportNode(node, buildMissingReturnTypeMessage())
						}
					}
				}
				if arrow.Parameters != nil {
					checkParameters(ctx, arrow.Parameters.Nodes, opts)
				}
			},
		}
	},
})
