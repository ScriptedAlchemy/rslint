package no_restricted_imports

import (
	"path/filepath"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type restrictedPath struct {
	Name             string
	Message          string
	AllowTypeImports bool
}

type restrictedPattern struct {
	Group            []string
	Message          string
	AllowTypeImports bool
}

type NoRestrictedImportsOptions struct {
	Paths    []restrictedPath
	Patterns []restrictedPattern
}

func parseOptions(options any) NoRestrictedImportsOptions {
	opts := NoRestrictedImportsOptions{
		Paths:    []restrictedPath{},
		Patterns: []restrictedPattern{},
	}
	if options == nil {
		return opts
	}
	if arr, ok := options.([]interface{}); ok && len(arr) > 0 {
		// string shorthand
		allStrings := true
		for _, item := range arr {
			if s, ok := item.(string); ok {
				opts.Paths = append(opts.Paths, restrictedPath{Name: s})
			} else {
				allStrings = false
				break
			}
		}
		if allStrings {
			return opts
		}

		optsMap, _ := arr[0].(map[string]interface{})
		if optsMap == nil {
			return opts
		}
		if paths, ok := optsMap["paths"].([]interface{}); ok {
			for _, item := range paths {
				switch v := item.(type) {
				case string:
					opts.Paths = append(opts.Paths, restrictedPath{Name: v})
				case map[string]interface{}:
					p := restrictedPath{}
					if s, ok := v["name"].(string); ok {
						p.Name = s
					}
					if s, ok := v["message"].(string); ok {
						p.Message = s
					}
					if b, ok := v["allowTypeImports"].(bool); ok {
						p.AllowTypeImports = b
					}
					if p.Name != "" {
						opts.Paths = append(opts.Paths, p)
					}
				}
			}
		}
		if patterns, ok := optsMap["patterns"].([]interface{}); ok {
			for _, item := range patterns {
				switch v := item.(type) {
				case string:
					opts.Patterns = append(opts.Patterns, restrictedPattern{Group: []string{v}})
				case map[string]interface{}:
					p := restrictedPattern{Group: []string{}}
					if s, ok := v["message"].(string); ok {
						p.Message = s
					}
					if b, ok := v["allowTypeImports"].(bool); ok {
						p.AllowTypeImports = b
					}
					if group, ok := v["group"].([]interface{}); ok {
						for _, g := range group {
							if gs, ok := g.(string); ok {
								p.Group = append(p.Group, gs)
							}
						}
					}
					if len(p.Group) > 0 {
						opts.Patterns = append(opts.Patterns, p)
					}
				}
			}
		}
	}
	return opts
}

func buildPathMessage(path, extra string) rule.RuleMessage {
	msg := "'" + path + "' import is restricted from being used."
	if extra != "" {
		msg += " " + extra
	}
	return rule.RuleMessage{Id: "path", Description: msg}
}

func buildPatternMessage(path, extra string) rule.RuleMessage {
	msg := "'" + path + "' import is restricted from being used by a pattern."
	if extra != "" {
		msg += " " + extra
	}
	return rule.RuleMessage{Id: "patterns", Description: msg}
}

func getModuleSpecifier(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case ast.KindImportDeclaration:
		decl := node.AsImportDeclaration()
		if decl != nil {
			return decl.ModuleSpecifier
		}
	case ast.KindExportDeclaration:
		decl := node.AsExportDeclaration()
		if decl != nil {
			return decl.ModuleSpecifier
		}
	case ast.KindImportEqualsDeclaration:
		decl := node.AsImportEqualsDeclaration()
		if decl != nil && decl.ModuleReference != nil && decl.ModuleReference.Kind == ast.KindExternalModuleReference {
			ref := decl.ModuleReference.AsExternalModuleReference()
			if ref != nil {
				return ref.Expression
			}
		}
	}
	return nil
}

func isTypeOnly(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindImportDeclaration:
		decl := node.AsImportDeclaration()
		return decl != nil && decl.ImportClause != nil && decl.ImportClause.IsTypeOnly()
	case ast.KindExportDeclaration:
		decl := node.AsExportDeclaration()
		return decl != nil && decl.IsTypeOnly
	case ast.KindImportEqualsDeclaration:
		decl := node.AsImportEqualsDeclaration()
		return decl != nil && decl.IsTypeOnly
	}
	return false
}

func matchPattern(value, pattern string) bool {
	negated := strings.HasPrefix(pattern, "!")
	if negated {
		pattern = strings.TrimPrefix(pattern, "!")
	}
	ok, _ := filepath.Match(pattern, value)
	if negated {
		return !ok
	}
	return ok
}

func literalValue(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindStringLiteral {
		return ""
	}
	return node.AsStringLiteral().Text
}

var NoRestrictedImportsRule = rule.CreateRule(rule.Rule{
	Name: "no-restricted-imports",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		check := func(node *ast.Node) {
			moduleSpecifier := getModuleSpecifier(node)
			path := literalValue(moduleSpecifier)
			if path == "" {
				return
			}
			typeOnly := isTypeOnly(node)

			for _, restricted := range opts.Paths {
				if restricted.Name != path {
					continue
				}
				if restricted.AllowTypeImports && typeOnly {
					return
				}
				ctx.ReportNode(moduleSpecifier, buildPathMessage(path, restricted.Message))
				return
			}

			for _, restricted := range opts.Patterns {
				if restricted.AllowTypeImports && typeOnly {
					continue
				}
				for _, pattern := range restricted.Group {
					if matchPattern(path, pattern) {
						ctx.ReportNode(moduleSpecifier, buildPatternMessage(path, restricted.Message))
						return
					}
				}
			}
		}

		return rule.RuleListeners{
			ast.KindImportDeclaration:       check,
			ast.KindExportDeclaration:       check,
			ast.KindImportEqualsDeclaration: check,
		}
	},
})
