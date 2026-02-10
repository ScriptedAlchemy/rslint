package no_restricted_imports

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type restrictedPath struct {
	Name             string
	Message          string
	ImportNames      map[string]bool
	AllowTypeImports bool
}

type restrictedPattern struct {
	Group            []string
	Regex            string
	CaseSensitive    bool
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

	parseRestrictedPaths := func(items []interface{}) {
		for _, item := range items {
			switch v := item.(type) {
			case string:
				opts.Paths = append(opts.Paths, restrictedPath{Name: v})
			case map[string]interface{}:
				p := restrictedPath{ImportNames: map[string]bool{}}
				if s, ok := v["name"].(string); ok {
					p.Name = s
				}
				if s, ok := v["message"].(string); ok {
					p.Message = s
				}
				if names, ok := v["importNames"].([]interface{}); ok {
					for _, rawName := range names {
						if name, ok := rawName.(string); ok {
							p.ImportNames[name] = true
						}
					}
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

	parseRestrictedPatterns := func(items []interface{}) {
		for _, item := range items {
			switch v := item.(type) {
			case string:
				opts.Patterns = append(opts.Patterns, restrictedPattern{Group: []string{v}})
			case map[string]interface{}:
				p := restrictedPattern{Group: []string{}}
				if group, ok := v["group"].([]interface{}); ok {
					for _, g := range group {
						if gs, ok := g.(string); ok {
							p.Group = append(p.Group, gs)
						}
					}
				}
				if s, ok := v["regex"].(string); ok {
					p.Regex = s
				}
				if b, ok := v["caseSensitive"].(bool); ok {
					p.CaseSensitive = b
				}
				if s, ok := v["message"].(string); ok {
					p.Message = s
				}
				if b, ok := v["allowTypeImports"].(bool); ok {
					p.AllowTypeImports = b
				}
				if len(p.Group) > 0 || p.Regex != "" {
					opts.Patterns = append(opts.Patterns, p)
				}
			}
		}
	}

	if arr, ok := options.([]interface{}); ok {
		if len(arr) == 0 {
			return opts
		}

		// string shorthand: ['foo', 'bar']
		allStrings := true
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				allStrings = false
				break
			}
			opts.Paths = append(opts.Paths, restrictedPath{Name: s})
		}
		if allStrings {
			return opts
		}

		if optsMap, ok := arr[0].(map[string]interface{}); ok {
			if paths, ok := optsMap["paths"].([]interface{}); ok {
				parseRestrictedPaths(paths)
			}
			if patterns, ok := optsMap["patterns"].([]interface{}); ok {
				parseRestrictedPatterns(patterns)
			}
		}
		return opts
	}

	if optsMap, ok := options.(map[string]interface{}); ok {
		if paths, ok := optsMap["paths"].([]interface{}); ok {
			parseRestrictedPaths(paths)
		}
		if patterns, ok := optsMap["patterns"].([]interface{}); ok {
			parseRestrictedPatterns(patterns)
		}
	}

	return opts
}

func buildPathMessage(path, extra string) rule.RuleMessage {
	msg := "'" + path + "' import is restricted from being used."
	messageID := "path"
	if extra != "" {
		msg += " " + extra
		messageID = "pathWithCustomMessage"
	}
	return rule.RuleMessage{Id: messageID, Description: msg}
}

func buildPatternMessage(path, extra string) rule.RuleMessage {
	msg := "'" + path + "' import is restricted from being used by a pattern."
	messageID := "patterns"
	if extra != "" {
		msg += " " + extra
		messageID = "patternWithCustomMessage"
	}
	return rule.RuleMessage{Id: messageID, Description: msg}
}

func buildImportNameMessage(importName, path, extra string) rule.RuleMessage {
	msg := "'" + importName + "' import from '" + path + "' is restricted."
	messageID := "importName"
	if extra != "" {
		msg += " " + extra
		messageID = "importNameWithCustomMessage"
	}
	return rule.RuleMessage{Id: messageID, Description: msg}
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
		if decl == nil || decl.ImportClause == nil {
			return false
		}
		if decl.ImportClause.IsTypeOnly() {
			return true
		}
		clause := decl.ImportClause.AsImportClause()
		if clause == nil || clause.Name() != nil || clause.NamedBindings == nil {
			return false
		}
		if clause.NamedBindings.Kind != ast.KindNamedImports {
			return false
		}
		namedImports := clause.NamedBindings.AsNamedImports()
		if namedImports == nil || namedImports.Elements == nil || len(namedImports.Elements.Nodes) == 0 {
			return false
		}
		for _, specifier := range namedImports.Elements.Nodes {
			if !specifier.IsTypeOnly() {
				return false
			}
		}
		return true
	case ast.KindExportDeclaration:
		decl := node.AsExportDeclaration()
		if decl == nil {
			return false
		}
		if decl.IsTypeOnly {
			return true
		}
		if decl.ExportClause == nil || decl.ExportClause.Kind != ast.KindNamedExports {
			return false
		}
		namedExports := decl.ExportClause.AsNamedExports()
		if namedExports == nil || namedExports.Elements == nil || len(namedExports.Elements.Nodes) == 0 {
			return false
		}
		for _, specifierNode := range namedExports.Elements.Nodes {
			specifier := specifierNode.AsExportSpecifier()
			if specifier == nil || !specifier.IsTypeOnly {
				return false
			}
		}
		return true
	case ast.KindImportEqualsDeclaration:
		decl := node.AsImportEqualsDeclaration()
		return decl != nil && decl.IsTypeOnly
	}
	return false
}

func matchPattern(value, pattern string) bool {
	ok, _ := filepath.Match(pattern, value)
	return ok
}

func matchPatternGroup(value string, patterns []string, caseSensitive bool) bool {
	matched := false
	for _, rawPattern := range patterns {
		pattern := rawPattern
		valueToMatch := value
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = strings.TrimPrefix(pattern, "!")
		}
		if !caseSensitive {
			pattern = strings.ToLower(pattern)
			valueToMatch = strings.ToLower(valueToMatch)
		}
		if matchPattern(valueToMatch, pattern) {
			if negated {
				matched = false
			} else {
				matched = true
			}
		}
	}
	return matched
}

func matchPatternRegex(value string, expression string, caseSensitive bool) bool {
	if expression == "" {
		return false
	}
	if !caseSensitive {
		expression = "(?i)" + expression
	}
	re, err := regexp.Compile(expression)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func literalValue(node *ast.Node) string {
	if node == nil || node.Kind != ast.KindStringLiteral {
		return ""
	}
	return node.AsStringLiteral().Text
}

type importNameEntry struct {
	Name string
	Node *ast.Node
}

func identifierText(node *ast.Node) string {
	if node == nil {
		return ""
	}
	if node.Kind == ast.KindIdentifier {
		return node.AsIdentifier().Text
	}
	return strings.TrimSpace(node.Text())
}

func importNameEntries(node *ast.Node) []importNameEntry {
	entries := []importNameEntry{}
	if node == nil {
		return entries
	}

	switch node.Kind {
	case ast.KindImportDeclaration:
		decl := node.AsImportDeclaration()
		if decl == nil || decl.ImportClause == nil {
			return entries
		}
		clause := decl.ImportClause.AsImportClause()
		if clause == nil {
			return entries
		}
		if clause.Name() != nil {
			entries = append(entries, importNameEntry{
				Name: "default",
				Node: clause.Name(),
			})
		}
		if clause.NamedBindings == nil {
			return entries
		}
		if clause.NamedBindings.Kind == ast.KindNamespaceImport {
			namespaceImport := clause.NamedBindings.AsNamespaceImport()
			if namespaceImport != nil {
				entries = append(entries, importNameEntry{
					Name: "*",
					Node: namespaceImport.AsNode(),
				})
			}
			return entries
		}
		if clause.NamedBindings.Kind != ast.KindNamedImports {
			return entries
		}
		namedImports := clause.NamedBindings.AsNamedImports()
		if namedImports == nil || namedImports.Elements == nil {
			return entries
		}
		for _, specifierNode := range namedImports.Elements.Nodes {
			specifier := specifierNode.AsImportSpecifier()
			if specifier == nil {
				continue
			}
			nameNode := specifier.Name()
			if specifier.PropertyName != nil {
				nameNode = specifier.PropertyName
			}
			importName := identifierText(nameNode)
			if importName == "" {
				continue
			}
			entries = append(entries, importNameEntry{
				Name: importName,
				Node: specifierNode,
			})
		}
	case ast.KindExportDeclaration:
		decl := node.AsExportDeclaration()
		if decl == nil || decl.ExportClause == nil || decl.ExportClause.Kind != ast.KindNamedExports {
			return entries
		}
		namedExports := decl.ExportClause.AsNamedExports()
		if namedExports == nil || namedExports.Elements == nil {
			return entries
		}
		for _, specifierNode := range namedExports.Elements.Nodes {
			specifier := specifierNode.AsExportSpecifier()
			if specifier == nil {
				continue
			}
			nameNode := specifier.Name()
			if specifier.PropertyName != nil {
				nameNode = specifier.PropertyName
			}
			importName := identifierText(nameNode)
			if importName == "" {
				continue
			}
			entries = append(entries, importNameEntry{
				Name: importName,
				Node: specifierNode,
			})
		}
	}
	return entries
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
			importEntries := importNameEntries(node)

			for _, restricted := range opts.Paths {
				if restricted.Name != path {
					continue
				}
				if restricted.AllowTypeImports && typeOnly {
					continue
				}

				if len(restricted.ImportNames) > 0 {
					reported := false
					for _, importEntry := range importEntries {
						if !restricted.ImportNames[importEntry.Name] {
							continue
						}
						ctx.ReportNode(importEntry.Node, buildImportNameMessage(importEntry.Name, path, restricted.Message))
						reported = true
					}
					if reported {
						return
					}
					continue
				}

				ctx.ReportNode(moduleSpecifier, buildPathMessage(path, restricted.Message))
				return
			}

			for _, restricted := range opts.Patterns {
				if restricted.AllowTypeImports && typeOnly {
					continue
				}
				matchedGroup := len(restricted.Group) > 0 && matchPatternGroup(path, restricted.Group, restricted.CaseSensitive)
				matchedRegex := restricted.Regex != "" && matchPatternRegex(path, restricted.Regex, restricted.CaseSensitive)
				if matchedGroup || matchedRegex {
					ctx.ReportNode(moduleSpecifier, buildPatternMessage(path, restricted.Message))
					return
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
