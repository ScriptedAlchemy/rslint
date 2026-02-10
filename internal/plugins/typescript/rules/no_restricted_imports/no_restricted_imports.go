package no_restricted_imports

import (
	"path"
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type restrictedPathRule struct {
	name             string
	message          string
	allowTypeImports bool
	importNames      map[string]bool
}

type restrictedPatternRule struct {
	group            []string
	regex            *regexp.Regexp
	message          string
	allowTypeImports bool
	caseSensitive    bool
}

type importUsage struct {
	source   string
	names    []string
	typeOnly bool
	node     *ast.Node
}

func parseStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

func compileRegex(pattern string, caseSensitive bool) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	compiledPattern := pattern
	if !caseSensitive {
		compiledPattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(compiledPattern)
	if err != nil {
		return nil
	}
	return re
}

func parsePathRuleEntry(entry any) (restrictedPathRule, bool) {
	switch typed := entry.(type) {
	case string:
		if typed == "" {
			return restrictedPathRule{}, false
		}
		return restrictedPathRule{name: typed}, true
	case map[string]interface{}:
		name, ok := typed["name"].(string)
		if !ok || name == "" {
			return restrictedPathRule{}, false
		}
		ruleItem := restrictedPathRule{name: name}
		if message, ok := typed["message"].(string); ok {
			ruleItem.message = message
		}
		if allowTypeImports, ok := typed["allowTypeImports"].(bool); ok {
			ruleItem.allowTypeImports = allowTypeImports
		}
		importNames := parseStringSlice(typed["importNames"])
		if len(importNames) > 0 {
			ruleItem.importNames = map[string]bool{}
			for _, importName := range importNames {
				ruleItem.importNames[importName] = true
			}
		}
		return ruleItem, true
	default:
		return restrictedPathRule{}, false
	}
}

func parsePatternRuleEntry(entry any) (restrictedPatternRule, bool) {
	switch typed := entry.(type) {
	case string:
		if typed == "" {
			return restrictedPatternRule{}, false
		}
		return restrictedPatternRule{
			group:         []string{typed},
			caseSensitive: true,
		}, true
	case map[string]interface{}:
		caseSensitive := true
		if explicitCaseSensitive, ok := typed["caseSensitive"].(bool); ok {
			caseSensitive = explicitCaseSensitive
		}
		patternRule := restrictedPatternRule{
			message:       "",
			caseSensitive: caseSensitive,
		}
		if message, ok := typed["message"].(string); ok {
			patternRule.message = message
		}
		if allowTypeImports, ok := typed["allowTypeImports"].(bool); ok {
			patternRule.allowTypeImports = allowTypeImports
		}
		if regexPattern, ok := typed["regex"].(string); ok && regexPattern != "" {
			patternRule.regex = compileRegex(regexPattern, caseSensitive)
			if patternRule.regex == nil {
				return restrictedPatternRule{}, false
			}
			return patternRule, true
		}
		group := parseStringSlice(typed["group"])
		if len(group) == 0 {
			return restrictedPatternRule{}, false
		}
		patternRule.group = group
		return patternRule, true
	default:
		return restrictedPatternRule{}, false
	}
}

func parseRestrictedImportOptions(options any) ([]restrictedPathRule, []restrictedPatternRule) {
	paths := []restrictedPathRule{}
	patterns := []restrictedPatternRule{}

	var optionsArray []interface{}
	switch typed := options.(type) {
	case []interface{}:
		optionsArray = typed
	case []string:
		for _, entry := range typed {
			paths = append(paths, restrictedPathRule{name: entry})
		}
		return paths, patterns
	case map[string]interface{}:
		optionsArray = []interface{}{typed}
	default:
		return paths, patterns
	}

	if len(optionsArray) == 0 {
		return paths, patterns
	}

	allStrings := true
	for _, entry := range optionsArray {
		if _, ok := entry.(string); !ok {
			allStrings = false
			break
		}
	}
	if allStrings {
		for _, entry := range optionsArray {
			pathName := entry.(string)
			if pathName == "" {
				continue
			}
			paths = append(paths, restrictedPathRule{name: pathName})
		}
		return paths, patterns
	}

	config, ok := optionsArray[0].(map[string]interface{})
	if !ok {
		return paths, patterns
	}

	switch typedPaths := config["paths"].(type) {
	case []string:
		for _, entry := range typedPaths {
			if entry == "" {
				continue
			}
			paths = append(paths, restrictedPathRule{name: entry})
		}
	case []interface{}:
		for _, entry := range typedPaths {
			ruleItem, ok := parsePathRuleEntry(entry)
			if ok {
				paths = append(paths, ruleItem)
			}
		}
	}

	switch typedPatterns := config["patterns"].(type) {
	case []string:
		for _, pattern := range typedPatterns {
			ruleItem, ok := parsePatternRuleEntry(pattern)
			if ok {
				patterns = append(patterns, ruleItem)
			}
		}
	case []interface{}:
		for _, entry := range typedPatterns {
			ruleItem, ok := parsePatternRuleEntry(entry)
			if ok {
				patterns = append(patterns, ruleItem)
			}
		}
	}

	return paths, patterns
}

func isNamedImportClauseTypeOnly(importDecl *ast.ImportDeclaration) bool {
	if importDecl == nil || importDecl.ImportClause == nil {
		return false
	}
	importClause := importDecl.ImportClause.AsImportClause()
	if importClause == nil {
		return false
	}
	if importClause.IsTypeOnly() {
		return true
	}
	if importClause.Name() != nil {
		return false
	}
	if importClause.NamedBindings == nil || importClause.NamedBindings.Kind != ast.KindNamedImports {
		return false
	}
	namedImports := importClause.NamedBindings.AsNamedImports()
	if namedImports == nil || namedImports.Elements == nil || len(namedImports.Elements.Nodes) == 0 {
		return false
	}
	for _, specifier := range namedImports.Elements.Nodes {
		if !specifier.IsTypeOnly() {
			return false
		}
	}
	return true
}

func isNamedExportClauseTypeOnly(exportDecl *ast.ExportDeclaration) bool {
	if exportDecl == nil {
		return false
	}
	if exportDecl.IsTypeOnly {
		return true
	}
	if exportDecl.ExportClause == nil || exportDecl.ExportClause.Kind != ast.KindNamedExports {
		return false
	}
	namedExports := exportDecl.ExportClause.AsNamedExports()
	if namedExports == nil || namedExports.Elements == nil || len(namedExports.Elements.Nodes) == 0 {
		return false
	}
	for _, specifier := range namedExports.Elements.Nodes {
		if !specifier.IsTypeOnly() {
			return false
		}
	}
	return true
}

func getImportSpecifierNames(importDecl *ast.ImportDeclaration) []string {
	if importDecl == nil || importDecl.ImportClause == nil {
		return nil
	}
	importClause := importDecl.ImportClause.AsImportClause()
	if importClause == nil || importClause.NamedBindings == nil || importClause.NamedBindings.Kind != ast.KindNamedImports {
		return nil
	}
	namedImports := importClause.NamedBindings.AsNamedImports()
	if namedImports == nil || namedImports.Elements == nil {
		return nil
	}
	names := []string{}
	for _, specifierNode := range namedImports.Elements.Nodes {
		specifier := specifierNode.AsImportSpecifier()
		if specifier == nil {
			continue
		}
		nameNode := specifier.Name()
		if specifier.PropertyName != nil {
			nameNode = specifier.PropertyName
		}
		if nameNode != nil && nameNode.Kind == ast.KindIdentifier {
			names = append(names, nameNode.AsIdentifier().Text)
		}
	}
	return names
}

func getExportSpecifierNames(exportDecl *ast.ExportDeclaration) []string {
	if exportDecl == nil || exportDecl.ExportClause == nil || exportDecl.ExportClause.Kind != ast.KindNamedExports {
		return nil
	}
	namedExports := exportDecl.ExportClause.AsNamedExports()
	if namedExports == nil || namedExports.Elements == nil {
		return nil
	}
	names := []string{}
	for _, specifierNode := range namedExports.Elements.Nodes {
		specifier := specifierNode.AsExportSpecifier()
		if specifier == nil {
			continue
		}
		nameNode := specifier.Name()
		if specifier.PropertyName != nil {
			nameNode = specifier.PropertyName
		}
		if nameNode != nil && nameNode.Kind == ast.KindIdentifier {
			names = append(names, nameNode.AsIdentifier().Text)
		}
	}
	return names
}

func globMatch(pattern string, value string, caseSensitive bool) bool {
	if !caseSensitive {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

func patternGroupMatches(group []string, modulePath string, caseSensitive bool) bool {
	if len(group) == 0 {
		return false
	}
	matched := false
	for _, pattern := range group {
		if pattern == "" {
			continue
		}
		isNegated := strings.HasPrefix(pattern, "!")
		actualPattern := pattern
		if isNegated {
			actualPattern = strings.TrimPrefix(pattern, "!")
		}
		if globMatch(actualPattern, modulePath, caseSensitive) {
			if isNegated {
				matched = false
			} else {
				matched = true
			}
		}
	}
	return matched
}

func buildPathMessage(source string, customMessage string) rule.RuleMessage {
	description := "Import from '" + source + "' is restricted."
	messageID := "path"
	if customMessage != "" {
		description = description + " " + customMessage
		messageID = "pathWithCustomMessage"
	}
	return rule.RuleMessage{
		Id:          messageID,
		Description: description,
	}
}

func buildImportNameMessage(name string, source string, customMessage string) rule.RuleMessage {
	description := "Import name '" + name + "' from '" + source + "' is restricted."
	if customMessage != "" {
		description = description + " " + customMessage
	}
	return rule.RuleMessage{
		Id:          "importNameWithCustomMessage",
		Description: description,
	}
}

func buildPatternMessage(source string, customMessage string) rule.RuleMessage {
	description := "Import from '" + source + "' matches a restricted pattern."
	messageID := "patterns"
	if customMessage != "" {
		description = description + " " + customMessage
		messageID = "patternWithCustomMessage"
	}
	return rule.RuleMessage{
		Id:          messageID,
		Description: description,
	}
}

func reportPathAndPatternRestrictions(
	ctx rule.RuleContext,
	usage importUsage,
	pathRules []restrictedPathRule,
	patternRules []restrictedPatternRule,
) {
	for _, pathRule := range pathRules {
		if usage.source != pathRule.name {
			continue
		}
		if pathRule.allowTypeImports && usage.typeOnly {
			continue
		}
		if len(pathRule.importNames) > 0 {
			for _, importName := range usage.names {
				if pathRule.importNames[importName] {
					ctx.ReportNode(usage.node, buildImportNameMessage(importName, usage.source, pathRule.message))
				}
			}
			continue
		}
		ctx.ReportNode(usage.node, buildPathMessage(usage.source, pathRule.message))
	}

	for _, patternRule := range patternRules {
		if patternRule.allowTypeImports && usage.typeOnly {
			continue
		}

		matches := false
		if patternRule.regex != nil {
			matches = patternRule.regex.MatchString(usage.source)
		} else {
			matches = patternGroupMatches(patternRule.group, usage.source, patternRule.caseSensitive)
		}
		if !matches {
			continue
		}

		ctx.ReportNode(usage.node, buildPatternMessage(usage.source, patternRule.message))
	}
}

var NoRestrictedImportsRule = rule.CreateRule(rule.Rule{
	Name: "no-restricted-imports",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		pathRules, patternRules := parseRestrictedImportOptions(options)
		if len(pathRules) == 0 && len(patternRules) == 0 {
			return rule.RuleListeners{}
		}

		getStringModuleSpecifier := func(node *ast.Node) string {
			if node == nil {
				return ""
			}
			switch node.Kind {
			case ast.KindStringLiteral:
				return node.AsStringLiteral().Text
			case ast.KindNoSubstitutionTemplateLiteral:
				return node.AsNoSubstitutionTemplateLiteral().Text
			default:
				return ""
			}
		}

		return rule.RuleListeners{
			ast.KindImportDeclaration: func(node *ast.Node) {
				importDecl := node.AsImportDeclaration()
				if importDecl == nil || importDecl.ModuleSpecifier == nil {
					return
				}
				source := getStringModuleSpecifier(importDecl.ModuleSpecifier)
				if source == "" {
					return
				}
				usage := importUsage{
					source:   source,
					names:    getImportSpecifierNames(importDecl),
					typeOnly: isNamedImportClauseTypeOnly(importDecl),
					node:     node,
				}
				reportPathAndPatternRestrictions(ctx, usage, pathRules, patternRules)
			},
			ast.KindImportEqualsDeclaration: func(node *ast.Node) {
				externalModuleReferenceExpr := ast.GetExternalModuleImportEqualsDeclarationExpression(node)
				source := getStringModuleSpecifier(externalModuleReferenceExpr)
				if source == "" {
					return
				}
				usage := importUsage{
					source:   source,
					names:    nil,
					typeOnly: node.IsTypeOnly(),
					node:     node,
				}
				reportPathAndPatternRestrictions(ctx, usage, pathRules, patternRules)
			},
			ast.KindExportDeclaration: func(node *ast.Node) {
				exportDecl := node.AsExportDeclaration()
				if exportDecl == nil || exportDecl.ModuleSpecifier == nil {
					return
				}
				source := getStringModuleSpecifier(exportDecl.ModuleSpecifier)
				if source == "" {
					return
				}
				usage := importUsage{
					source:   source,
					names:    getExportSpecifierNames(exportDecl),
					typeOnly: isNamedExportClauseTypeOnly(exportDecl),
					node:     node,
				}
				reportPathAndPatternRestrictions(ctx, usage, pathRules, patternRules)
			},
		}
	},
})
