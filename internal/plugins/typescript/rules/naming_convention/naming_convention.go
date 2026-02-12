package naming_convention

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

var camelCaseRe = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
var strictCamelCaseRe = regexp.MustCompile(`^[a-z](?:[a-z0-9]*)(?:[A-Z][a-z0-9]+)*$`)
var pascalCaseRe = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`)
var strictPascalCaseRe = regexp.MustCompile(`^[A-Z](?:[a-z0-9]+(?:[A-Z][a-z0-9]+)*)?$`)
var snakeCaseRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
var upperCaseRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$`)
var identifierNameRe = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
var numericNameRe = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)

type namingFilter struct {
	Regex string `json:"regex"`
	Match *bool  `json:"match"`
}

type namingCustom struct {
	Regex string `json:"regex"`
	Match *bool  `json:"match"`
}

type namingConventionOption struct {
	Selector           any      `json:"selector"`
	Format             []string `json:"format"`
	LeadingUnderscore  string   `json:"leadingUnderscore"`
	TrailingUnderscore string   `json:"trailingUnderscore"`
	Prefix             []string `json:"prefix"`
	Suffix             []string `json:"suffix"`
	Modifiers          []string `json:"modifiers"`
	Types              []string `json:"types"`
	Filter             any      `json:"filter"`
	Custom             any      `json:"custom"`
}

type parsedNamingOption struct {
	Selectors          []string
	Formats            []string
	LeadingUnderscore  string
	TrailingUnderscore string
	Prefix             []string
	Suffix             []string
	Modifiers          []string
	Types              []string
	FilterRegex        *regexp.Regexp
	FilterMatch        bool
	CustomRegex        *regexp.Regexp
	CustomMatch        bool
}

type namingCandidate struct {
	Name         string
	NameNode     *ast.Node
	Selector     string
	TypeName     string
	Modifiers    []string
	TypeCategory string
}

func buildDoesNotMatchFormatMessage(typeName string, name string, formats string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "doesNotMatchFormat",
		Description: typeName + " name `" + name + "` must match one of the following formats: " + formats,
	}
}

func buildDoesNotMatchFormatTrimmedMessage(typeName string, name string, processedName string, formats string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "doesNotMatchFormatTrimmed",
		Description: typeName + " name `" + name + "` trimmed as `" + processedName + "` must match one of the following formats: " + formats,
	}
}

func buildSatisfyCustomMessage(typeName string, name string, regex string, regexMatch string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "satisfyCustom",
		Description: typeName + " name `" + name + "` must " + regexMatch + " the RegExp: /" + regex + "/u",
	}
}

func buildMissingAffixMessage(typeName string, name string, position string, affixes string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingAffix",
		Description: typeName + " name `" + name + "` must have one of the following " + position + "es: " + affixes,
	}
}

func buildMissingUnderscoreMessage(typeName string, name string, count string, position string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingUnderscore",
		Description: typeName + " name `" + name + "` must have " + count + " " + position + " underscore(s).",
	}
}

func buildUnexpectedUnderscoreMessage(typeName string, name string, position string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpectedUnderscore",
		Description: typeName + " name `" + name + "` must not have a " + position + " underscore.",
	}
}

func selectorList(raw any) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := []string{}
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	default:
		return nil
	}
}

func compileRegex(source string) *regexp.Regexp {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	re, err := regexp.Compile(source)
	if err != nil {
		return nil
	}
	return re
}

func parseFilter(filter any) (*regexp.Regexp, bool) {
	switch f := filter.(type) {
	case nil:
		return nil, true
	case string:
		return compileRegex(f), true
	case map[string]interface{}:
		regex, _ := f["regex"].(string)
		match := true
		if value, ok := f["match"].(bool); ok {
			match = value
		}
		return compileRegex(regex), match
	case namingFilter:
		match := true
		if f.Match != nil {
			match = *f.Match
		}
		return compileRegex(f.Regex), match
	case *namingFilter:
		if f == nil {
			return nil, true
		}
		match := true
		if f.Match != nil {
			match = *f.Match
		}
		return compileRegex(f.Regex), match
	default:
		return nil, true
	}
}

func parseCustom(custom any) (*regexp.Regexp, bool) {
	switch c := custom.(type) {
	case nil:
		return nil, true
	case map[string]interface{}:
		regex, _ := c["regex"].(string)
		match := true
		if value, ok := c["match"].(bool); ok {
			match = value
		}
		return compileRegex(regex), match
	case namingCustom:
		match := true
		if c.Match != nil {
			match = *c.Match
		}
		return compileRegex(c.Regex), match
	case *namingCustom:
		if c == nil {
			return nil, true
		}
		match := true
		if c.Match != nil {
			match = *c.Match
		}
		return compileRegex(c.Regex), match
	default:
		return nil, true
	}
}

func parseOptions(options any) []parsedNamingOption {
	defaultOptions := []parsedNamingOption{
		{
			Selectors:          []string{"default"},
			Formats:            []string{"camelCase"},
			LeadingUnderscore:  "allow",
			TrailingUnderscore: "allow",
		},
		{
			Selectors: []string{"import"},
			Formats:   []string{"camelCase", "PascalCase"},
		},
		{
			Selectors:          []string{"variable"},
			Formats:            []string{"camelCase", "UPPER_CASE"},
			LeadingUnderscore:  "allow",
			TrailingUnderscore: "allow",
		},
		{
			Selectors: []string{"typeLike"},
			Formats:   []string{"PascalCase"},
		},
	}

	if options == nil {
		return defaultOptions
	}

	rawOptions := []interface{}{}
	switch opt := options.(type) {
	case []interface{}:
		if len(opt) == 1 {
			if nested, ok := opt[0].([]interface{}); ok {
				rawOptions = nested
				break
			}
		}
		rawOptions = opt
	case []map[string]interface{}:
		for _, item := range opt {
			rawOptions = append(rawOptions, item)
		}
	case map[string]interface{}:
		rawOptions = []interface{}{opt}
	default:
		return defaultOptions
	}

	if len(rawOptions) == 0 {
		return defaultOptions
	}

	parsed := []parsedNamingOption{}
	for _, raw := range rawOptions {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var opt namingConventionOption
		if err := json.Unmarshal(encoded, &opt); err != nil {
			continue
		}
		selectors := selectorList(opt.Selector)
		if len(selectors) == 0 {
			continue
		}
		parsedOpt := parsedNamingOption{
			Selectors:          selectors,
			Formats:            opt.Format,
			LeadingUnderscore:  opt.LeadingUnderscore,
			TrailingUnderscore: opt.TrailingUnderscore,
			Prefix:             opt.Prefix,
			Suffix:             opt.Suffix,
			Modifiers:          opt.Modifiers,
			Types:              opt.Types,
		}
		if parsedOpt.LeadingUnderscore == "" {
			parsedOpt.LeadingUnderscore = "forbid"
		}
		if parsedOpt.TrailingUnderscore == "" {
			parsedOpt.TrailingUnderscore = "forbid"
		}

		parsedOpt.FilterRegex, parsedOpt.FilterMatch = parseFilter(opt.Filter)
		parsedOpt.CustomRegex, parsedOpt.CustomMatch = parseCustom(opt.Custom)
		parsed = append(parsed, parsedOpt)
	}

	if len(parsed) == 0 {
		return defaultOptions
	}
	return parsed
}

func hasAllModifiers(candidate namingCandidate, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, item := range required {
		if !slices.Contains(candidate.Modifiers, item) {
			return false
		}
	}
	return true
}

func selectorMatches(selector string, candidateSelector string) bool {
	if selector == candidateSelector {
		return true
	}
	switch selector {
	case "default":
		return true
	case "typeLike":
		return candidateSelector == "class" || candidateSelector == "interface" || candidateSelector == "typeAlias" || candidateSelector == "enum" || candidateSelector == "typeParameter"
	case "variableLike":
		return candidateSelector == "variable" || candidateSelector == "function" || candidateSelector == "parameter"
	case "memberLike":
		return candidateSelector == "property" ||
			candidateSelector == "classProperty" ||
			candidateSelector == "objectLiteralProperty" ||
			candidateSelector == "typeProperty" ||
			candidateSelector == "parameterProperty" ||
			candidateSelector == "enumMember" ||
			candidateSelector == "method" ||
			candidateSelector == "classMethod" ||
			candidateSelector == "objectLiteralMethod" ||
			candidateSelector == "typeMethod" ||
			candidateSelector == "accessor" ||
			candidateSelector == "autoAccessor" ||
			candidateSelector == "classicAccessor"
	case "property":
		return candidateSelector == "property" || candidateSelector == "classProperty" || candidateSelector == "autoAccessor" || candidateSelector == "objectLiteralProperty" || candidateSelector == "typeProperty" || candidateSelector == "parameterProperty"
	case "method":
		return candidateSelector == "method" || candidateSelector == "classMethod" || candidateSelector == "objectLiteralMethod" || candidateSelector == "typeMethod"
	case "classProperty":
		return candidateSelector == "classProperty" || candidateSelector == "autoAccessor"
	case "accessor":
		return candidateSelector == "accessor" || candidateSelector == "autoAccessor" || candidateSelector == "classicAccessor"
	case "objectLiteralProperty", "parameterProperty", "typeProperty", "classMethod", "objectLiteralMethod", "typeMethod", "autoAccessor", "classicAccessor", "enumMember":
		return candidateSelector == selector
	}
	return false
}

func appliesToType(types []string, candidateType string) bool {
	if len(types) == 0 {
		return true
	}
	return candidateType != "" && slices.Contains(types, candidateType)
}

func selectorSupportsTypeConstraints(selector string) bool {
	switch selector {
	case "variable", "parameter", "parameterProperty", "classProperty", "objectLiteralProperty", "typeProperty", "property":
		return true
	default:
		return false
	}
}

func selectorSpecificity(selector string) int {
	switch selector {
	case "default":
		return 0
	case "typeLike", "variableLike", "memberLike", "property", "method":
		return 1
	default:
		return 2
	}
}

func optionScore(opt *parsedNamingOption, selector string) int {
	score := selectorSpecificity(selector)
	score += len(opt.Modifiers) * 10
	if len(opt.Types) > 0 {
		score += 20
	}
	if opt.FilterRegex != nil {
		score += 2
	}
	if opt.CustomRegex != nil {
		score += 1
	}
	return score
}

func pickOption(opts []parsedNamingOption, candidate namingCandidate) *parsedNamingOption {
	var matched *parsedNamingOption
	bestScore := -1
	bestIndex := -1
	for i := range opts {
		opt := &opts[i]
		if !hasAllModifiers(candidate, opt.Modifiers) {
			continue
		}
		if selectorSupportsTypeConstraints(candidate.Selector) && !appliesToType(opt.Types, candidate.TypeCategory) {
			continue
		}
		if opt.FilterRegex != nil {
			matchedFilter := opt.FilterRegex.MatchString(candidate.Name)
			if matchedFilter != opt.FilterMatch {
				continue
			}
		}
		for _, selector := range opt.Selectors {
			if selectorMatches(selector, candidate.Selector) {
				score := optionScore(opt, selector)
				if matched == nil || score > bestScore || (score == bestScore && i > bestIndex) {
					matched = opt
					bestScore = score
					bestIndex = i
				}
				break
			}
		}
	}
	return matched
}

func formatMatches(format string, name string) bool {
	switch format {
	case "camelCase":
		return camelCaseRe.MatchString(name)
	case "strictCamelCase":
		return strictCamelCaseRe.MatchString(name)
	case "PascalCase":
		return pascalCaseRe.MatchString(name)
	case "StrictPascalCase":
		return strictPascalCaseRe.MatchString(name)
	case "snake_case":
		return snakeCaseRe.MatchString(name)
	case "UPPER_CASE":
		return upperCaseRe.MatchString(name)
	default:
		return true
	}
}

func formatListForMessage(formats []string) string {
	if len(formats) == 0 {
		return "<none>"
	}
	return strings.Join(formats, ", ")
}

func trimLeadingUnderscores(name string) string {
	return strings.TrimLeft(name, "_")
}

func trimTrailingUnderscores(name string) string {
	return strings.TrimRight(name, "_")
}

func underscoreCount(name string, leading bool) int {
	count := 0
	if leading {
		for count < len(name) && name[count] == '_' {
			count++
		}
		return count
	}
	for count < len(name) && name[len(name)-1-count] == '_' {
		count++
	}
	return count
}

func applyUnderscorePolicy(candidate namingCandidate, processedName string, policy string, leading bool) (string, *rule.RuleMessage) {
	position := "leading"
	if !leading {
		position = "trailing"
	}
	count := underscoreCount(processedName, leading)
	hasSingle := count >= 1
	hasDouble := count >= 2

	switch policy {
	case "allow":
		if leading {
			processedName = trimLeadingUnderscores(processedName)
		} else {
			processedName = trimTrailingUnderscores(processedName)
		}
	case "allowDouble":
		switch count {
		case 0:
			// keep as-is
		case 2:
			if leading {
				processedName = strings.TrimPrefix(processedName, "__")
			} else {
				processedName = strings.TrimSuffix(processedName, "__")
			}
		default:
			msg := buildUnexpectedUnderscoreMessage(candidate.TypeName, candidate.Name, position)
			return processedName, &msg
		}
	case "allowSingleOrDouble":
		switch count {
		case 0:
			// keep as-is
		case 1:
			if leading {
				processedName = strings.TrimPrefix(processedName, "_")
			} else {
				processedName = strings.TrimSuffix(processedName, "_")
			}
		case 2:
			if leading {
				processedName = strings.TrimPrefix(processedName, "__")
			} else {
				processedName = strings.TrimSuffix(processedName, "__")
			}
		default:
			msg := buildUnexpectedUnderscoreMessage(candidate.TypeName, candidate.Name, position)
			return processedName, &msg
		}
	case "forbid":
		if hasSingle {
			msg := buildUnexpectedUnderscoreMessage(candidate.TypeName, candidate.Name, position)
			return processedName, &msg
		}
	case "require":
		if !hasSingle {
			msg := buildMissingUnderscoreMessage(candidate.TypeName, candidate.Name, "one", position)
			return processedName, &msg
		}
		if leading {
			processedName = strings.TrimPrefix(processedName, "_")
		} else {
			processedName = strings.TrimSuffix(processedName, "_")
		}
	case "requireDouble":
		if !hasDouble {
			msg := buildMissingUnderscoreMessage(candidate.TypeName, candidate.Name, "two", position)
			return processedName, &msg
		}
		if leading {
			processedName = strings.TrimPrefix(processedName, "__")
		} else {
			processedName = strings.TrimSuffix(processedName, "__")
		}
	}
	return processedName, nil
}

func applyAffix(name string, affixes []string, prefix bool) (string, bool) {
	if len(affixes) == 0 {
		return name, true
	}
	for _, affix := range affixes {
		if prefix && strings.HasPrefix(name, affix) {
			return strings.TrimPrefix(name, affix), true
		}
		if !prefix && strings.HasSuffix(name, affix) {
			return strings.TrimSuffix(name, affix), true
		}
	}
	return name, false
}

func inferTypeCategory(typeNode *ast.Node) string {
	if typeNode == nil {
		return ""
	}
	typeNode = ast.SkipParentheses(typeNode)
	if typeNode == nil {
		return ""
	}
	if typeNode.Kind == ast.KindParenthesizedType {
		parenthesizedType := typeNode.AsParenthesizedTypeNode()
		if parenthesizedType == nil {
			return ""
		}
		return inferTypeCategory(parenthesizedType.Type)
	}
	if typeNode.Kind == ast.KindLiteralType {
		literalType := typeNode.AsLiteralTypeNode()
		if literalType == nil {
			return ""
		}
		return inferTypeCategory(literalType.Literal)
	}
	switch typeNode.Kind {
	case ast.KindAnyKeyword:
		return "any"
	case ast.KindNullKeyword, ast.KindUndefinedKeyword, ast.KindVoidKeyword:
		return "nullish"
	case ast.KindStringKeyword, ast.KindStringLiteral:
		return "string"
	case ast.KindNumberKeyword, ast.KindNumericLiteral:
		return "number"
	case ast.KindBooleanKeyword, ast.KindTrueKeyword, ast.KindFalseKeyword:
		return "boolean"
	case ast.KindFunctionType, ast.KindConstructorType:
		return "function"
	case ast.KindTypeOperator:
		typeOperator := typeNode.AsTypeOperatorNode()
		if typeOperator == nil {
			return ""
		}
		return inferTypeCategory(typeOperator.Type)
	case ast.KindArrayType, ast.KindTupleType:
		return "array"
	case ast.KindTypeReference:
		typeRef := typeNode.AsTypeReferenceNode()
		if typeRef == nil || typeRef.TypeName == nil {
			return ""
		}
		typeName := ""
		if typeRef.TypeName.Kind == ast.KindIdentifier {
			typeName = typeRef.TypeName.AsIdentifier().Text
		}
		if typeName == "Array" || typeName == "ReadonlyArray" {
			return "array"
		}
		switch typeName {
		case "string", "String":
			return "string"
		case "number", "Number":
			return "number"
		case "boolean", "Boolean":
			return "boolean"
		case "Function":
			return "function"
		case "any":
			return "any"
		}
	case ast.KindUnionType:
		union := typeNode.AsUnionTypeNode()
		if union == nil || union.Types == nil {
			return ""
		}
		candidate := ""
		for _, child := range union.Types.Nodes {
			childCategory := inferTypeCategory(child)
			if childCategory == "nullish" {
				continue
			}
			if childCategory == "" {
				return ""
			}
			if candidate == "" {
				candidate = childCategory
				continue
			}
			if candidate != childCategory {
				return ""
			}
		}
		return candidate
	}
	return ""
}

func inferExpressionCategory(expr *ast.Node) string {
	if expr == nil {
		return ""
	}
	expr = ast.SkipParentheses(expr)
	if expr == nil {
		return ""
	}
	switch expr.Kind {
	case ast.KindStringLiteral, ast.KindNoSubstitutionTemplateLiteral, ast.KindTemplateExpression:
		return "string"
	case ast.KindNumericLiteral:
		return "number"
	case ast.KindTrueKeyword, ast.KindFalseKeyword:
		return "boolean"
	case ast.KindArrayLiteralExpression:
		return "array"
	case ast.KindArrowFunction, ast.KindFunctionExpression:
		return "function"
	default:
		return ""
	}
}

func declarationName(node *ast.Node) (string, *ast.Node) {
	if node == nil || node.Name() == nil {
		return "", nil
	}
	nameNode := node.Name()
	switch nameNode.Kind {
	case ast.KindIdentifier:
		return nameNode.AsIdentifier().Text, nameNode
	case ast.KindPrivateIdentifier:
		privateName := nameNode.AsPrivateIdentifier().Text
		privateName = strings.TrimPrefix(privateName, "#")
		return privateName, nameNode
	case ast.KindStringLiteral:
		return nameNode.AsStringLiteral().Text, nameNode
	case ast.KindNumericLiteral:
		return nameNode.AsNumericLiteral().Text, nameNode
	}
	return "", nil
}

func hasCandidateName(name string, nameNode *ast.Node) bool {
	if nameNode == nil {
		return false
	}
	if name != "" {
		return true
	}
	return nameNode.Kind == ast.KindStringLiteral
}

func declarationModifiers(node *ast.Node) []string {
	if node == nil {
		return nil
	}
	flags := ast.GetCombinedModifierFlags(node)
	modifiers := []string{}
	if flags&ast.ModifierFlagsReadonly != 0 {
		modifiers = append(modifiers, "readonly")
	}
	if flags&ast.ModifierFlagsStatic != 0 {
		modifiers = append(modifiers, "static")
	}
	if flags&ast.ModifierFlagsAsync != 0 {
		modifiers = append(modifiers, "async")
	}
	if flags&ast.ModifierFlagsOverride != 0 {
		modifiers = append(modifiers, "override")
	}
	if flags&ast.ModifierFlagsAbstract != 0 {
		modifiers = append(modifiers, "abstract")
	}
	if flags&ast.ModifierFlagsPrivate != 0 {
		modifiers = append(modifiers, "private")
	}
	if flags&ast.ModifierFlagsProtected != 0 {
		modifiers = append(modifiers, "protected")
	}
	if flags&ast.ModifierFlagsPublic != 0 {
		modifiers = append(modifiers, "public")
	}
	if flags&ast.ModifierFlagsExport != 0 || flags&ast.ModifierFlagsDefault != 0 || ast.HasSyntacticModifier(node, ast.ModifierFlagsExport) || ast.HasSyntacticModifier(node, ast.ModifierFlagsDefault) {
		modifiers = append(modifiers, "exported")
	}
	if node.Kind == ast.KindVariableDeclaration && node.Parent != nil && node.Parent.Kind == ast.KindVariableDeclarationList {
		parentStmt := node.Parent.Parent
		if parentStmt != nil && parentStmt.Kind == ast.KindVariableStatement && (ast.HasSyntacticModifier(parentStmt, ast.ModifierFlagsExport) || ast.HasSyntacticModifier(parentStmt, ast.ModifierFlagsDefault)) {
			if !slices.Contains(modifiers, "exported") {
				modifiers = append(modifiers, "exported")
			}
		}
	}
	return modifiers
}

func withExportedModifier(modifiers []string, name string, exportedNames map[string]bool) []string {
	if name == "" || len(exportedNames) == 0 || !exportedNames[name] || slices.Contains(modifiers, "exported") {
		return modifiers
	}
	return append(modifiers, "exported")
}

func withModifier(modifiers []string, modifier string) []string {
	if modifier == "" || slices.Contains(modifiers, modifier) {
		return modifiers
	}
	return append(modifiers, modifier)
}

func withUnusedModifier(modifiers []string, name string, identifierCounts map[string]int) []string {
	if name == "" || len(identifierCounts) == 0 || identifierCounts[name] != 1 || slices.Contains(modifiers, "exported") {
		return modifiers
	}
	return withModifier(modifiers, "unused")
}

func withRequiresQuotesModifier(modifiers []string, nameNode *ast.Node) []string {
	if nameNode == nil || nameNode.Kind != ast.KindStringLiteral {
		return modifiers
	}
	name := nameNode.AsStringLiteral().Text
	if identifierNameRe.MatchString(name) || numericNameRe.MatchString(name) {
		return modifiers
	}
	return withModifier(modifiers, "requiresQuotes")
}

func collectExportedNames(sourceFile *ast.SourceFile) map[string]bool {
	exportedNames := map[string]bool{}
	if sourceFile == nil || sourceFile.Statements == nil {
		return exportedNames
	}
	for _, statement := range sourceFile.Statements.Nodes {
		if statement == nil || statement.Kind != ast.KindExportDeclaration {
			continue
		}
		exportDecl := statement.AsExportDeclaration()
		if exportDecl == nil || exportDecl.ModuleSpecifier != nil || exportDecl.ExportClause == nil || exportDecl.ExportClause.Kind != ast.KindNamedExports {
			continue
		}
		namedExports := exportDecl.ExportClause.AsNamedExports()
		if namedExports == nil || namedExports.Elements == nil {
			continue
		}
		for _, element := range namedExports.Elements.Nodes {
			if element == nil {
				continue
			}
			specifier := element.AsExportSpecifier()
			if specifier == nil {
				continue
			}
			localName := specifier.Name()
			if specifier.PropertyName != nil {
				localName = specifier.PropertyName
			}
			if localName != nil && localName.Kind == ast.KindIdentifier {
				exportedNames[localName.AsIdentifier().Text] = true
			}
		}
	}
	return exportedNames
}

func isGlobalDeclaration(node *ast.Node) bool {
	if node == nil {
		return false
	}
	container := node
	if node.Kind == ast.KindVariableDeclaration {
		if node.Parent == nil || node.Parent.Kind != ast.KindVariableDeclarationList || node.Parent.Parent == nil {
			return false
		}
		container = node.Parent.Parent
	}
	return container != nil && container.Parent != nil && container.Parent.Kind == ast.KindSourceFile
}

func collectIdentifierCounts(root *ast.Node, counts map[string]int) {
	if root == nil {
		return
	}
	if root.Kind == ast.KindIdentifier {
		identifier := root.AsIdentifier()
		if identifier != nil {
			counts[identifier.Text]++
		}
	}
	root.ForEachChild(func(child *ast.Node) bool {
		collectIdentifierCounts(child, counts)
		return false
	})
}

func isAutoAccessorProperty(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindPropertyDeclaration {
		return false
	}
	flags := ast.GetCombinedModifierFlags(node)
	if flags&ast.ModifierFlagsAccessor != 0 {
		return true
	}
	modifiers := node.Modifiers()
	if modifiers == nil {
		return false
	}
	for _, modifier := range modifiers.Nodes {
		if modifier != nil && modifier.Kind == ast.KindAccessorKeyword {
			return true
		}
	}
	return false
}

func validateCandidate(ctx rule.RuleContext, opts []parsedNamingOption, candidate namingCandidate) {
	if candidate.NameNode == nil {
		return
	}
	candidate.Modifiers = withRequiresQuotesModifier(candidate.Modifiers, candidate.NameNode)
	if candidate.NameNode.Kind == ast.KindPrivateIdentifier {
		candidate.Modifiers = withModifier(candidate.Modifiers, "#private")
	}
	option := pickOption(opts, candidate)
	if option == nil {
		return
	}

	processedName := candidate.Name
	changedName := false

	nextName, underscoreMessage := applyUnderscorePolicy(candidate, processedName, option.LeadingUnderscore, true)
	if underscoreMessage != nil {
		ctx.ReportNode(candidate.NameNode, *underscoreMessage)
		return
	}
	if nextName != processedName {
		changedName = true
	}
	processedName = nextName

	nextName, underscoreMessage = applyUnderscorePolicy(candidate, processedName, option.TrailingUnderscore, false)
	if underscoreMessage != nil {
		ctx.ReportNode(candidate.NameNode, *underscoreMessage)
		return
	}
	if nextName != processedName {
		changedName = true
	}
	processedName = nextName

	nextName, hasPrefix := applyAffix(processedName, option.Prefix, true)
	if len(option.Prefix) > 0 && !hasPrefix {
		ctx.ReportNode(candidate.NameNode, buildMissingAffixMessage(candidate.TypeName, candidate.Name, "prefix", strings.Join(option.Prefix, ", ")))
		return
	}
	if nextName != processedName {
		changedName = true
	}
	processedName = nextName

	nextName, hasSuffix := applyAffix(processedName, option.Suffix, false)
	if len(option.Suffix) > 0 && !hasSuffix {
		ctx.ReportNode(candidate.NameNode, buildMissingAffixMessage(candidate.TypeName, candidate.Name, "suffix", strings.Join(option.Suffix, ", ")))
		return
	}
	if nextName != processedName {
		changedName = true
	}
	processedName = nextName

	if option.CustomRegex != nil {
		matched := option.CustomRegex.MatchString(processedName)
		if matched != option.CustomMatch {
			regexMatch := "not match"
			if option.CustomMatch {
				regexMatch = "match"
			}
			ctx.ReportNode(candidate.NameNode, buildSatisfyCustomMessage(candidate.TypeName, candidate.Name, option.CustomRegex.String(), regexMatch))
			return
		}
	}

	if len(option.Formats) == 0 {
		return
	}
	for _, format := range option.Formats {
		if formatMatches(format, processedName) {
			return
		}
	}

	formats := formatListForMessage(option.Formats)
	if changedName {
		ctx.ReportNode(candidate.NameNode, buildDoesNotMatchFormatTrimmedMessage(candidate.TypeName, candidate.Name, processedName, formats))
		return
	}
	ctx.ReportNode(candidate.NameNode, buildDoesNotMatchFormatMessage(candidate.TypeName, candidate.Name, formats))
}

var NamingConventionRule = rule.CreateRule(rule.Rule{
	Name: "naming-convention",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		exportedNames := collectExportedNames(ctx.SourceFile)
		identifierCounts := map[string]int{}
		if ctx.SourceFile != nil {
			collectIdentifierCounts(ctx.SourceFile.AsNode(), identifierCounts)
		}

		return rule.RuleListeners{
			ast.KindVariableDeclaration: func(node *ast.Node) {
				varDecl := node.AsVariableDeclaration()
				if varDecl == nil {
					return
				}
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				modifiers := declarationModifiers(node)
				if node.Parent != nil && node.Parent.Kind == ast.KindVariableDeclarationList {
					list := node.Parent.AsVariableDeclarationList()
					if list != nil && list.Flags&ast.NodeFlagsConst != 0 {
						modifiers = append(modifiers, "const")
					}
				}
				modifiers = withExportedModifier(modifiers, name, exportedNames)
				if isGlobalDeclaration(node) {
					modifiers = withModifier(modifiers, "global")
				}
				if varDecl.Initializer != nil {
					initializer := ast.SkipParentheses(varDecl.Initializer)
					if initializer != nil && ast.GetCombinedModifierFlags(initializer)&ast.ModifierFlagsAsync != 0 {
						modifiers = withModifier(modifiers, "async")
					}
				}
				modifiers = withUnusedModifier(modifiers, name, identifierCounts)
				typeCategory := inferTypeCategory(varDecl.Type)
				if typeCategory == "" {
					typeCategory = inferExpressionCategory(varDecl.Initializer)
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:         name,
					NameNode:     nameNode,
					Selector:     "variable",
					TypeName:     "Variable",
					Modifiers:    modifiers,
					TypeCategory: typeCategory,
				})
			},
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := declarationModifiers(node)
				if functionDecl := node.AsFunctionDeclaration(); functionDecl != nil && functionDecl.AsteriskToken != nil {
					candidateModifiers = append(candidateModifiers, "generator")
				}
				candidateModifiers = withExportedModifier(candidateModifiers, name, exportedNames)
				if isGlobalDeclaration(node) {
					candidateModifiers = withModifier(candidateModifiers, "global")
				}
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "function",
					TypeName:  "Function",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindFunctionExpression: func(node *ast.Node) {
				functionExpr := node.AsFunctionExpression()
				if functionExpr == nil || functionExpr.Name() == nil {
					return
				}
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := declarationModifiers(node)
				if functionExpr.AsteriskToken != nil {
					candidateModifiers = append(candidateModifiers, "generator")
				}
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "function",
					TypeName:  "Function",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindClassDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := withExportedModifier(declarationModifiers(node), name, exportedNames)
				if isGlobalDeclaration(node) {
					candidateModifiers = withModifier(candidateModifiers, "global")
				}
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "class",
					TypeName:  "Class",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindClassExpression: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := declarationModifiers(node)
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "class",
					TypeName:  "Class",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := withExportedModifier(declarationModifiers(node), name, exportedNames)
				if isGlobalDeclaration(node) {
					candidateModifiers = withModifier(candidateModifiers, "global")
				}
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "interface",
					TypeName:  "Interface",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := withExportedModifier(declarationModifiers(node), name, exportedNames)
				if isGlobalDeclaration(node) {
					candidateModifiers = withModifier(candidateModifiers, "global")
				}
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "typeAlias",
					TypeName:  "Type Alias",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindEnumDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				candidateModifiers := withExportedModifier(declarationModifiers(node), name, exportedNames)
				if isGlobalDeclaration(node) {
					candidateModifiers = withModifier(candidateModifiers, "global")
				}
				candidateModifiers = withUnusedModifier(candidateModifiers, name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "enum",
					TypeName:  "Enum",
					Modifiers: candidateModifiers,
				})
			},
			ast.KindParameter: func(node *ast.Node) {
				parameter := node.AsParameterDeclaration()
				if parameter == nil || parameter.Name() == nil || parameter.Name().Kind != ast.KindIdentifier {
					return
				}
				modifiers := declarationModifiers(node)
				selector := "parameter"
				typeName := "Parameter"
				if parameter.Parent != nil && parameter.Parent.Kind == ast.KindConstructor &&
					(slices.Contains(modifiers, "readonly") ||
						slices.Contains(modifiers, "private") ||
						slices.Contains(modifiers, "protected") ||
						slices.Contains(modifiers, "public")) {
					selector = "parameterProperty"
					typeName = "Parameter Property"
				}
				modifiers = withUnusedModifier(modifiers, parameter.Name().AsIdentifier().Text, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:         parameter.Name().AsIdentifier().Text,
					NameNode:     parameter.Name(),
					Selector:     selector,
					TypeName:     typeName,
					Modifiers:    modifiers,
					TypeCategory: inferTypeCategory(parameter.Type),
				})
			},
			ast.KindBindingElement: func(node *ast.Node) {
				binding := node.AsBindingElement()
				if binding == nil || binding.Name() == nil || binding.Name().Kind != ast.KindIdentifier {
					return
				}
				name := binding.Name().AsIdentifier().Text
				modifiers := []string{}
				if binding.PropertyName == nil {
					modifiers = append(modifiers, "destructured")
				}
				selector := "variable"
				typeName := "Variable"
				typeCategory := ""
				resolved := false
				for current := node.Parent; current != nil; current = current.Parent {
					switch current.Kind {
					case ast.KindParameter:
						selector = "parameter"
						typeName = "Parameter"
						modifiers = append(modifiers, declarationModifiers(current)...)
						param := current.AsParameterDeclaration()
						if param != nil {
							typeCategory = inferTypeCategory(param.Type)
						}
						resolved = true
					case ast.KindVariableDeclaration:
						selector = "variable"
						typeName = "Variable"
						modifiers = append(modifiers, declarationModifiers(current)...)
						if current.Parent != nil && current.Parent.Kind == ast.KindVariableDeclarationList {
							list := current.Parent.AsVariableDeclarationList()
							if list != nil && list.Flags&ast.NodeFlagsConst != 0 {
								modifiers = withModifier(modifiers, "const")
							}
						}
						if isGlobalDeclaration(current) {
							modifiers = withModifier(modifiers, "global")
						}
						modifiers = withExportedModifier(modifiers, name, exportedNames)
						varDecl := current.AsVariableDeclaration()
						if varDecl != nil {
							typeCategory = inferTypeCategory(varDecl.Type)
						}
						resolved = true
					}
					if resolved {
						break
					}
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:         name,
					NameNode:     binding.Name(),
					Selector:     selector,
					TypeName:     typeName,
					Modifiers:    withUnusedModifier(modifiers, name, identifierCounts),
					TypeCategory: typeCategory,
				})
			},
			ast.KindTypeParameter: func(node *ast.Node) {
				typeParam := node.AsTypeParameter()
				if typeParam == nil || typeParam.Name() == nil {
					return
				}
				name := typeParam.Name().Text()
				modifiers := withUnusedModifier(declarationModifiers(node), name, identifierCounts)
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  typeParam.Name(),
					Selector:  "typeParameter",
					TypeName:  "Type Parameter",
					Modifiers: modifiers,
				})
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				propDecl := node.AsPropertyDeclaration()
				modifiers := declarationModifiers(node)
				if propDecl != nil && propDecl.Initializer != nil {
					initializer := ast.SkipParentheses(propDecl.Initializer)
					if initializer != nil && ast.GetCombinedModifierFlags(initializer)&ast.ModifierFlagsAsync != 0 {
						modifiers = withModifier(modifiers, "async")
					}
				}
				selector := "classProperty"
				typeName := "Class Property"
				typeCategory := inferTypeCategory(propDecl.Type)
				if isAutoAccessorProperty(node) {
					selector = "autoAccessor"
					typeName = "Accessor"
				} else if typeCategory == "function" || inferExpressionCategory(propDecl.Initializer) == "function" {
					selector = "classMethod"
					typeName = "Class Method"
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:         name,
					NameNode:     nameNode,
					Selector:     selector,
					TypeName:     typeName,
					Modifiers:    modifiers,
					TypeCategory: typeCategory,
				})
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				selector := "classMethod"
				typeName := "Class Method"
				if node.Parent != nil && node.Parent.Kind == ast.KindObjectLiteralExpression {
					selector = "objectLiteralMethod"
					typeName = "Object Literal Method"
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  selector,
					TypeName:  typeName,
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindGetAccessor: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "classicAccessor",
					TypeName:  "Accessor",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindSetAccessor: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "classicAccessor",
					TypeName:  "Accessor",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindPropertySignature: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				selector := "typeProperty"
				typeName := "Type Property"
				propertySignature := node.AsPropertySignatureDeclaration()
				if propertySignature != nil && inferTypeCategory(propertySignature.Type) == "function" {
					selector = "typeMethod"
					typeName = "Type Method"
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  selector,
					TypeName:  typeName,
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindMethodSignature: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "typeMethod",
					TypeName:  "Type Method",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindEnumMember: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "enumMember",
					TypeName:  "Enum Member",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindPropertyAssignment: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				selector := "objectLiteralProperty"
				typeName := "Object Literal Property"
				modifiers := []string{}
				propertyAssignment := node.AsPropertyAssignment()
				if propertyAssignment != nil {
					if inferExpressionCategory(propertyAssignment.Initializer) == "function" {
						selector = "objectLiteralMethod"
						typeName = "Object Literal Method"
					}
					initializer := ast.SkipParentheses(propertyAssignment.Initializer)
					if initializer != nil && ast.GetCombinedModifierFlags(initializer)&ast.ModifierFlagsAsync != 0 {
						modifiers = withModifier(modifiers, "async")
					}
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  selector,
					TypeName:  typeName,
					Modifiers: modifiers,
				})
			},
			ast.KindShorthandPropertyAssignment: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if !hasCandidateName(name, nameNode) {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "objectLiteralProperty",
					TypeName:  "Object Literal Property",
					Modifiers: []string{},
				})
			},
			ast.KindImportSpecifier: func(node *ast.Node) {
				importSpecifier := node.AsImportSpecifier()
				if importSpecifier == nil || importSpecifier.Name() == nil {
					return
				}
				if importSpecifier.PropertyName == nil {
					return
				}
				modifiers := []string{}
				if importSpecifier.PropertyName.Kind == ast.KindIdentifier &&
					importSpecifier.PropertyName.AsIdentifier().Text == "default" {
					modifiers = append(modifiers, "default")
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      importSpecifier.Name().Text(),
					NameNode:  importSpecifier.Name(),
					Selector:  "import",
					TypeName:  "Import",
					Modifiers: modifiers,
				})
			},
			ast.KindImportClause: func(node *ast.Node) {
				importClause := node.AsImportClause()
				if importClause == nil || importClause.Name() == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      importClause.Name().Text(),
					NameNode:  importClause.Name().AsNode(),
					Selector:  "import",
					TypeName:  "Import",
					Modifiers: []string{"default"},
				})
			},
			ast.KindNamespaceImport: func(node *ast.Node) {
				namespaceImport := node.AsNamespaceImport()
				if namespaceImport == nil || namespaceImport.Name() == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      namespaceImport.Name().Text(),
					NameNode:  namespaceImport.Name(),
					Selector:  "import",
					TypeName:  "Import",
					Modifiers: []string{"namespace"},
				})
			},
		}
	},
})
