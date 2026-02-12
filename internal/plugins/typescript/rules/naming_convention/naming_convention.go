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
var strictCamelCaseRe = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
var pascalCaseRe = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`)
var strictPascalCaseRe = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`)
var snakeCaseRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
var upperCaseRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$`)

type namingFilter struct {
	Regex string `json:"regex"`
	Match *bool  `json:"match"`
}

type namingCustom struct {
	Regex string `json:"regex"`
	Match *bool  `json:"match"`
}

type namingConventionOption struct {
	Selector           any           `json:"selector"`
	Format             []string      `json:"format"`
	LeadingUnderscore  string        `json:"leadingUnderscore"`
	TrailingUnderscore string        `json:"trailingUnderscore"`
	Prefix             []string      `json:"prefix"`
	Suffix             []string      `json:"suffix"`
	Modifiers          []string      `json:"modifiers"`
	Types              []string      `json:"types"`
	Filter             *namingFilter `json:"filter"`
	Custom             *namingCustom `json:"custom"`
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

		if opt.Filter != nil {
			parsedOpt.FilterRegex = compileRegex(opt.Filter.Regex)
			parsedOpt.FilterMatch = true
			if opt.Filter.Match != nil {
				parsedOpt.FilterMatch = *opt.Filter.Match
			}
		}
		if opt.Custom != nil {
			parsedOpt.CustomRegex = compileRegex(opt.Custom.Regex)
			parsedOpt.CustomMatch = true
			if opt.Custom.Match != nil {
				parsedOpt.CustomMatch = *opt.Custom.Match
			}
		}
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
		return candidateSelector == "variable" || candidateSelector == "parameter" || candidateSelector == "property" || candidateSelector == "import"
	case "memberLike":
		return candidateSelector == "property" || candidateSelector == "method" || candidateSelector == "accessor"
	case "classProperty", "objectLiteralProperty", "parameterProperty", "typeProperty":
		return candidateSelector == "property"
	case "classMethod", "objectLiteralMethod", "typeMethod":
		return candidateSelector == "method"
	}
	return false
}

func appliesToType(types []string, candidateType string) bool {
	if len(types) == 0 {
		return true
	}
	return candidateType != "" && slices.Contains(types, candidateType)
}

func pickOption(opts []parsedNamingOption, candidate namingCandidate) *parsedNamingOption {
	var matched *parsedNamingOption
	for i := range opts {
		opt := &opts[i]
		if !hasAllModifiers(candidate, opt.Modifiers) {
			continue
		}
		if !appliesToType(opt.Types, candidate.TypeCategory) {
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
				matched = opt
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

func applyUnderscorePolicy(candidate namingCandidate, processedName string, policy string, leading bool) (string, *rule.RuleMessage) {
	position := "leading"
	if !leading {
		position = "trailing"
	}
	hasSingle := false
	hasDouble := false
	if leading {
		hasSingle = strings.HasPrefix(processedName, "_")
		hasDouble = strings.HasPrefix(processedName, "__")
	} else {
		hasSingle = strings.HasSuffix(processedName, "_")
		hasDouble = strings.HasSuffix(processedName, "__")
	}

	switch policy {
	case "allow":
		if leading {
			processedName = trimLeadingUnderscores(processedName)
		} else {
			processedName = trimTrailingUnderscores(processedName)
		}
	case "allowDouble":
		if hasSingle {
			if leading {
				processedName = trimLeadingUnderscores(processedName)
			} else {
				processedName = trimTrailingUnderscores(processedName)
			}
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
	switch typeNode.Kind {
	case ast.KindStringKeyword, ast.KindStringLiteral:
		return "string"
	case ast.KindNumberKeyword, ast.KindNumericLiteral:
		return "number"
	case ast.KindBooleanKeyword, ast.KindTrueKeyword, ast.KindFalseKeyword:
		return "boolean"
	case ast.KindFunctionType, ast.KindConstructorType:
		return "function"
	case ast.KindArrayType, ast.KindTupleType:
		return "array"
	case ast.KindTypeReference:
		typeRef := typeNode.AsTypeReferenceNode()
		if typeRef == nil || typeRef.TypeName == nil {
			return ""
		}
		typeName := typeRef.TypeName.Text()
		if typeName == "Array" || typeName == "ReadonlyArray" {
			return "array"
		}
	case ast.KindUnionType:
		union := typeNode.AsUnionTypeNode()
		if union == nil || union.Types == nil {
			return ""
		}
		candidate := ""
		for _, child := range union.Types.Nodes {
			childCategory := inferTypeCategory(child)
			if childCategory == "" {
				if child.Kind == ast.KindNullKeyword || child.Kind == ast.KindUndefinedKeyword {
					continue
				}
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

func declarationName(node *ast.Node) (string, *ast.Node) {
	if node == nil || node.Name() == nil {
		return "", nil
	}
	nameNode := node.Name()
	switch nameNode.Kind {
	case ast.KindIdentifier:
		return nameNode.AsIdentifier().Text, nameNode
	case ast.KindPrivateIdentifier:
		return "#" + nameNode.AsPrivateIdentifier().Text, nameNode
	case ast.KindStringLiteral:
		return nameNode.AsStringLiteral().Text, nameNode
	case ast.KindNumericLiteral:
		return nameNode.AsNumericLiteral().Text, nameNode
	}
	return "", nil
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
	if flags&ast.ModifierFlagsPrivate != 0 {
		modifiers = append(modifiers, "private")
	}
	if flags&ast.ModifierFlagsProtected != 0 {
		modifiers = append(modifiers, "protected")
	}
	if flags&ast.ModifierFlagsPublic != 0 {
		modifiers = append(modifiers, "public")
	}
	if flags&ast.ModifierFlagsExport != 0 {
		modifiers = append(modifiers, "exported")
	}
	return modifiers
}

func validateCandidate(ctx rule.RuleContext, opts []parsedNamingOption, candidate namingCandidate) {
	if candidate.Name == "" || candidate.NameNode == nil {
		return
	}
	option := pickOption(opts, candidate)
	if option == nil {
		return
	}
	if option.CustomRegex != nil {
		matched := option.CustomRegex.MatchString(candidate.Name)
		if matched != option.CustomMatch {
			regexMatch := "match"
			if option.CustomMatch {
				regexMatch = "not match"
			}
			ctx.ReportNode(candidate.NameNode, buildSatisfyCustomMessage(candidate.TypeName, candidate.Name, option.CustomRegex.String(), regexMatch))
			return
		}
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

	if processedName == "" {
		return
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

		return rule.RuleListeners{
			ast.KindVariableDeclaration: func(node *ast.Node) {
				varDecl := node.AsVariableDeclaration()
				if varDecl == nil {
					return
				}
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				modifiers := declarationModifiers(node)
				if node.Parent != nil && node.Parent.Kind == ast.KindVariableDeclarationList {
					list := node.Parent.AsVariableDeclarationList()
					if list != nil && list.Flags&ast.NodeFlagsConst != 0 {
						modifiers = append(modifiers, "const")
					}
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:         name,
					NameNode:     nameNode,
					Selector:     "variable",
					TypeName:     "Variable",
					Modifiers:    modifiers,
					TypeCategory: inferTypeCategory(varDecl.Type),
				})
			},
			ast.KindFunctionDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				candidateModifiers := declarationModifiers(node)
				if functionDecl := node.AsFunctionDeclaration(); functionDecl != nil && functionDecl.AsteriskToken != nil {
					candidateModifiers = append(candidateModifiers, "generator")
				}
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
				if name == "" || nameNode == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "class",
					TypeName:  "Class",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "interface",
					TypeName:  "Interface",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindTypeAliasDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "typeAlias",
					TypeName:  "Type Alias",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindEnumDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "enum",
					TypeName:  "Enum",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindParameter: func(node *ast.Node) {
				parameter := node.AsParameterDeclaration()
				if parameter == nil || parameter.Name() == nil || parameter.Name().Kind != ast.KindIdentifier {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:         parameter.Name().AsIdentifier().Text,
					NameNode:     parameter.Name(),
					Selector:     "parameter",
					TypeName:     "Parameter",
					Modifiers:    declarationModifiers(node),
					TypeCategory: inferTypeCategory(parameter.Type),
				})
			},
			ast.KindPropertyDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				propDecl := node.AsPropertyDeclaration()
				validateCandidate(ctx, opts, namingCandidate{
					Name:         name,
					NameNode:     nameNode,
					Selector:     "property",
					TypeName:     "Class Property",
					Modifiers:    declarationModifiers(node),
					TypeCategory: inferTypeCategory(propDecl.Type),
				})
			},
			ast.KindMethodDeclaration: func(node *ast.Node) {
				name, nameNode := declarationName(node)
				if name == "" || nameNode == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      name,
					NameNode:  nameNode,
					Selector:  "method",
					TypeName:  "Class Method",
					Modifiers: declarationModifiers(node),
				})
			},
			ast.KindImportSpecifier: func(node *ast.Node) {
				importSpecifier := node.AsImportSpecifier()
				if importSpecifier == nil || importSpecifier.Name() == nil {
					return
				}
				validateCandidate(ctx, opts, namingCandidate{
					Name:      importSpecifier.Name().Text(),
					NameNode:  importSpecifier.Name(),
					Selector:  "import",
					TypeName:  "Import",
					Modifiers: []string{},
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
