package explicit_member_accessibility

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type AccessibilityLevel string

const (
	AccessibilityExplicit AccessibilityLevel = "explicit"
	AccessibilityNoPublic AccessibilityLevel = "no-public"
	AccessibilityOff      AccessibilityLevel = "off"
)

type ExplicitMemberAccessibilityOverrides struct {
	Accessors           AccessibilityLevel `json:"accessors"`
	Constructors        AccessibilityLevel `json:"constructors"`
	Methods             AccessibilityLevel `json:"methods"`
	ParameterProperties AccessibilityLevel `json:"parameterProperties"`
	Properties          AccessibilityLevel `json:"properties"`
}

type ExplicitMemberAccessibilityOptions struct {
	Accessibility      AccessibilityLevel                   `json:"accessibility"`
	IgnoredMethodNames []string                             `json:"ignoredMethodNames"`
	Overrides          ExplicitMemberAccessibilityOverrides `json:"overrides"`
}

func buildMissingAccessibilityMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "missingAccessibility",
		Description: "Missing accessibility modifier.",
	}
}

func buildUnwantedPublicAccessibilityMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unwantedPublicAccessibility",
		Description: "Public accessibility modifier is not allowed.",
	}
}

func parseOptions(options any) ExplicitMemberAccessibilityOptions {
	opts := ExplicitMemberAccessibilityOptions{
		Accessibility: AccessibilityExplicit,
	}

	parseLevel := func(value any) (AccessibilityLevel, bool) {
		level, ok := value.(string)
		if !ok {
			return "", false
		}
		parsed := AccessibilityLevel(level)
		switch parsed {
		case AccessibilityExplicit, AccessibilityNoPublic, AccessibilityOff:
			return parsed, true
		default:
			return "", false
		}
	}

	parseMap := func(m map[string]interface{}) {
		if level, ok := parseLevel(m["accessibility"]); ok {
			opts.Accessibility = level
		}
		if ignored, ok := m["ignoredMethodNames"].([]interface{}); ok {
			names := make([]string, 0, len(ignored))
			for _, value := range ignored {
				if name, ok := value.(string); ok {
					names = append(names, name)
				}
			}
			opts.IgnoredMethodNames = names
		}
		if overrides, ok := m["overrides"].(map[string]interface{}); ok {
			if level, ok := parseLevel(overrides["accessors"]); ok {
				opts.Overrides.Accessors = level
			}
			if level, ok := parseLevel(overrides["constructors"]); ok {
				opts.Overrides.Constructors = level
			}
			if level, ok := parseLevel(overrides["methods"]); ok {
				opts.Overrides.Methods = level
			}
			if level, ok := parseLevel(overrides["parameterProperties"]); ok {
				opts.Overrides.ParameterProperties = level
			}
			if level, ok := parseLevel(overrides["properties"]); ok {
				opts.Overrides.Properties = level
			}
		}
	}

	switch value := options.(type) {
	case []interface{}:
		if len(value) > 0 {
			if m, ok := value[0].(map[string]interface{}); ok {
				parseMap(m)
			}
		}
	case map[string]interface{}:
		parseMap(value)
	}

	return opts
}

func hasAccessibilityModifier(node *ast.Node) bool {
	if node == nil {
		return false
	}
	flags := ast.GetCombinedModifierFlags(node)
	return flags&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected) != 0
}

func hasReadonlyModifier(node *ast.Node) bool {
	if node == nil {
		return false
	}
	return ast.GetCombinedModifierFlags(node)&ast.ModifierFlagsReadonly != 0
}

func getNodeModifiers(node *ast.Node) []*ast.Node {
	if node == nil || node.Modifiers() == nil {
		return nil
	}
	return node.Modifiers().Nodes
}

func getPublicModifierRange(sourceFile *ast.SourceFile, node *ast.Node) (start int, end int, ok bool) {
	for _, modifier := range getNodeModifiers(node) {
		if modifier == nil || modifier.Kind != ast.KindPublicKeyword {
			continue
		}
		trimmed := utils.TrimNodeTextRange(sourceFile, modifier)
		return trimmed.Pos(), trimmed.End(), true
	}
	return 0, 0, false
}

func firstRelevantModifierPos(sourceFile *ast.SourceFile, node *ast.Node) (int, bool) {
	for _, modifier := range getNodeModifiers(node) {
		if modifier == nil || modifier.Kind == ast.KindDecorator {
			continue
		}
		trimmed := utils.TrimNodeTextRange(sourceFile, modifier)
		return trimmed.Pos(), true
	}
	return 0, false
}

func nameRange(sourceFile *ast.SourceFile, nameNode *ast.Node) (int, int, bool) {
	if nameNode == nil {
		return 0, 0, false
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, nameNode)
	if trimmed.End() <= trimmed.Pos() {
		return 0, 0, false
	}
	return trimmed.Pos(), trimmed.End(), true
}

func findKeywordBeforePos(sourceFile *ast.SourceFile, node *ast.Node, beforePos int, keyword string) (int, int, bool) {
	if sourceFile == nil || node == nil || beforePos <= node.Pos() {
		return 0, 0, false
	}
	trimmed := utils.TrimNodeTextRange(sourceFile, node)
	start := trimmed.Pos()
	if beforePos < start {
		return 0, 0, false
	}
	text := sourceFile.Text()
	if beforePos > len(text) || start >= len(text) {
		return 0, 0, false
	}
	segment := text[start:beforePos]
	idx := strings.LastIndex(segment, keyword)
	if idx < 0 {
		return 0, 0, false
	}
	kwStart := start + idx
	kwEnd := kwStart + len(keyword)
	return kwStart, kwEnd, true
}

func methodLikeMissingRange(sourceFile *ast.SourceFile, node *ast.Node) (int, int, bool) {
	if node == nil {
		return 0, 0, false
	}
	switch node.Kind {
	case ast.KindMethodDeclaration:
		name := node.Name()
		if name == nil {
			return 0, 0, false
		}
		_, end, ok := nameRange(sourceFile, name)
		if !ok {
			return 0, 0, false
		}
		if start, ok := firstRelevantModifierPos(sourceFile, node); ok {
			return start, end, true
		}
		return nameRange(sourceFile, name)
	case ast.KindConstructor:
		trimmed := utils.TrimNodeTextRange(sourceFile, node)
		searchEnd := trimmed.End()
		ctor := node.AsConstructorDeclaration()
		if ctor != nil && ctor.Parameters != nil && len(ctor.Parameters.Nodes) > 0 {
			firstParam := ctor.Parameters.Nodes[0]
			if firstParam != nil {
				searchEnd = firstParam.Pos()
			}
		}
		return findKeywordBeforePos(sourceFile, node, searchEnd, "constructor")
	case ast.KindGetAccessor:
		name := node.Name()
		if name == nil {
			return 0, 0, false
		}
		_, end, ok := nameRange(sourceFile, name)
		if !ok {
			return 0, 0, false
		}
		keywordStart, _, ok := findKeywordBeforePos(sourceFile, node, name.Pos(), "get")
		if !ok {
			return 0, 0, false
		}
		return keywordStart, end, true
	case ast.KindSetAccessor:
		name := node.Name()
		if name == nil {
			return 0, 0, false
		}
		_, end, ok := nameRange(sourceFile, name)
		if !ok {
			return 0, 0, false
		}
		keywordStart, _, ok := findKeywordBeforePos(sourceFile, node, name.Pos(), "set")
		if !ok {
			return 0, 0, false
		}
		return keywordStart, end, true
	case ast.KindPropertyDeclaration:
		name := node.Name()
		if name == nil {
			return 0, 0, false
		}
		_, end, ok := nameRange(sourceFile, name)
		if !ok {
			return 0, 0, false
		}
		if start, ok := firstRelevantModifierPos(sourceFile, node); ok {
			return start, end, true
		}
		for _, modifier := range getNodeModifiers(node) {
			if modifier != nil && modifier.Kind == ast.KindAccessorKeyword {
				trimmed := utils.TrimNodeTextRange(sourceFile, modifier)
				return trimmed.Pos(), end, true
			}
		}
		return nameRange(sourceFile, name)
	default:
		return 0, 0, false
	}
}

func parameterPropertyMissingRange(sourceFile *ast.SourceFile, parameter *ast.Node) (int, int, bool) {
	if parameter == nil || parameter.Kind != ast.KindParameter {
		return 0, 0, false
	}
	paramDecl := parameter.AsParameterDeclaration()
	if paramDecl == nil || paramDecl.Name() == nil {
		return 0, 0, false
	}
	start, ok := firstRelevantModifierPos(sourceFile, parameter)
	if !ok {
		trimmed := utils.TrimNodeTextRange(sourceFile, parameter)
		start = trimmed.Pos()
	}
	_, end, ok := nameRange(sourceFile, paramDecl.Name())
	if !ok {
		trimmed := utils.TrimNodeTextRange(sourceFile, parameter)
		end = trimmed.End()
	}
	if end <= start {
		return 0, 0, false
	}
	return start, end, true
}

func methodName(node *ast.Node) string {
	if node == nil {
		return ""
	}
	if node.Kind == ast.KindConstructor {
		return "constructor"
	}
	nameNode := node.Name()
	if nameNode == nil {
		return ""
	}
	switch nameNode.Kind {
	case ast.KindIdentifier:
		return nameNode.AsIdentifier().Text
	case ast.KindStringLiteral:
		return nameNode.AsStringLiteral().Text
	case ast.KindNumericLiteral:
		return nameNode.AsNumericLiteral().Text
	case ast.KindPrivateIdentifier:
		return "#" + nameNode.AsPrivateIdentifier().Text
	case ast.KindComputedPropertyName:
		computed := nameNode.AsComputedPropertyName()
		if computed == nil || computed.Expression == nil {
			return ""
		}
		switch computed.Expression.Kind {
		case ast.KindIdentifier:
			return computed.Expression.AsIdentifier().Text
		case ast.KindStringLiteral:
			return computed.Expression.AsStringLiteral().Text
		case ast.KindNumericLiteral:
			return computed.Expression.AsNumericLiteral().Text
		case ast.KindNoSubstitutionTemplateLiteral:
			return computed.Expression.AsNoSubstitutionTemplateLiteral().Text
		default:
			return ""
		}
	default:
		return ""
	}
}

func isPrivateMemberName(node *ast.Node) bool {
	if node == nil {
		return false
	}
	name := node.Name()
	return name != nil && name.Kind == ast.KindPrivateIdentifier
}

func isParameterProperty(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindParameter {
		return false
	}
	return ast.GetCombinedModifierFlags(node)&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0
}

func reportRange(ctx rule.RuleContext, start int, end int, message rule.RuleMessage) {
	if start < 0 || end <= start {
		return
	}
	ctx.ReportRange(core.NewTextRange(start, end), message)
}

func levelOrDefault(override AccessibilityLevel, base AccessibilityLevel) AccessibilityLevel {
	if override == "" {
		return base
	}
	return override
}

var ExplicitMemberAccessibilityRule = rule.CreateRule(rule.Rule{
	Name: "explicit-member-accessibility",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		baseCheck := opts.Accessibility
		methodCheck := levelOrDefault(opts.Overrides.Methods, baseCheck)
		constructorCheck := levelOrDefault(opts.Overrides.Constructors, baseCheck)
		accessorCheck := levelOrDefault(opts.Overrides.Accessors, baseCheck)
		propertyCheck := levelOrDefault(opts.Overrides.Properties, baseCheck)
		paramPropCheck := levelOrDefault(opts.Overrides.ParameterProperties, baseCheck)

		ignoredMethodNames := map[string]bool{}
		for _, name := range opts.IgnoredMethodNames {
			ignoredMethodNames[name] = true
		}

		checkMethodLike := func(node *ast.Node, level AccessibilityLevel) {
			if node == nil || level == AccessibilityOff || isPrivateMemberName(node) {
				return
			}

			name := methodName(node)
			if ignoredMethodNames[name] {
				return
			}

			switch level {
			case AccessibilityExplicit:
				if hasAccessibilityModifier(node) {
					return
				}
				start, end, ok := methodLikeMissingRange(ctx.SourceFile, node)
				if !ok {
					return
				}
				reportRange(ctx, start, end, buildMissingAccessibilityMessage())
			case AccessibilityNoPublic:
				start, end, ok := getPublicModifierRange(ctx.SourceFile, node)
				if !ok {
					return
				}
				reportRange(ctx, start, end, buildUnwantedPublicAccessibilityMessage())
			}
		}

		checkProperty := func(node *ast.Node) {
			if node == nil || propertyCheck == AccessibilityOff || isPrivateMemberName(node) {
				return
			}

			switch propertyCheck {
			case AccessibilityExplicit:
				if hasAccessibilityModifier(node) {
					return
				}
				start, end, ok := methodLikeMissingRange(ctx.SourceFile, node)
				if !ok {
					return
				}
				reportRange(ctx, start, end, buildMissingAccessibilityMessage())
			case AccessibilityNoPublic:
				start, end, ok := getPublicModifierRange(ctx.SourceFile, node)
				if !ok {
					return
				}
				reportRange(ctx, start, end, buildUnwantedPublicAccessibilityMessage())
			}
		}

		checkConstructorParameters := func(node *ast.Node) {
			if node == nil || paramPropCheck == AccessibilityOff {
				return
			}
			constructor := node.AsConstructorDeclaration()
			if constructor == nil || constructor.Parameters == nil {
				return
			}
			for _, param := range constructor.Parameters.Nodes {
				if !isParameterProperty(param) {
					continue
				}
				switch paramPropCheck {
				case AccessibilityExplicit:
					if hasAccessibilityModifier(param) {
						continue
					}
					start, end, ok := parameterPropertyMissingRange(ctx.SourceFile, param)
					if !ok {
						continue
					}
					reportRange(ctx, start, end, buildMissingAccessibilityMessage())
				case AccessibilityNoPublic:
					// Match upstream behavior: only report public readonly parameter properties.
					if !hasReadonlyModifier(param) {
						continue
					}
					start, end, ok := getPublicModifierRange(ctx.SourceFile, param)
					if !ok {
						continue
					}
					reportRange(ctx, start, end, buildUnwantedPublicAccessibilityMessage())
				}
			}
		}

		return rule.RuleListeners{
			ast.KindMethodDeclaration: func(node *ast.Node) {
				checkMethodLike(node, methodCheck)
			},
			ast.KindConstructor: func(node *ast.Node) {
				checkMethodLike(node, constructorCheck)
				checkConstructorParameters(node)
			},
			ast.KindGetAccessor: func(node *ast.Node) {
				checkMethodLike(node, accessorCheck)
			},
			ast.KindSetAccessor: func(node *ast.Node) {
				checkMethodLike(node, accessorCheck)
			},
			ast.KindPropertyDeclaration: checkProperty,
		}
	},
})
