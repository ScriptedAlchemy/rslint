package member_ordering

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type memberTypeGroup []string

type memberOrderingConfig struct {
	memberTypes      []memberTypeGroup
	memberTypesNever bool
	order            string
	optionalityOrder string
}

type memberOrderingOptions struct {
	defaultConfig      memberOrderingConfig
	classesConfig      *memberOrderingConfig
	classExprConfig    *memberOrderingConfig
	interfacesConfig   *memberOrderingConfig
	typeLiteralsConfig *memberOrderingConfig
}

type memberInfo struct {
	node          *ast.Node
	name          string
	nameKey       string
	groupIndex    int
	optional      bool
	isStatic      bool
	isAbstract    bool
	isDecorated   bool
	isReadonly    bool
	isPrivateName bool
	accessibility string
	kind          string
}

func buildIncorrectOrderMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "incorrectOrder",
		Description: "Member order is incorrect.",
	}
}

func buildIncorrectGroupOrderMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "incorrectGroupOrder",
		Description: "Member group order is incorrect.",
	}
}

func buildIncorrectRequiredMembersOrderMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "incorrectRequiredMembersOrder",
		Description: "Optional and required members are in the wrong order.",
	}
}

func defaultConfig() memberOrderingConfig {
	return memberOrderingConfig{
		memberTypes: []memberTypeGroup{
			{"signature"},
			{"call-signature"},
			{"public-static-field"},
			{"protected-static-field"},
			{"private-static-field"},
			{"#private-static-field"},
			{"public-decorated-field"},
			{"protected-decorated-field"},
			{"private-decorated-field"},
			{"public-instance-field"},
			{"protected-instance-field"},
			{"private-instance-field"},
			{"#private-instance-field"},
			{"public-abstract-field"},
			{"protected-abstract-field"},
			{"public-field"},
			{"protected-field"},
			{"private-field"},
			{"#private-field"},
			{"static-field"},
			{"instance-field"},
			{"abstract-field"},
			{"decorated-field"},
			{"field"},
			{"static-initialization"},
			{"public-constructor"},
			{"protected-constructor"},
			{"private-constructor"},
			{"constructor"},
			{"public-static-accessor"},
			{"protected-static-accessor"},
			{"private-static-accessor"},
			{"#private-static-accessor"},
			{"public-decorated-accessor"},
			{"protected-decorated-accessor"},
			{"private-decorated-accessor"},
			{"public-instance-accessor"},
			{"protected-instance-accessor"},
			{"private-instance-accessor"},
			{"#private-instance-accessor"},
			{"public-abstract-accessor"},
			{"protected-abstract-accessor"},
			{"public-accessor"},
			{"protected-accessor"},
			{"private-accessor"},
			{"#private-accessor"},
			{"static-accessor"},
			{"instance-accessor"},
			{"abstract-accessor"},
			{"decorated-accessor"},
			{"accessor"},
			{"public-static-get"},
			{"protected-static-get"},
			{"private-static-get"},
			{"#private-static-get"},
			{"public-decorated-get"},
			{"protected-decorated-get"},
			{"private-decorated-get"},
			{"public-instance-get"},
			{"protected-instance-get"},
			{"private-instance-get"},
			{"#private-instance-get"},
			{"public-abstract-get"},
			{"protected-abstract-get"},
			{"public-get"},
			{"protected-get"},
			{"private-get"},
			{"#private-get"},
			{"static-get"},
			{"instance-get"},
			{"abstract-get"},
			{"decorated-get"},
			{"get"},
			{"public-static-set"},
			{"protected-static-set"},
			{"private-static-set"},
			{"#private-static-set"},
			{"public-decorated-set"},
			{"protected-decorated-set"},
			{"private-decorated-set"},
			{"public-instance-set"},
			{"protected-instance-set"},
			{"private-instance-set"},
			{"#private-instance-set"},
			{"public-abstract-set"},
			{"protected-abstract-set"},
			{"public-set"},
			{"protected-set"},
			{"private-set"},
			{"#private-set"},
			{"static-set"},
			{"instance-set"},
			{"abstract-set"},
			{"decorated-set"},
			{"set"},
			{"public-static-method"},
			{"protected-static-method"},
			{"private-static-method"},
			{"#private-static-method"},
			{"public-decorated-method"},
			{"protected-decorated-method"},
			{"private-decorated-method"},
			{"public-instance-method"},
			{"protected-instance-method"},
			{"private-instance-method"},
			{"#private-instance-method"},
			{"public-abstract-method"},
			{"protected-abstract-method"},
			{"public-method"},
			{"protected-method"},
			{"private-method"},
			{"#private-method"},
			{"static-method"},
			{"instance-method"},
			{"abstract-method"},
			{"decorated-method"},
			{"method"},
		},
		order: "as-written",
	}
}

func parseOptions(options any) memberOrderingOptions {
	parsed := memberOrderingOptions{
		defaultConfig: defaultConfig(),
	}
	if options == nil {
		return parsed
	}

	var optsMap map[string]interface{}
	switch value := options.(type) {
	case []interface{}:
		if len(value) == 0 {
			return parsed
		}
		first, ok := value[0].(map[string]interface{})
		if !ok {
			return parsed
		}
		optsMap = first
	case map[string]interface{}:
		optsMap = value
	default:
		return parsed
	}

	if defaultRaw, ok := optsMap["default"]; ok {
		parsed.defaultConfig = parseMemberOrderingConfigRaw(defaultRaw, parsed.defaultConfig)
	}
	if classesRaw, ok := optsMap["classes"]; ok {
		cfg := parseMemberOrderingConfigRaw(classesRaw, parsed.defaultConfig)
		parsed.classesConfig = &cfg
	}
	if classExprRaw, ok := optsMap["classExpressions"]; ok {
		cfg := parseMemberOrderingConfigRaw(classExprRaw, parsed.defaultConfig)
		parsed.classExprConfig = &cfg
	}
	if interfacesRaw, ok := optsMap["interfaces"]; ok {
		cfg := parseMemberOrderingConfigRaw(interfacesRaw, parsed.defaultConfig)
		parsed.interfacesConfig = &cfg
	}
	if typeLiteralsRaw, ok := optsMap["typeLiterals"]; ok {
		cfg := parseMemberOrderingConfigRaw(typeLiteralsRaw, parsed.defaultConfig)
		parsed.typeLiteralsConfig = &cfg
	}
	return parsed
}

func parseMemberOrderingConfigRaw(raw interface{}, base memberOrderingConfig) memberOrderingConfig {
	switch value := raw.(type) {
	case map[string]interface{}:
		return parseMemberOrderingConfig(value, base)
	case string, []interface{}:
		return parseMemberOrderingConfig(map[string]interface{}{
			"memberTypes": value,
		}, base)
	default:
		return base
	}
}

func parseMemberOrderingConfig(configMap map[string]interface{}, base memberOrderingConfig) memberOrderingConfig {
	cfg := base
	if configMap == nil {
		return cfg
	}

	if order, ok := configMap["order"].(string); ok && order != "" {
		cfg.order = order
	}
	if optionalityOrder, ok := configMap["optionalityOrder"].(string); ok && optionalityOrder != "" {
		cfg.optionalityOrder = optionalityOrder
	}
	if memberTypes, hasMemberTypes := configMap["memberTypes"]; hasMemberTypes {
		cfg.memberTypesNever = false
		cfg.memberTypes = nil

		if memberTypesValue, ok := memberTypes.(string); ok {
			if memberTypesValue == "never" {
				cfg.memberTypesNever = true
				return cfg
			}
			cfg.memberTypes = []memberTypeGroup{{memberTypesValue}}
			return cfg
		}

		if arr, ok := memberTypes.([]interface{}); ok {
			memberGroups := make([]memberTypeGroup, 0, len(arr))
			for _, item := range arr {
				switch v := item.(type) {
				case string:
					memberGroups = append(memberGroups, memberTypeGroup{v})
				case []interface{}:
					group := make(memberTypeGroup, 0, len(v))
					for _, inner := range v {
						s, ok := inner.(string)
						if !ok || s == "" {
							continue
						}
						group = append(group, s)
					}
					if len(group) > 0 {
						memberGroups = append(memberGroups, group)
					}
				}
			}
			if len(memberGroups) > 0 {
				cfg.memberTypes = memberGroups
			}
		}
	}
	return cfg
}

func effectiveConfig(node *ast.Node, opts memberOrderingOptions) memberOrderingConfig {
	switch node.Kind {
	case ast.KindClassDeclaration:
		if opts.classesConfig != nil {
			return *opts.classesConfig
		}
	case ast.KindClassExpression:
		if opts.classExprConfig != nil {
			return *opts.classExprConfig
		}
	case ast.KindInterfaceDeclaration:
		if opts.interfacesConfig != nil {
			return *opts.interfacesConfig
		}
	case ast.KindTypeLiteral:
		if opts.typeLiteralsConfig != nil {
			return *opts.typeLiteralsConfig
		}
	}
	return opts.defaultConfig
}

func collectMembers(ctx rule.RuleContext, container *ast.Node, cfg memberOrderingConfig) []memberInfo {
	members := membersForContainer(container)
	if len(members) == 0 {
		return nil
	}

	collected := make([]memberInfo, 0, len(members))
	for _, member := range members {
		if member == nil {
			continue
		}
		info := buildMemberInfo(ctx, member)
		info.groupIndex = memberGroupIndex(info, cfg)
		collected = append(collected, info)
	}
	return collected
}

func membersForContainer(container *ast.Node) []*ast.Node {
	if container == nil {
		return nil
	}
	switch container.Kind {
	case ast.KindClassDeclaration:
		classDeclaration := container.AsClassDeclaration()
		if classDeclaration != nil && classDeclaration.Members != nil {
			return classDeclaration.Members.Nodes
		}
	case ast.KindClassExpression:
		classExpression := container.AsClassExpression()
		if classExpression != nil && classExpression.Members != nil {
			return classExpression.Members.Nodes
		}
	case ast.KindInterfaceDeclaration:
		interfaceDeclaration := container.AsInterfaceDeclaration()
		if interfaceDeclaration != nil && interfaceDeclaration.Members != nil {
			return interfaceDeclaration.Members.Nodes
		}
	case ast.KindTypeLiteral:
		typeLiteral := container.AsTypeLiteralNode()
		if typeLiteral != nil && typeLiteral.Members != nil {
			return typeLiteral.Members.Nodes
		}
	}
	return nil
}

func buildMemberInfo(ctx rule.RuleContext, node *ast.Node) memberInfo {
	info := memberInfo{
		node:          node,
		name:          memberName(ctx, node),
		optional:      isOptionalMember(node),
		isStatic:      ast.HasSyntacticModifier(node, ast.ModifierFlagsStatic),
		isAbstract:    ast.HasSyntacticModifier(node, ast.ModifierFlagsAbstract),
		isReadonly:    ast.HasSyntacticModifier(node, ast.ModifierFlagsReadonly),
		isDecorated:   utils.IncludesModifier(node, ast.KindDecorator),
		isPrivateName: node.Name() != nil && node.Name().Kind == ast.KindPrivateIdentifier,
		accessibility: memberAccessibility(node),
		kind:          memberKind(node),
	}
	if info.name == "" {
		info.name = info.kind
	}
	info.nameKey = normalizeMemberNameForSorting(info.name)
	return info
}

func normalizeMemberNameForSorting(name string) string {
	name = strings.TrimSpace(name)
	if len(name) >= 2 {
		if (name[0] == '"' && name[len(name)-1] == '"') || (name[0] == '\'' && name[len(name)-1] == '\'') {
			name = name[1 : len(name)-1]
		}
	}
	return name
}

func memberName(ctx rule.RuleContext, node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindConstructor, ast.KindConstructSignature:
		return "new"
	case ast.KindCallSignature:
		return "call"
	case ast.KindClassStaticBlockDeclaration:
		return "static"
	case ast.KindIndexSignature:
		indexSignature := node.AsIndexSignatureDeclaration()
		if indexSignature != nil && indexSignature.Parameters != nil && len(indexSignature.Parameters.Nodes) > 0 {
			parameter := indexSignature.Parameters.Nodes[0]
			if parameter != nil && parameter.Name() != nil {
				switch parameter.Name().Kind {
				case ast.KindIdentifier:
					return parameter.Name().AsIdentifier().Text
				case ast.KindStringLiteral:
					return parameter.Name().AsStringLiteral().Text
				case ast.KindNumericLiteral:
					return parameter.Name().AsNumericLiteral().Text
				}
			}
		}
		return "index"
	}
	nameNode := node.Name()
	if nameNode == nil || ctx.SourceFile == nil {
		return ""
	}
	name, _ := utils.GetNameFromMember(ctx.SourceFile, nameNode)
	return name
}

func memberKind(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case ast.KindPropertyDeclaration, ast.KindPropertySignature:
		if utils.IncludesModifier(node, ast.KindAccessorKeyword) {
			return "accessor"
		}
		if node.Kind == ast.KindPropertyDeclaration {
			propertyDeclaration := node.AsPropertyDeclaration()
			if propertyDeclaration != nil && propertyDeclaration.Initializer != nil {
				switch propertyDeclaration.Initializer.Kind {
				case ast.KindArrowFunction, ast.KindFunctionExpression:
					return "method"
				}
			}
		}
		return "field"
	case ast.KindMethodDeclaration, ast.KindMethodSignature:
		return "method"
	case ast.KindGetAccessor:
		return "get"
	case ast.KindSetAccessor:
		return "set"
	case ast.KindConstructor:
		return "constructor"
	case ast.KindConstructSignature:
		return "construct-signature"
	case ast.KindCallSignature:
		return "call-signature"
	case ast.KindIndexSignature:
		return "signature"
	case ast.KindClassStaticBlockDeclaration:
		return "static-initialization"
	}
	return "field"
}

func memberAccessibility(node *ast.Node) string {
	if node == nil {
		return ""
	}
	switch {
	case ast.HasSyntacticModifier(node, ast.ModifierFlagsPrivate):
		return "private"
	case ast.HasSyntacticModifier(node, ast.ModifierFlagsProtected):
		return "protected"
	case ast.HasSyntacticModifier(node, ast.ModifierFlagsPublic):
		return "public"
	default:
		return "public"
	}
}

func isOptionalMember(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if node.QuestionToken() != nil {
		return true
	}
	if node.Kind == ast.KindIndexSignature {
		indexSignature := node.AsIndexSignatureDeclaration()
		if indexSignature == nil || indexSignature.Parameters == nil || len(indexSignature.Parameters.Nodes) == 0 {
			return false
		}
		parameter := indexSignature.Parameters.Nodes[0]
		return parameter != nil && parameter.QuestionToken() != nil
	}
	return false
}

func memberGroupIndex(member memberInfo, cfg memberOrderingConfig) int {
	if cfg.memberTypesNever || len(cfg.memberTypes) == 0 {
		return 0
	}
	for index, group := range cfg.memberTypes {
		for _, token := range group {
			if memberMatchesGroup(member, token) {
				return index
			}
		}
	}
	return len(cfg.memberTypes)
}

func memberMatchesGroup(member memberInfo, group string) bool {
	if group == "" {
		return false
	}
	if group == "never" {
		return true
	}

	baseKinds := []string{
		"static-initialization",
		"call-signature",
		"construct-signature",
		"index-signature",
		"constructor",
		"accessor",
		"method",
		"field",
		"get",
		"set",
		"signature",
	}

	base := ""
	for _, candidate := range baseKinds {
		if group == candidate || strings.HasSuffix(group, "-"+candidate) {
			base = candidate
			break
		}
	}
	if base == "" {
		return false
	}

	if !memberMatchesBase(member, base) {
		return false
	}

	prefix := strings.TrimSuffix(group, base)
	prefix = strings.TrimSuffix(prefix, "-")
	if prefix == "" {
		if member.isAbstract || member.isDecorated {
			return false
		}
		return true
	}
	hasAbstract := false
	hasDecorated := false
	for _, token := range strings.Split(prefix, "-") {
		switch token {
		case "public":
			if member.accessibility != "public" || member.isPrivateName {
				return false
			}
		case "protected":
			if member.accessibility != "protected" {
				return false
			}
		case "private":
			if member.accessibility != "private" {
				return false
			}
		case "#private":
			if !member.isPrivateName {
				return false
			}
		case "static":
			if !member.isStatic {
				return false
			}
		case "instance":
			if member.isStatic {
				return false
			}
		case "abstract":
			hasAbstract = true
			if !member.isAbstract {
				return false
			}
		case "decorated":
			hasDecorated = true
			if !member.isDecorated {
				return false
			}
		case "readonly":
			if !member.isReadonly {
				return false
			}
		default:
			return false
		}
	}
	if member.isAbstract && !hasAbstract {
		return false
	}
	if member.isDecorated && !hasDecorated {
		return false
	}
	return true
}

func memberMatchesBase(member memberInfo, base string) bool {
	switch base {
	case "field":
		return member.kind == "field"
	case "method":
		return member.kind == "method"
	case "get":
		return member.kind == "get"
	case "set":
		return member.kind == "set"
	case "accessor":
		return member.kind == "accessor"
	case "constructor":
		return member.kind == "constructor" || member.kind == "construct-signature" || member.nameKey == "new"
	case "construct-signature":
		return member.node != nil && member.node.Kind == ast.KindConstructSignature
	case "call-signature":
		return member.kind == "call-signature"
	case "index-signature":
		return member.kind == "signature"
	case "signature":
		return member.kind == "signature"
	case "static-initialization":
		return member.kind == "static-initialization"
	default:
		return false
	}
}

func compareMemberName(left, right string, order string) int {
	switch order {
	case "alphabetically":
		return strings.Compare(left, right)
	case "alphabetically-case-insensitive":
		return strings.Compare(strings.ToLower(left), strings.ToLower(right))
	case "natural":
		return compareNatural(left, right, false)
	case "natural-case-insensitive":
		return compareNatural(left, right, true)
	default:
		return 0
	}
}

func compareNatural(left, right string, caseInsensitive bool) int {
	leftParts := splitNaturalParts(left)
	rightParts := splitNaturalParts(right)
	limit := len(leftParts)
	if len(rightParts) < limit {
		limit = len(rightParts)
	}

	for i := range limit {
		leftPart := leftParts[i]
		rightPart := rightParts[i]

		leftIsNumber := isNumericString(leftPart)
		rightIsNumber := isNumericString(rightPart)
		if leftIsNumber && rightIsNumber {
			numberCompare := compareNumericStrings(leftPart, rightPart)
			if numberCompare != 0 {
				return numberCompare
			}
			continue
		}

		compareLeft := leftPart
		compareRight := rightPart
		if caseInsensitive {
			compareLeft = strings.ToLower(compareLeft)
			compareRight = strings.ToLower(compareRight)
		}
		partCompare := strings.Compare(compareLeft, compareRight)
		if partCompare != 0 {
			return partCompare
		}
	}

	if len(leftParts) != len(rightParts) {
		if len(leftParts) < len(rightParts) {
			return -1
		}
		return 1
	}
	if caseInsensitive {
		return 0
	}
	return strings.Compare(left, right)
}

func splitNaturalParts(value string) []string {
	if value == "" {
		return []string{""}
	}
	parts := []string{}
	start := 0
	inDigits := unicode.IsDigit(rune(value[0]))
	for i := 1; i < len(value); i++ {
		isDigit := unicode.IsDigit(rune(value[i]))
		if isDigit == inDigits {
			continue
		}
		parts = append(parts, value[start:i])
		start = i
		inDigits = isDigit
	}
	parts = append(parts, value[start:])
	return parts
}

func isNumericString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func compareNumericStrings(left, right string) int {
	leftInt := new(big.Int)
	rightInt := new(big.Int)
	_, leftOK := leftInt.SetString(left, 10)
	_, rightOK := rightInt.SetString(right, 10)
	if !leftOK || !rightOK {
		return strings.Compare(left, right)
	}
	return leftInt.Cmp(rightInt)
}

func optionalityKey(member memberInfo, optionalityOrder string) int {
	switch optionalityOrder {
	case "required-first":
		if member.optional {
			return 1
		}
		return 0
	case "optional-first":
		if member.optional {
			return 0
		}
		return 1
	default:
		return 0
	}
}

func checkOrdering(ctx rule.RuleContext, members []memberInfo, cfg memberOrderingConfig) {
	if len(members) < 2 {
		return
	}

	if !cfg.memberTypesNever && len(cfg.memberTypes) > 0 {
		maxSeenGroup := -1
		for _, member := range members {
			if member.groupIndex >= len(cfg.memberTypes) {
				continue
			}
			if member.groupIndex < maxSeenGroup {
				ctx.ReportNode(member.node, buildIncorrectGroupOrderMessage())
				continue
			}
			if member.groupIndex > maxSeenGroup {
				maxSeenGroup = member.groupIndex
			}
		}
	}

	if cfg.optionalityOrder != "" {
		type optionalityState struct {
			firstOptional *memberInfo
			firstRequired *memberInfo
			reported      bool
		}
		stateByGroup := map[int]*optionalityState{}
		for i := range members {
			member := &members[i]
			if !cfg.memberTypesNever && len(cfg.memberTypes) > 0 && member.groupIndex >= len(cfg.memberTypes) {
				continue
			}
			state, ok := stateByGroup[member.groupIndex]
			if !ok {
				state = &optionalityState{}
				stateByGroup[member.groupIndex] = state
			}
			switch cfg.optionalityOrder {
			case "required-first":
				if member.optional {
					if state.firstOptional == nil {
						state.firstOptional = member
					}
					continue
				}
				if state.firstOptional != nil && !state.reported {
					ctx.ReportNode(state.firstOptional.node, buildIncorrectRequiredMembersOrderMessage())
					state.reported = true
				}
			case "optional-first":
				if !member.optional {
					if state.firstRequired == nil {
						state.firstRequired = member
					}
					continue
				}
				if state.firstRequired != nil && !state.reported {
					ctx.ReportNode(state.firstRequired.node, buildIncorrectRequiredMembersOrderMessage())
					state.reported = true
				}
			}
		}
	}

	if cfg.order == "" || cfg.order == "as-written" {
		return
	}

	previousByKey := map[string]memberInfo{}
	for _, member := range members {
		if !cfg.memberTypesNever && len(cfg.memberTypes) > 0 && member.groupIndex >= len(cfg.memberTypes) {
			continue
		}
		if !isNameComparableMember(member) {
			continue
		}
		key := fmt.Sprintf("%d:%d", member.groupIndex, optionalityKey(member, cfg.optionalityOrder))
		if cfg.memberTypesNever {
			bucket := memberNameOrderBucket(member)
			if bucket == "" {
				continue
			}
			key = fmt.Sprintf("never:%s:%d", bucket, optionalityKey(member, cfg.optionalityOrder))
		}
		prev, exists := previousByKey[key]
		if exists && compareMemberName(prev.nameKey, member.nameKey, cfg.order) > 0 {
			ctx.ReportNode(member.node, buildIncorrectOrderMessage())
		}
		previousByKey[key] = member
	}
}

func memberNameOrderBucket(member memberInfo) string {
	switch member.kind {
	case "signature":
		return ""
	case "call-signature", "construct-signature", "constructor":
		return "signature-call-construct"
	default:
		return "main"
	}
}

func isNameComparableMember(member memberInfo) bool {
	if member.kind == "static-initialization" {
		return false
	}
	switch member.kind {
	case "field", "method", "get", "set", "accessor", "call-signature", "construct-signature", "constructor":
		return true
	default:
		return false
	}
}

func checkMemberOrderingNode(ctx rule.RuleContext, node *ast.Node, opts memberOrderingOptions) {
	if node == nil {
		return
	}
	cfg := effectiveConfig(node, opts)
	members := collectMembers(ctx, node, cfg)
	if len(members) == 0 {
		return
	}

	// Preserve original source order.
	sort.SliceStable(members, func(i, j int) bool {
		return members[i].node.Pos() < members[j].node.Pos()
	})
	checkOrdering(ctx, members, cfg)
}

func createMemberOrderingRule(ruleName string) rule.Rule {
	return rule.CreateRule(rule.Rule{
		Name: ruleName,
		Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
			opts := parseOptions(options)
			return rule.RuleListeners{
				ast.KindClassDeclaration: func(node *ast.Node) {
					checkMemberOrderingNode(ctx, node, opts)
				},
				ast.KindClassExpression: func(node *ast.Node) {
					checkMemberOrderingNode(ctx, node, opts)
				},
				ast.KindInterfaceDeclaration: func(node *ast.Node) {
					checkMemberOrderingNode(ctx, node, opts)
				},
				ast.KindTypeLiteral: func(node *ast.Node) {
					checkMemberOrderingNode(ctx, node, opts)
				},
			}
		},
	})
}

var MemberOrderingRule = createMemberOrderingRule("member-ordering")
var MemberOrderingAlphabeticallyOrderAliasRule = createMemberOrderingRule("member-ordering-alphabetically-order")
var MemberOrderingAlphabeticallyCaseInsensitiveOrderAliasRule = createMemberOrderingRule("member-ordering-alphabetically-case-insensitive-order")
var MemberOrderingNaturalOrderAliasRule = createMemberOrderingRule("member-ordering-natural-order")
var MemberOrderingNaturalCaseInsensitiveOrderAliasRule = createMemberOrderingRule("member-ordering-natural-case-insensitive-order")
var MemberOrderingRequiredAliasRule = createMemberOrderingRule("member-ordering-required")
