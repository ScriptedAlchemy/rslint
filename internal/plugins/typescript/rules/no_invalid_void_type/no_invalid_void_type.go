package no_invalid_void_type

import (
	"encoding/json"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type NoInvalidVoidTypeOptions struct {
	AllowInGenericTypeArguments interface{} `json:"allowInGenericTypeArguments"`
	AllowAsThisParameter        bool        `json:"allowAsThisParameter"`
}

type parsedNoInvalidVoidTypeOptions struct {
	allowAsThisParameter bool
	genericMode          string // all | none | whitelist
	genericAllowlist     map[string]struct{}
}

func buildInvalidVoidForGenericMessage(generic string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidVoidForGeneric",
		Description: generic + " may not have void as a type argument.",
	}
}

func buildInvalidVoidNotReturnMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidVoidNotReturn",
		Description: "void is only valid as a return type.",
	}
}

func buildInvalidVoidNotReturnOrGenericMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidVoidNotReturnOrGeneric",
		Description: "void is only valid as a return type or generic type argument.",
	}
}

func buildInvalidVoidNotReturnOrThisParamMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidVoidNotReturnOrThisParam",
		Description: "void is only valid as return type or type of `this` parameter.",
	}
}

func buildInvalidVoidNotReturnOrThisParamOrGenericMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidVoidNotReturnOrThisParamOrGeneric",
		Description: "void is only valid as a return type or generic type argument or the type of a `this` parameter.",
	}
}

func buildInvalidVoidUnionConstituentMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidVoidUnionConstituent",
		Description: "void is not valid as a constituent in a union type",
	}
}

func normalizeQualifiedName(text string) string {
	return strings.Join(strings.Fields(text), "")
}

func parseOptions(options any) parsedNoInvalidVoidTypeOptions {
	result := parsedNoInvalidVoidTypeOptions{
		allowAsThisParameter: false,
		genericMode:          "all",
		genericAllowlist:     map[string]struct{}{},
	}

	raw := NoInvalidVoidTypeOptions{
		AllowInGenericTypeArguments: true,
		AllowAsThisParameter:        false,
	}

	applyJSON := func(value any) {
		if value == nil {
			return
		}
		payload, err := json.Marshal(value)
		if err != nil {
			return
		}
		_ = json.Unmarshal(payload, &raw)
	}

	switch value := options.(type) {
	case NoInvalidVoidTypeOptions:
		raw = value
	case *NoInvalidVoidTypeOptions:
		if value != nil {
			raw = *value
		}
	case map[string]interface{}:
		applyJSON(value)
	case []interface{}:
		if len(value) > 0 {
			applyJSON(value[0])
		}
	default:
		if value != nil {
			applyJSON(value)
		}
	}

	result.allowAsThisParameter = raw.AllowAsThisParameter

	switch value := raw.AllowInGenericTypeArguments.(type) {
	case bool:
		if value {
			result.genericMode = "all"
		} else {
			result.genericMode = "none"
		}
	case []string:
		result.genericMode = "whitelist"
		for _, item := range value {
			result.genericAllowlist[normalizeQualifiedName(item)] = struct{}{}
		}
	case []interface{}:
		result.genericMode = "whitelist"
		for _, item := range value {
			name, ok := item.(string)
			if !ok {
				continue
			}
			result.genericAllowlist[normalizeQualifiedName(name)] = struct{}{}
		}
	default:
		result.genericMode = "all"
	}

	return result
}

func (opts parsedNoInvalidVoidTypeOptions) allowsGenericTypeArguments() bool {
	return opts.genericMode != "none"
}

func buildDefaultInvalidMessage(node *ast.Node, opts parsedNoInvalidVoidTypeOptions) rule.RuleMessage {
	if opts.allowsGenericTypeArguments() && opts.allowAsThisParameter {
		return buildInvalidVoidNotReturnOrThisParamOrGenericMessage()
	}
	if opts.allowsGenericTypeArguments() {
		if node != nil && node.Parent != nil && node.Parent.Kind == ast.KindUnionType {
			return buildInvalidVoidUnionConstituentMessage()
		}
		return buildInvalidVoidNotReturnOrGenericMessage()
	}
	if opts.allowAsThisParameter {
		return buildInvalidVoidNotReturnOrThisParamMessage()
	}
	return buildInvalidVoidNotReturnMessage()
}

func containsNode(target *ast.Node, node *ast.Node) bool {
	if target == nil || node == nil {
		return false
	}
	for current := node; current != nil; current = current.Parent {
		if current == target {
			return true
		}
	}
	return false
}

func containsVoidKeyword(node *ast.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == ast.KindVoidKeyword {
		return true
	}
	found := false
	node.ForEachChild(func(child *ast.Node) bool {
		if containsVoidKeyword(child) {
			found = true
			return true
		}
		return false
	})
	return found
}

func isUnionAllowed(union *ast.UnionTypeNode) bool {
	if union == nil || union.Types == nil {
		return false
	}
	for _, member := range union.Types.Nodes {
		if member == nil {
			return false
		}
		switch member.Kind {
		case ast.KindVoidKeyword, ast.KindNeverKeyword:
			continue
		case ast.KindTypeReference:
			typeRef := member.AsTypeReferenceNode()
			if typeRef == nil || typeRef.TypeArguments == nil || len(typeRef.TypeArguments.Nodes) == 0 {
				return false
			}
			hasVoidTypeArg := false
			for _, typeArg := range typeRef.TypeArguments.Nodes {
				if containsVoidKeyword(typeArg) {
					hasVoidTypeArg = true
					break
				}
			}
			if !hasVoidTypeArg {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func staticNameFromNode(node *ast.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	switch node.Kind {
	case ast.KindIdentifier, ast.KindStringLiteral, ast.KindNumericLiteral, ast.KindNoSubstitutionTemplateLiteral:
		return node.Text(), true
	case ast.KindComputedPropertyName:
		computed := node.AsComputedPropertyName()
		if computed == nil || computed.Expression == nil {
			return "", false
		}
		return staticNameFromNode(computed.Expression)
	default:
		return "", false
	}
}

func hasFunctionOverloadSignatures(node *ast.Node, fn *ast.FunctionDeclaration) bool {
	if node == nil || fn == nil || fn.Name() == nil || node.Parent == nil {
		return false
	}
	var siblings []*ast.Node
	switch node.Parent.Kind {
	case ast.KindSourceFile:
		source := node.Parent.AsSourceFile()
		if source == nil || source.Statements == nil {
			return false
		}
		siblings = source.Statements.Nodes
	case ast.KindModuleBlock:
		module := node.Parent.AsModuleBlock()
		if module == nil || module.Statements == nil {
			return false
		}
		siblings = module.Statements.Nodes
	case ast.KindBlock:
		block := node.Parent.AsBlock()
		if block == nil || block.Statements == nil {
			return false
		}
		siblings = block.Statements.Nodes
	default:
		return false
	}

	targetName := fn.Name().Text()
	for _, sibling := range siblings {
		if sibling == nil {
			continue
		}
		if sibling == node {
			break
		}
		if sibling.Kind != ast.KindFunctionDeclaration {
			continue
		}
		overload := sibling.AsFunctionDeclaration()
		if overload == nil || overload.Body != nil || overload.Name() == nil {
			continue
		}
		if overload.Name().Text() == targetName {
			return true
		}
	}
	return false
}

func hasMethodOverloadSignatures(node *ast.Node, method *ast.MethodDeclaration) bool {
	if node == nil || method == nil || method.Name() == nil || node.Parent == nil {
		return false
	}
	targetName, ok := staticNameFromNode(method.Name())
	if !ok {
		return false
	}
	targetStatic := ast.HasSyntacticModifier(node, ast.ModifierFlagsStatic)

	var members []*ast.Node
	switch node.Parent.Kind {
	case ast.KindClassDeclaration:
		classDecl := node.Parent.AsClassDeclaration()
		if classDecl == nil || classDecl.Members == nil {
			return false
		}
		members = classDecl.Members.Nodes
	case ast.KindClassExpression:
		classExpr := node.Parent.AsClassExpression()
		if classExpr == nil || classExpr.Members == nil {
			return false
		}
		members = classExpr.Members.Nodes
	default:
		return false
	}

	for _, member := range members {
		if member == nil {
			continue
		}
		if member == node {
			break
		}
		if member.Kind != ast.KindMethodDeclaration {
			continue
		}
		overload := member.AsMethodDeclaration()
		if overload == nil || overload.Body != nil || overload.Name() == nil {
			continue
		}
		if ast.HasSyntacticModifier(member, ast.ModifierFlagsStatic) != targetStatic {
			continue
		}
		name, ok := staticNameFromNode(overload.Name())
		if ok && name == targetName {
			return true
		}
	}
	return false
}

func isUnionInOverloadImplementation(unionNode *ast.Node) bool {
	if unionNode == nil {
		return false
	}
	for current := unionNode.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindFunctionDeclaration:
			fn := current.AsFunctionDeclaration()
			if fn == nil || fn.Body == nil {
				return false
			}
			return hasFunctionOverloadSignatures(current, fn)
		case ast.KindMethodDeclaration:
			method := current.AsMethodDeclaration()
			if method == nil || method.Body == nil {
				return false
			}
			return hasMethodOverloadSignatures(current, method)
		}
	}
	return false
}

func isGenericTypeArgumentContext(node *ast.Node) (bool, string) {
	if node == nil {
		return false, ""
	}

	if parent := node.Parent; parent != nil && parent.Kind == ast.KindTypeReference {
		typeRef := parent.AsTypeReferenceNode()
		if typeRef != nil && typeRef.TypeArguments != nil {
			for _, arg := range typeRef.TypeArguments.Nodes {
				if containsNode(arg, node) {
					name := ""
					if typeRef.TypeName != nil {
						name = normalizeQualifiedName(typeRef.TypeName.Text())
					}
					return true, name
				}
			}
		}
	}

	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindCallExpression:
			callExpr := current.AsCallExpression()
			if callExpr != nil && callExpr.TypeArguments != nil {
				for _, arg := range callExpr.TypeArguments.Nodes {
					if containsNode(arg, node) {
						return true, ""
					}
				}
			}
		case ast.KindNewExpression:
			newExpr := current.AsNewExpression()
			if newExpr != nil && newExpr.TypeArguments != nil {
				for _, arg := range newExpr.TypeArguments.Nodes {
					if containsNode(arg, node) {
						return true, ""
					}
				}
			}
		case ast.KindTypeReference:
			typeRef := current.AsTypeReferenceNode()
			if typeRef != nil && typeRef.TypeArguments != nil {
				for _, arg := range typeRef.TypeArguments.Nodes {
					if containsNode(arg, node) {
						name := ""
						if typeRef.TypeName != nil {
							name = normalizeQualifiedName(typeRef.TypeName.Text())
						}
						return true, name
					}
				}
			}
		}
	}

	return false, ""
}

var NoInvalidVoidTypeRule = rule.CreateRule(rule.Rule{
	Name: "no-invalid-void-type",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindVoidKeyword: func(node *ast.Node) {
				if node == nil {
					return
				}

				if inGeneric, genericName := isGenericTypeArgumentContext(node); inGeneric {
					switch opts.genericMode {
					case "all":
						return
					case "whitelist":
						if _, ok := opts.genericAllowlist[normalizeQualifiedName(genericName)]; ok {
							return
						}
						ctx.ReportNode(node, buildInvalidVoidForGenericMessage(genericName))
						return
					case "none":
						if opts.allowAsThisParameter {
							ctx.ReportNode(node, buildInvalidVoidNotReturnOrThisParamMessage())
						} else {
							ctx.ReportNode(node, buildInvalidVoidNotReturnMessage())
						}
						return
					}
				}

				if node.Parent != nil && node.Parent.Kind == ast.KindTypeParameter && opts.allowsGenericTypeArguments() {
					typeParameter := node.Parent.AsTypeParameter()
					if typeParameter != nil {
						if typeParameter.DefaultType == node {
							return
						}
						ctx.ReportNode(node, buildDefaultInvalidMessage(node, opts))
						return
					}
				}

				if node.Parent != nil && node.Parent.Kind == ast.KindUnionType {
					union := node.Parent.AsUnionTypeNode()
					if isUnionAllowed(union) {
						return
					}
					if isUnionInOverloadImplementation(node.Parent) {
						return
					}
					ctx.ReportNode(node, buildDefaultInvalidMessage(node, opts))
					return
				}

				if node.Parent != nil && node.Parent.Kind == ast.KindParameter {
					if opts.allowAsThisParameter {
						param := node.Parent.AsParameterDeclaration()
						if param != nil && param.Name() != nil && param.Name().Kind == ast.KindIdentifier && param.Name().AsIdentifier().Text == "this" {
							return
						}
					}
					ctx.ReportNode(node, buildDefaultInvalidMessage(node, opts))
					return
				}

				for current := node.Parent; current != nil; current = current.Parent {
					switch current.Kind {
					case ast.KindFunctionType,
						ast.KindConstructorType,
						ast.KindFunctionDeclaration,
						ast.KindMethodDeclaration,
						ast.KindArrowFunction,
						ast.KindFunctionExpression,
						ast.KindMethodSignature:
						return
					}
				}

				// Report invalid void usage by default
				ctx.ReportNode(node, buildDefaultInvalidMessage(node, opts))
			},
		}
	},
})
