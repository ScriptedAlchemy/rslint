package dot_notation

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

// Options mirrors @typescript-eslint/dot-notation options
type Options struct {
	AllowIndexSignaturePropertyAccess bool   `json:"allowIndexSignaturePropertyAccess"`
	AllowKeywords                     bool   `json:"allowKeywords"`
	AllowPattern                      string `json:"allowPattern"`
	AllowPrivateClassPropertyAccess   bool   `json:"allowPrivateClassPropertyAccess"`
	AllowProtectedClassPropertyAccess bool   `json:"allowProtectedClassPropertyAccess"`
}

func parseOptions(options any) Options {
	// defaults
	opts := Options{
		AllowKeywords:                     true,
		AllowIndexSignaturePropertyAccess: true,
	}

	if options == nil {
		return opts
	}

	// Support [ { ... } ] and { ... }
	if arr, ok := options.([]interface{}); ok {
		if len(arr) > 0 {
			if m, ok := arr[0].(map[string]interface{}); ok {
				if v, ok := m["allowIndexSignaturePropertyAccess"].(bool); ok {
					opts.AllowIndexSignaturePropertyAccess = v
				}
				if v, ok := m["allowKeywords"].(bool); ok {
					opts.AllowKeywords = v
				}
				if v, ok := m["allowPattern"].(string); ok {
					opts.AllowPattern = v
				}
				if v, ok := m["allowPrivateClassPropertyAccess"].(bool); ok {
					opts.AllowPrivateClassPropertyAccess = v
				}
				if v, ok := m["allowProtectedClassPropertyAccess"].(bool); ok {
					opts.AllowProtectedClassPropertyAccess = v
				}
			}
		}
		return opts
	}

	if m, ok := options.(map[string]interface{}); ok {
		if v, ok := m["allowIndexSignaturePropertyAccess"].(bool); ok {
			opts.AllowIndexSignaturePropertyAccess = v
		}
		if v, ok := m["allowKeywords"].(bool); ok {
			opts.AllowKeywords = v
		}
		if v, ok := m["allowPattern"].(string); ok {
			opts.AllowPattern = v
		}
		if v, ok := m["allowPrivateClassPropertyAccess"].(bool); ok {
			opts.AllowPrivateClassPropertyAccess = v
		}
		if v, ok := m["allowProtectedClassPropertyAccess"].(bool); ok {
			opts.AllowProtectedClassPropertyAccess = v
		}
	}
	return opts
}

func buildUseDotMessage() rule.RuleMessage {
	return rule.RuleMessage{Id: "useDot", Description: "Use dot notation instead of bracket notation."}
}

func buildUseBracketsMessage(key string) rule.RuleMessage {
	// Keep key for parity with ESLint message data (not used in printing now)
	_ = key
	return rule.RuleMessage{Id: "useBrackets", Description: "Property is a keyword - use bracket notation."}
}

// Reserved keywords that should trigger dot -> bracket when allowKeywords=false.
// Excludes identifiers that TS-ESLint treats as safe to access via dot even when allowKeywords=false
// (per tests): let, yield, eval, arguments, and literals true/false/null.
var keywordSet = map[string]struct{}{
	"break": {}, "case": {}, "catch": {}, "class": {}, "const": {}, "continue": {}, "debugger": {}, "default": {},
	"delete": {}, "do": {}, "else": {}, "export": {}, "extends": {}, "finally": {}, "for": {}, "function": {},
	"if": {}, "import": {}, "in": {}, "instanceof": {}, "new": {}, "return": {}, "super": {}, "switch": {},
	"this": {}, "throw": {}, "try": {}, "typeof": {}, "var": {}, "void": {}, "while": {}, "with": {},
	// intentionally not including: let, yield, eval, arguments, true, false, null
}

var identRE = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

func isValidIdentifier(name string) bool {
	return identRE.MatchString(name)
}

func isKeyword(name string) bool {
	_, ok := keywordSet[name]
	return ok
}

func typeHasIndexSignature(t *checker.Type) bool {
	if t == nil {
		return false
	}
	// Explore alias target declarations first if present
	if alias := checker.Type_alias(t); alias != nil && alias.Symbol() != nil {
		if decls := alias.Symbol().Declarations; len(decls) > 0 {
			for _, decl := range decls {
				if decl == nil {
					continue
				}
				switch decl.Kind {
				case ast.KindTypeAliasDeclaration:
					ta := decl.AsTypeAliasDeclaration()
					if ta != nil && ta.Type != nil && ta.Type.Kind == ast.KindTypeLiteral {
						tl := ta.Type.AsTypeLiteralNode()
						if tl != nil && tl.Members != nil {
							for _, m := range tl.Members.Nodes {
								if m != nil && m.Kind == ast.KindIndexSignature {
									return true
								}
							}
						}
					}
				case ast.KindInterfaceDeclaration:
					iface := decl.AsInterfaceDeclaration()
					if iface != nil && iface.Members != nil {
						for _, m := range iface.Members.Nodes {
							if m != nil && m.Kind == ast.KindIndexSignature {
								return true
							}
						}
					}
				case ast.KindTypeLiteral:
					tl := decl.AsTypeLiteralNode()
					if tl != nil && tl.Members != nil {
						for _, m := range tl.Members.Nodes {
							if m != nil && m.Kind == ast.KindIndexSignature {
								return true
							}
						}
					}
				}
			}
		}
	}

	sym := checker.Type_symbol(t)
	if sym == nil || len(sym.Declarations) == 0 {
		return false
	}
	for _, decl := range sym.Declarations {
		if decl == nil {
			continue
		}
		switch decl.Kind {
		case ast.KindInterfaceDeclaration:
			iface := decl.AsInterfaceDeclaration()
			if iface != nil && iface.Members != nil {
				for _, m := range iface.Members.Nodes {
					if m != nil && m.Kind == ast.KindIndexSignature {
						return true
					}
				}
			}
		case ast.KindTypeAliasDeclaration:
			alias := decl.AsTypeAliasDeclaration()
			if alias != nil && alias.Type != nil && alias.Type.Kind == ast.KindTypeLiteral {
				tl := alias.Type.AsTypeLiteralNode()
				if tl != nil && tl.Members != nil {
					for _, m := range tl.Members.Nodes {
						if m != nil && m.Kind == ast.KindIndexSignature {
							return true
						}
					}
				}
			}
		case ast.KindClassDeclaration:
			classDecl := decl.AsClassDeclaration()
			if classDecl != nil && classDecl.Members != nil {
				for _, m := range classDecl.Members.Nodes {
					if m != nil && m.Kind == ast.KindIndexSignature {
						return true
					}
				}
			}
		case ast.KindTypeLiteral:
			tl := decl.AsTypeLiteralNode()
			if tl != nil && tl.Members != nil {
				for _, m := range tl.Members.Nodes {
					if m != nil && m.Kind == ast.KindIndexSignature {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasAnyIndexSignature walks unions/intersections to detect an index signature on any part
func hasAnyIndexSignature(t *checker.Type) bool {
	if t == nil {
		return false
	}
	if utils.IsUnionType(t) {
		for _, part := range t.Types() {
			if hasAnyIndexSignature(part) {
				return true
			}
		}
		return false
	}
	if utils.IsIntersectionType(t) {
		for _, part := range t.Types() {
			if hasAnyIndexSignature(part) {
				return true
			}
		}
		return false
	}
	return typeHasIndexSignature(t)
}

// hasStringLikeIndexSignatureTS uses available checker APIs to detect declared string-like index signatures.
func hasStringLikeIndexSignatureTS(typeChecker *checker.Checker, t *checker.Type) bool {
	if t == nil {
		return false
	}
	nn := typeChecker.GetNonNullableType(t)
	app := checker.Checker_getApparentType(typeChecker, nn)

	infos := checker.Checker_getIndexInfosOfType(typeChecker, app)
	if len(infos) == 0 {
		return false
	}
	for _, info := range infos {
		if info == nil {
			continue
		}
		kt := checker.IndexInfo_keyType(info)
		if kt == nil {
			continue
		}
		// Treat both string-like and template-literal key types as allowing string keys
		flags := checker.Type_flags(kt)
		if (flags&checker.TypeFlagsStringLike) != 0 || (flags&checker.TypeFlagsTemplateLiteral) != 0 {
			return true
		}
	}
	return false
}

// hasStringLikeIndexSignature returns true if the (apparent) type has an index signature
// whose key type is string-like. It recursively checks union and intersection parts.
func hasStringLikeIndexSignature(typeChecker *checker.Checker, t *checker.Type) bool {
	if t == nil {
		return false
	}
	// If this is a type alias, inspect the alias declaration's type literal for index signatures
	if alias := checker.Type_alias(t); alias != nil && alias.Symbol() != nil {
		for _, decl := range alias.Symbol().Declarations {
			if decl == nil {
				continue
			}
			if decl.Kind == ast.KindTypeAliasDeclaration {
				ta := decl.AsTypeAliasDeclaration()
				if ta != nil && ta.Type != nil && ta.Type.Kind == ast.KindTypeLiteral {
					tl := ta.Type.AsTypeLiteralNode()
					if tl != nil && tl.Members != nil {
						for _, m := range tl.Members.Nodes {
							if m != nil && m.Kind == ast.KindIndexSignature {
								is := m.AsIndexSignatureDeclaration()
								if is != nil && is.Parameters != nil && len(is.Parameters.Nodes) > 0 {
									p := is.Parameters.Nodes[0]
									if p != nil && p.Type() != nil {
										kt := checker.Checker_getTypeFromTypeNode(typeChecker, p.Type())
										if kt != nil && (checker.Type_flags(kt)&checker.TypeFlagsStringLike) != 0 {
											return true
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if utils.IsUnionType(t) {
		for _, part := range t.Types() {
			if hasStringLikeIndexSignature(typeChecker, part) {
				return true
			}
		}
		return false
	}
	if utils.IsIntersectionType(t) {
		for _, part := range t.Types() {
			if hasStringLikeIndexSignature(typeChecker, part) {
				return true
			}
		}
		return false
	}

	// Scan declarations for index signatures, and check the key type using the checker
	sym := checker.Type_symbol(t)
	if sym != nil {
		for _, decl := range sym.Declarations {
			if decl == nil {
				continue
			}
			switch decl.Kind {
			case ast.KindInterfaceDeclaration:
				iface := decl.AsInterfaceDeclaration()
				if iface != nil && iface.Members != nil {
					for _, m := range iface.Members.Nodes {
						if m != nil && m.Kind == ast.KindIndexSignature {
							is := m.AsIndexSignatureDeclaration()
							if is != nil && is.Parameters != nil && len(is.Parameters.Nodes) > 0 {
								p := is.Parameters.Nodes[0]
								if p != nil && p.Type() != nil {
									kt := checker.Checker_getTypeFromTypeNode(typeChecker, p.Type())
									if kt != nil && (checker.Type_flags(kt)&checker.TypeFlagsStringLike) != 0 {
										return true
									}
								}
							}
						}
					}
				}
			case ast.KindTypeAliasDeclaration:
				ta := decl.AsTypeAliasDeclaration()
				if ta != nil && ta.Type != nil && ta.Type.Kind == ast.KindTypeLiteral {
					tl := ta.Type.AsTypeLiteralNode()
					if tl != nil && tl.Members != nil {
						for _, m := range tl.Members.Nodes {
							if m != nil && m.Kind == ast.KindIndexSignature {
								is := m.AsIndexSignatureDeclaration()
								if is != nil && is.Parameters != nil && len(is.Parameters.Nodes) > 0 {
									p := is.Parameters.Nodes[0]
									if p != nil && p.Type() != nil {
										kt := checker.Checker_getTypeFromTypeNode(typeChecker, p.Type())
										if kt != nil && (checker.Type_flags(kt)&checker.TypeFlagsStringLike) != 0 {
											return true
										}
									}
								}
							}
						}
					}
				}
			case ast.KindClassDeclaration:
				cd := decl.AsClassDeclaration()
				if cd != nil && cd.Members != nil {
					for _, m := range cd.Members.Nodes {
						if m != nil && m.Kind == ast.KindIndexSignature {
							is := m.AsIndexSignatureDeclaration()
							if is != nil && is.Parameters != nil && len(is.Parameters.Nodes) > 0 {
								p := is.Parameters.Nodes[0]
								if p != nil && p.Type() != nil {
									kt := checker.Checker_getTypeFromTypeNode(typeChecker, p.Type())
									if kt != nil && (checker.Type_flags(kt)&checker.TypeFlagsStringLike) != 0 {
										return true
									}
								}
							}
						}
					}
				}
			case ast.KindTypeLiteral:
				tl := decl.AsTypeLiteralNode()
				if tl != nil && tl.Members != nil {
					for _, m := range tl.Members.Nodes {
						if m != nil && m.Kind == ast.KindIndexSignature {
							is := m.AsIndexSignatureDeclaration()
							if is != nil && is.Parameters != nil && len(is.Parameters.Nodes) > 0 {
								p := is.Parameters.Nodes[0]
								if p != nil && p.Type() != nil {
									kt := checker.Checker_getTypeFromTypeNode(typeChecker, p.Type())
									if kt != nil && (checker.Type_flags(kt)&checker.TypeFlagsStringLike) != 0 {
										return true
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}

// typeContainsTypeParameter returns true if the given type or any of its immediate
// union/intersection constituents contains a type parameter.
func typeContainsTypeParameter(t *checker.Type) bool {
	if t == nil {
		return false
	}
	if utils.IsTypeParameter(t) {
		return true
	}
	if utils.IsUnionType(t) || utils.IsIntersectionType(t) {
		for _, part := range t.Types() {
			if utils.IsTypeParameter(part) {
				return true
			}
		}
	}
	return false
}

func getStringLiteralValue(srcFile *ast.SourceFile, n *ast.Node) (string, bool) {
	switch n.Kind {
	case ast.KindStringLiteral, ast.KindNoSubstitutionTemplateLiteral:
		rng := utils.TrimNodeTextRange(srcFile, n)
		text := srcFile.Text()[rng.Pos():rng.End()]
		if len(text) >= 2 {
			quote := text[0]
			if (quote == '\'' || quote == '"' || quote == '`') && text[len(text)-1] == quote {
				return text[1 : len(text)-1], true
			}
		}
		// Fallback to raw text without outer quotes
		return strings.Trim(text, "'\"`"), true
	case ast.KindNullKeyword:
		return "null", true
	case ast.KindTrueKeyword:
		return "true", true
	case ast.KindFalseKeyword:
		return "false", true
	default:
		return "", false
	}
}

// DotNotationRule enforces dot-notation when safe and allowed by options.
var DotNotationRule = rule.CreateRule(rule.Rule{
	Name: "dot-notation",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)
		var allowRE *regexp.Regexp
		if opts.AllowPattern != "" {
			// best-effort; ignore regexp compile errors by treating as no allow pattern
			if re, err := regexp.Compile(opts.AllowPattern); err == nil {
				allowRE = re
			}
		}

		// Derive allowIndexSignaturePropertyAccess from tsconfig option as well
		tsAllowIndex := false
		if ctx.Program != nil {
			copts := ctx.Program.Options()
			if copts != nil && copts.NoPropertyAccessFromIndexSignature.IsTrue() {
				tsAllowIndex = true
			}
		}

		listeners := rule.RuleListeners{}

		// Handle bracket → dot (ElementAccessExpression)
		listeners[ast.KindElementAccessExpression] = func(node *ast.Node) {
			elem := node.AsElementAccessExpression()
			if elem == nil || elem.ArgumentExpression == nil {
				return
			}

			// Only for simple string literals (and no-substitution templates)
			propName, ok := getStringLiteralValue(ctx.SourceFile, elem.ArgumentExpression)
			if !ok {
				return
			}

			// Option: allow pattern
			if allowRE != nil && allowRE.MatchString(propName) {
				return
			}

			// Option: allow keywords via bracket notation only when allowKeywords is false.
			// Additionally treat true/false/null as reserved when allowKeywords is false.
			if !opts.AllowKeywords && (isKeyword(propName) || propName == "null" || propName == "true" || propName == "false") {
				return
			}

			// TS-specific relaxations
			objType := ctx.TypeChecker.GetTypeAtLocation(elem.Expression)
			nnType := ctx.TypeChecker.GetNonNullableType(objType)
			appType := checker.Checker_getApparentType(ctx.TypeChecker, nnType)
			// Try resolve symbol to check modifiers on the non-nullable type first
			sym := checker.Checker_getPropertyOfType(ctx.TypeChecker, appType, propName)
			if sym == nil {
				for _, s := range checker.Checker_getPropertiesOfType(ctx.TypeChecker, appType) {
					if s != nil && s.Name == propName {
						sym = s
						break
					}
				}
			}

			if sym != nil {
				flags := checker.GetDeclarationModifierFlagsFromSymbol(sym)
				if (flags & ast.ModifierFlagsPrivate) != 0 {
					if opts.AllowPrivateClassPropertyAccess {
						return
					}
					// Continue to report error when allowPrivateClassPropertyAccess is false
				} else if (flags & ast.ModifierFlagsProtected) != 0 {
					if opts.AllowProtectedClassPropertyAccess {
						return
					}
					// Continue to report error when allowProtectedClassPropertyAccess is false
				}
			}

			// Allow bracket notation for properties that are NOT explicitly declared,
			// but are covered by an index signature AND the allowIndexSignaturePropertyAccess flag (or TS option) is enabled.
			// Additionally, if the index signature key is template-literal based and the property name matches,
			// treat it as covered by the index signature.
			allowIndexAccess := opts.AllowIndexSignaturePropertyAccess || tsAllowIndex
			if allowIndexAccess && sym == nil {
				if hasStringLikeIndexSignatureTS(ctx.TypeChecker, nnType) || hasStringLikeIndexSignature(ctx.TypeChecker, appType) || hasAnyIndexSignature(appType) {
					return
				}
				// Also permit when index key type or value type includes a type parameter; this captures
				// cases like [extraKey: ExtraKey] where ExtraKey is a template-literal type parameter.
				for _, info := range checker.Checker_getIndexInfosOfType(ctx.TypeChecker, appType) {
					if info == nil {
						continue
					}
					if typeContainsTypeParameter(checker.IndexInfo_keyType(info)) || typeContainsTypeParameter(checker.IndexInfo_valueType(info)) {
						return
					}
				}
			}

			// Suggest using dot notation if the name is a valid identifier and
			// - allowKeywords is true; or
			// - it's not a reserved keyword (and not true/false/null when allowKeywords is false)
			if isValidIdentifier(propName) && (opts.AllowKeywords || (!isKeyword(propName))) {
				text := ctx.SourceFile.Text()
				exprRange := utils.TrimNodeTextRange(ctx.SourceFile, elem.Expression)
				// Find '[' after the object
				i := exprRange.End()
				for i < len(text) && text[i] != '[' {
					i++
				}
				// Detect if there is a newline between the object end and '['
				hasNewline := false
				for k := exprRange.End(); k < i; k++ {
					if text[k] == '\n' {
						hasNewline = true
						break
					}
				}
				// Compute the start of the line containing '['
				lineStart := i
				for lineStart > 0 && text[lineStart-1] != '\n' {
					lineStart--
				}
				start := lineStart
				if hasNewline {
					// For multi-line element access, anchor to the first quote inside the brackets
					// to match the base rule's reported location (line of the '[').
					quoteStart := -1
					// Find the end at the closing ']'
					endScan := i
					for endScan < len(text) && text[endScan] != ']' {
						endScan++
					}
					for p := i; p < endScan; p++ {
						if text[p] == '\'' || text[p] == '"' || text[p] == '`' {
							quoteStart = p
							break
						}
					}
					if quoteStart >= 0 {
						start = quoteStart
					} else {
						start = i
					}
				}
				// Find the end at the closing ']'
				j := i
				for j < len(text) && text[j] != ']' {
					j++
				}
				if j < len(text) {
					j++
				}
				anchored := core.NewTextRange(start, j)
				ctx.ReportRange(anchored, buildUseDotMessage())
			}
		}

		// Handle dot → bracket (PropertyAccessExpression) when keywords are disallowed
		listeners[ast.KindPropertyAccessExpression] = func(node *ast.Node) {
			if opts.AllowKeywords {
				return
			}
			pae := node.AsPropertyAccessExpression()
			if pae == nil || pae.Name() == nil || pae.Expression == nil {
				return
			}
			name := pae.Name().Text()
			if !isKeyword(name) {
				return
			}
			// Avoid autofix if comments present (heuristic)
			textRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
			if !utils.HasCommentsInRange(ctx.SourceFile, textRange) {
				objRange := utils.TrimNodeTextRange(ctx.SourceFile, pae.Expression)
				objectText := ctx.SourceFile.Text()[objRange.Pos():objRange.End()]
				replacement := objectText + "[\"" + name + "\"]"
				ctx.ReportNodeWithFixes(node, buildUseBracketsMessage(name), rule.RuleFixReplace(ctx.SourceFile, node, replacement))
				return
			}
			ctx.ReportNode(node, buildUseBracketsMessage(name))
		}

		return listeners
	},
})
