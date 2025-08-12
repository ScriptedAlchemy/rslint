package dot_notation

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
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
		AllowKeywords: true,
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

var keywordSet = map[string]struct{}{
	// ECMAScript keywords and reserved words commonly guarded by ESLint rule
	"break": {}, "case": {}, "catch": {}, "class": {}, "const": {}, "continue": {}, "debugger": {}, "default": {},
	"delete": {}, "do": {}, "else": {}, "export": {}, "extends": {}, "finally": {}, "for": {}, "function": {},
	"if": {}, "import": {}, "in": {}, "instanceof": {}, "new": {}, "return": {}, "super": {}, "switch": {},
	"this": {}, "throw": {}, "try": {}, "typeof": {}, "var": {}, "void": {}, "while": {}, "with": {}, "yield": {},
	"let": {}, "static": {}, "enum": {}, "await": {}, "null": {}, "true": {}, "false": {},
}

var identRE = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

func isValidIdentifier(name string) bool {
	return identRE.MatchString(name)
}

func isKeyword(name string) bool {
	_, ok := keywordSet[name]
	return ok
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

			// Option: allow keywords via bracket notation
			if !opts.AllowKeywords && isKeyword(propName) {
				return
			}

			// TS-specific relaxations
			if opts.AllowPrivateClassPropertyAccess || opts.AllowProtectedClassPropertyAccess || opts.AllowIndexSignaturePropertyAccess {
				objType := ctx.TypeChecker.GetTypeAtLocation(elem.Expression)
				// Try resolve symbol to check modifiers
				sym := checker.Checker_getPropertyOfType(ctx.TypeChecker, objType, propName)
				if sym != nil {
					flags := checker.GetDeclarationModifierFlagsFromSymbol(sym)
					if opts.AllowPrivateClassPropertyAccess && (flags&ast.ModifierFlagsPrivate) != 0 {
						return
					}
					if opts.AllowProtectedClassPropertyAccess && (flags&ast.ModifierFlagsProtected) != 0 {
						return
					}
				} else if opts.AllowIndexSignaturePropertyAccess {
					// If property cannot be resolved on the type, approximate that an index signature may allow it.
					return
				}
			}

			// Suggest using dot notation if the name is a valid identifier
			if isValidIdentifier(propName) {
				// Avoid autofix when there are comments inside the element expression range
				textRange := utils.TrimNodeTextRange(ctx.SourceFile, node)
				if !utils.HasCommentsInRange(ctx.SourceFile, textRange) {
					objRange := utils.TrimNodeTextRange(ctx.SourceFile, elem.Expression)
					objectText := ctx.SourceFile.Text()[objRange.Pos():objRange.End()]
					replacement := objectText + "." + propName
					ctx.ReportNodeWithFixes(node, buildUseDotMessage(), rule.RuleFixReplace(ctx.SourceFile, node, replacement))
					return
				}
				ctx.ReportNode(node, buildUseDotMessage())
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
