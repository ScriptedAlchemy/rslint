package no_var_requires

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type Options struct {
	Allow []string `json:"allow"`
}

var NoVarRequiresRule = rule.CreateRule(rule.Rule{
	Name: "no-var-requires",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := &Options{}
		if options != nil {
			if optArray, ok := options.([]interface{}); ok && len(optArray) > 0 {
				if optMap, ok := optArray[0].(map[string]interface{}); ok {
					if allowList, exists := optMap["allow"]; exists {
						if allowSlice, ok := allowList.([]interface{}); ok {
							for _, item := range allowSlice {
								if str, ok := item.(string); ok {
									opts.Allow = append(opts.Allow, str)
								}
							}
						} else if allowStrSlice, ok := allowList.([]string); ok {
							opts.Allow = allowStrSlice
						}
					}
				}
			} else if optMap, ok := options.(map[string]interface{}); ok {
				if allowList, exists := optMap["allow"]; exists {
					if allowSlice, ok := allowList.([]interface{}); ok {
						for _, item := range allowSlice {
							if str, ok := item.(string); ok {
								opts.Allow = append(opts.Allow, str)
							}
						}
					} else if allowStrSlice, ok := allowList.([]string); ok {
						opts.Allow = allowStrSlice
					}
				}
			} else if o, ok := options.(Options); ok {
				opts = &o
			} else if o, ok := options.(*Options); ok {
				opts = o
			}
		}

		// Compile allow patterns into regexes
		var allowPatterns []*regexp.Regexp
		for _, pattern := range opts.Allow {
			p := pattern
			// Upstream test config often passes regex-literals-as-strings, like
			// `/package\.json$/`; strip delimiters for Go regexp parsing.
			if strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") && len(p) > 2 {
				p = p[1 : len(p)-1]
			}
			if re, err := regexp.Compile(p); err == nil {
				allowPatterns = append(allowPatterns, re)
			}
		}

		isImportPathAllowed := func(importPath string) bool {
			for _, pattern := range allowPatterns {
				if pattern.MatchString(importPath) {
					return true
				}
			}
			return false
		}

		isStringOrTemplateLiteral := func(node *ast.Node) bool {
			if node == nil {
				return false
			}
			if node.Kind == ast.KindStringLiteral {
				return true
			}
			if node.Kind == ast.KindNoSubstitutionTemplateLiteral {
				return true
			}
			return false
		}

		isRequireIdentifierShadowed := func(node *ast.Node) bool {
			if node == nil || ctx.TypeChecker == nil {
				return false
			}
			symbol := ctx.TypeChecker.GetSymbolAtLocation(node)
			if symbol == nil {
				return false
			}
			for _, decl := range symbol.Declarations {
				if decl == nil {
					continue
				}
				if ast.GetSourceFileOfNode(decl) == ctx.SourceFile {
					return true
				}
			}
			return false
		}

		// Helper to check if a node or any of its ancestors is a variable declaration
		isInVariableDeclaration := func(node *ast.Node) bool {
			current := node
			for current != nil {
				if current.Kind == ast.KindVariableDeclaration ||
					current.Kind == ast.KindVariableDeclarationList {
					return true
				}
				current = current.Parent
			}
			return false
		}

		return rule.RuleListeners{
			ast.KindCallExpression: func(node *ast.Node) {
				callExpr := node.AsCallExpression()
				if callExpr == nil {
					return
				}

				// Check if this is a require() call
				callee := callExpr.Expression
				if callee == nil || callee.Kind != ast.KindIdentifier {
					return
				}

				identifier := callee.AsIdentifier()
				if identifier == nil || identifier.Text != "require" {
					return
				}

				// Check if require is a local variable (not the global require)
				if isRequireIdentifierShadowed(callee) {
					return
				}

				// Check arguments for allow patterns
				args := callExpr.Arguments
				if args != nil && len(args.Nodes) > 0 && isStringOrTemplateLiteral(args.Nodes[0]) {
					// Get string value from argument
					arg := args.Nodes[0]
					var argValue string
					switch arg.Kind {
					case ast.KindStringLiteral:
						stringLiteral := arg.AsStringLiteral()
						if stringLiteral != nil {
							// Remove quotes from the text
							text := stringLiteral.Text
							if len(text) >= 2 && ((text[0] == '"' && text[len(text)-1] == '"') ||
								(text[0] == '\'' && text[len(text)-1] == '\'')) {
								argValue = text[1 : len(text)-1]
							} else {
								argValue = text
							}
						}
					case ast.KindNoSubstitutionTemplateLiteral:
						templateLiteral := arg.AsNoSubstitutionTemplateLiteral()
						if templateLiteral != nil {
							argValue = templateLiteral.Text
						}
					}
					if argValue != "" && isImportPathAllowed(argValue) {
						return
					}
				}

				// Get the parent, handling optional chaining
				parent := node.Parent
				if parent != nil && parent.Kind == ast.KindPropertyAccessExpression {
					// This handles optional chaining like require?.('foo')
					parent = parent.Parent
				}

				if parent == nil {
					return
				}

				// Check if this is part of a TypeScript import statement
				// import foo = require('foo') is allowed
				if parent.Kind == ast.KindImportEqualsDeclaration {
					return
				}

				// Standalone require() calls are allowed
				if parent.Kind == ast.KindExpressionStatement {
					return
				}

				// Check if require is used in contexts that are not allowed
				if isInVariableDeclaration(node) ||
					parent.Kind == ast.KindCallExpression ||
					parent.Kind == ast.KindPropertyAccessExpression ||
					parent.Kind == ast.KindNewExpression ||
					parent.Kind == ast.KindAsExpression ||
					parent.Kind == ast.KindTypeAssertionExpression {
					ctx.ReportNode(node, rule.RuleMessage{
						Description: "Require statement not part of import statement.",
						Id:          "noVarReqs",
					})
				}
			},
		}
	},
})
