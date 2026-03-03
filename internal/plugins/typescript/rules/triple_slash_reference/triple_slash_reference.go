package triple_slash_reference

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
)

type TripleSlashReferenceOptions struct {
	Lib   string `json:"lib"`   // "always" | "never"
	Path  string `json:"path"`  // "always" | "never" | "prefer-import"
	Types string `json:"types"` // "always" | "never" | "prefer-import"
}

var tripleSlashRegex = regexp.MustCompile(`^///\s*<reference\s*(types|path|lib)\s*=\s*["']([^"']+)["']`)

type referenceDirective struct {
	kind   string
	module string
	start  int
	end    int
}

// TripleSlashReferenceRule implements the triple-slash-reference rule
// Disallow certain triple slash directives
var TripleSlashReferenceRule = rule.CreateRule(rule.Rule{
	Name: "triple-slash-reference",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := parseOptions(options)
	text := ctx.SourceFile.Text()
	directives := collectLeadingDirectives(text)
	if len(directives) == 0 {
		return rule.RuleListeners{}
	}

	importSources := collectImportSources(ctx.SourceFile)

	for _, directive := range directives {
		shouldReport := false
		switch directive.kind {
		case "types":
			shouldReport = opts.Types == "never" || (opts.Types == "prefer-import" && importSources[directive.module])
		case "path":
			shouldReport = opts.Path == "never"
		case "lib":
			shouldReport = opts.Lib == "never"
		}
		if !shouldReport {
			continue
		}
		ctx.ReportRange(
			core.NewTextRange(directive.start, directive.end),
			rule.RuleMessage{
				Id:          "tripleSlashReference",
				Description: fmt.Sprintf("Do not use a triple slash reference for %s, use `import` style instead.", directive.module),
			},
		)
	}

	return rule.RuleListeners{}
}

func parseOptions(options any) TripleSlashReferenceOptions {
	opts := TripleSlashReferenceOptions{
		Lib:   "always",
		Path:  "never",
		Types: "prefer-import",
	}
	applyMap := func(raw map[string]interface{}) {
		if raw == nil {
			return
		}
		if lib, ok := raw["lib"].(string); ok {
			opts.Lib = lib
		}
		if path, ok := raw["path"].(string); ok {
			opts.Path = path
		}
		if types, ok := raw["types"].(string); ok {
			opts.Types = types
		}
	}

	switch raw := options.(type) {
	case TripleSlashReferenceOptions:
		opts = raw
	case *TripleSlashReferenceOptions:
		if raw != nil {
			opts = *raw
		}
	case map[string]interface{}:
		applyMap(raw)
	case []interface{}:
		if len(raw) > 0 {
			if firstMap, ok := raw[0].(map[string]interface{}); ok {
				applyMap(firstMap)
			}
		}
	}
	return opts
}

func collectImportSources(sourceFile *ast.SourceFile) map[string]bool {
	imports := map[string]bool{}
	if sourceFile == nil || sourceFile.Statements == nil {
		return imports
	}

	extractText := func(node *ast.Node) (string, bool) {
		if node == nil {
			return "", false
		}
		switch node.Kind {
		case ast.KindStringLiteral:
			lit := node.AsStringLiteral()
			if lit != nil {
				return lit.Text, true
			}
		case ast.KindNoSubstitutionTemplateLiteral:
			lit := node.AsNoSubstitutionTemplateLiteral()
			if lit != nil {
				return lit.Text, true
			}
		}
		return "", false
	}

	for _, stmt := range sourceFile.Statements.Nodes {
		switch stmt.Kind {
		case ast.KindImportDeclaration:
			decl := stmt.AsImportDeclaration()
			if decl != nil && decl.ModuleSpecifier != nil {
				if value, ok := extractText(decl.ModuleSpecifier); ok {
					imports[value] = true
				}
			}
		case ast.KindImportEqualsDeclaration:
			decl := stmt.AsImportEqualsDeclaration()
			if decl != nil && decl.ModuleReference != nil && decl.ModuleReference.Kind == ast.KindExternalModuleReference {
				ref := decl.ModuleReference.AsExternalModuleReference()
				if ref != nil && ref.Expression != nil {
					if value, ok := extractText(ref.Expression); ok {
						imports[value] = true
					}
				}
			}
		}
	}

	return imports
}

func collectLeadingDirectives(text string) []referenceDirective {
	inBlockComment := false
	lineStart := 0
	directives := make([]referenceDirective, 0)

	for lineStart <= len(text) {
		lineEnd := len(text)
		if idx := strings.IndexByte(text[lineStart:], '\n'); idx >= 0 {
			lineEnd = lineStart + idx
		}

		line := text[lineStart:lineEnd]
		trimmedLeft := strings.TrimLeft(line, " \t")
		trimmed := strings.TrimSpace(line)

		if inBlockComment {
			if strings.Contains(trimmedLeft, "*/") {
				inBlockComment = false
			}
		} else if trimmed == "" || (lineStart == 0 && strings.HasPrefix(trimmedLeft, "#!")) {
			// Keep scanning leading blank lines and shebang.
		} else if strings.HasPrefix(trimmedLeft, "/*") {
			if !strings.Contains(trimmedLeft[2:], "*/") {
				inBlockComment = true
			}
		} else if strings.HasPrefix(trimmedLeft, "//") {
			if strings.HasPrefix(trimmedLeft, "///") {
				match := tripleSlashRegex.FindStringSubmatch(trimmedLeft)
				if len(match) == 3 {
					columnOffset := strings.Index(line, "///")
					start := lineStart + columnOffset
					directives = append(directives, referenceDirective{
						kind:   match[1],
						module: match[2],
						start:  start,
						end:    lineStart + len(line),
					})
				}
			}
		} else {
			// Stop once non-comment code starts.
			break
		}

		if lineEnd == len(text) {
			break
		}
		lineStart = lineEnd + 1
	}

	return directives
}
