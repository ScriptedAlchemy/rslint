package ban_ts_comment

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type directiveMode uint8

const (
	directiveModeDisabled directiveMode = iota
	directiveModeBan
	directiveModeAllowWithDescription
)

type DirectiveConfig struct {
	Mode              directiveMode
	DescriptionFormat string
	DescriptionRegex  *regexp.Regexp
}

type BanTsCommentOptions struct {
	TsExpectError            interface{} `json:"ts-expect-error"`
	TsIgnore                 interface{} `json:"ts-ignore"`
	TsNocheck                interface{} `json:"ts-nocheck"`
	TsCheck                  interface{} `json:"ts-check"`
	MinimumDescriptionLength int         `json:"minimumDescriptionLength"`
}

// Regular expressions for matching TypeScript directives
var (
	singleLinePragmaRegex    = regexp.MustCompile(`^\/\/\/?\s*@ts-(check|nocheck)(.*)$`)
	singleLineDirectiveRegex = regexp.MustCompile(`^\/*\s*@ts-(expect-error|ignore)(.*)$`)
	multiLineDirectiveRegex  = regexp.MustCompile(`^\s*(?:\/|\*)*\s*@ts-(expect-error|ignore)(.*)$`)
)

func buildTsDirectiveCommentMessage(directive string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "tsDirectiveComment",
		Description: "Do not use \"@ts-" + directive + "\" because it alters compilation errors.",
	}
}

func buildTsDirectiveCommentRequiresDescriptionMessage(directive string, minLen int) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "tsDirectiveCommentRequiresDescription",
		Description: "Include a description after the \"@ts-" + directive + "\" directive to explain why the @ts-" + directive + " is necessary. The description must be " + formatInt(minLen) + " characters or longer.",
	}
}

func buildTsDirectiveCommentDescriptionNotMatchPatternMessage(directive string, format string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "tsDirectiveCommentDescriptionNotMatchPattern",
		Description: "The description for the \"@ts-" + directive + "\" directive must match the " + format + " format.",
	}
}

func buildTsIgnoreInsteadOfExpectErrorMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "tsIgnoreInsteadOfExpectError",
		Description: "Use \"@ts-expect-error\" instead of \"@ts-ignore\", as \"@ts-ignore\" will do nothing if the following line is error-free.",
	}
}

func buildReplaceTsIgnoreWithTsExpectErrorMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "replaceTsIgnoreWithTsExpectError",
		Description: "Replace \"@ts-ignore\" with \"@ts-expect-error\".",
	}
}

// BanTsCommentRule implements the ban-ts-comment rule
// Bans @ts-<directive> comments or requires descriptions after directive
var BanTsCommentRule = rule.CreateRule(rule.Rule{
	Name: "ban-ts-comment",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := BanTsCommentOptions{
		TsExpectError:            "allow-with-description",
		TsIgnore:                 true,
		TsNocheck:                true,
		TsCheck:                  false,
		MinimumDescriptionLength: 3,
	}

	// Parse options
	if options != nil {
		var optsMap map[string]interface{}
		var ok bool

		// Handle array format: [{ option: value }]
		if optArray, isArray := options.([]interface{}); isArray && len(optArray) > 0 {
			optsMap, ok = optArray[0].(map[string]interface{})
		} else {
			// Handle direct object format: { option: value }
			optsMap, ok = options.(map[string]interface{})
		}

		if ok {
			if val, exists := optsMap["ts-expect-error"]; exists {
				opts.TsExpectError = val
			}
			if val, exists := optsMap["ts-ignore"]; exists {
				opts.TsIgnore = val
			}
			if val, exists := optsMap["ts-nocheck"]; exists {
				opts.TsNocheck = val
			}
			if val, exists := optsMap["ts-check"]; exists {
				opts.TsCheck = val
			}
			if val, ok := optsMap["minimumDescriptionLength"].(float64); ok {
				opts.MinimumDescriptionLength = int(val)
			} else if val, ok := optsMap["minimumDescriptionLength"].(int); ok {
				opts.MinimumDescriptionLength = val
			}
		}
	}

	// Parse directive configurations
	configs := map[string]*DirectiveConfig{
		"ts-expect-error": parseDirectiveConfig(opts.TsExpectError),
		"ts-ignore":       parseDirectiveConfig(opts.TsIgnore),
		"ts-nocheck":      parseDirectiveConfig(opts.TsNocheck),
		"ts-check":        parseDirectiveConfig(opts.TsCheck),
	}

	// Get the full text of the source file
	text := ctx.SourceFile.Text()
	firstStatementLine, hasFirstStatement := getFirstStatementLine(ctx.SourceFile)

	// Process the text to find comments
	processComments(ctx, text, configs, opts.MinimumDescriptionLength, firstStatementLine, hasFirstStatement)

	return rule.RuleListeners{}
}

// parseDirectiveConfig converts the option value to DirectiveConfig
func parseDirectiveConfig(value interface{}) *DirectiveConfig {
	config := &DirectiveConfig{Mode: directiveModeDisabled}

	switch v := value.(type) {
	case bool:
		if v {
			config.Mode = directiveModeBan
		}
	case string:
		if v == "allow-with-description" {
			config.Mode = directiveModeAllowWithDescription
		}
	case map[string]interface{}:
		if descFormat, ok := v["descriptionFormat"].(string); ok {
			config.Mode = directiveModeAllowWithDescription
			config.DescriptionFormat = descFormat
			if compiled, err := regexp.Compile(descFormat); err == nil {
				config.DescriptionRegex = compiled
			}
		}
	}

	return config
}

func getFirstStatementLine(sourceFile *ast.SourceFile) (int, bool) {
	sf := sourceFile.AsSourceFile()
	if sf == nil || sf.Statements == nil || len(sf.Statements.Nodes) == 0 {
		return 0, false
	}
	firstStatementStart := utils.TrimNodeTextRange(sourceFile, sf.Statements.Nodes[0]).Pos()
	line, _ := scanner.GetECMALineAndCharacterOfPosition(sourceFile, firstStatementStart)
	return line + 1, true
}

// processComments scans the source text for comments and checks for banned directives
func processComments(
	ctx rule.RuleContext,
	text string,
	configs map[string]*DirectiveConfig,
	minDescLength int,
	firstStatementLine int,
	hasFirstStatement bool,
) {
	pos := 0
	length := len(text)

	for pos < length {
		// Skip to next potential comment
		if pos+1 < length {
			if text[pos] == '/' && text[pos+1] == '/' {
				// Single-line comment
				commentStart := pos
				pos += 2
				lineEnd := pos
				for lineEnd < length && text[lineEnd] != '\n' && text[lineEnd] != '\r' {
					lineEnd++
				}
				commentText := text[commentStart:lineEnd]
				checkComment(ctx, commentText, commentStart, configs, minDescLength, false, firstStatementLine, hasFirstStatement)
				pos = lineEnd
			} else if text[pos] == '/' && text[pos+1] == '*' {
				// Multi-line comment
				commentStart := pos
				pos += 2
				commentEnd := pos
				for commentEnd+1 < length {
					if text[commentEnd] == '*' && text[commentEnd+1] == '/' {
						commentEnd += 2
						break
					}
					commentEnd++
				}
				commentText := text[commentStart:commentEnd]
				checkComment(ctx, commentText, commentStart, configs, minDescLength, true, firstStatementLine, hasFirstStatement)
				pos = commentEnd
			} else {
				pos++
			}
		} else {
			pos++
		}
	}
}

// checkComment checks a single comment for banned directives
func checkComment(
	ctx rule.RuleContext,
	commentText string,
	commentStart int,
	configs map[string]*DirectiveConfig,
	minDescLength int,
	isMultiLine bool,
	firstStatementLine int,
	hasFirstStatement bool,
) {
	commentValue := commentText
	if isMultiLine {
		if len(commentValue) >= 4 && strings.HasPrefix(commentValue, "/*") && strings.HasSuffix(commentValue, "*/") {
			commentValue = commentValue[2 : len(commentValue)-2]
		}
	} else if len(commentValue) >= 2 && strings.HasPrefix(commentValue, "//") {
		commentValue = commentValue[2:]
	}

	var directiveType string
	var description string

	if isMultiLine {
		lines := strings.Split(commentValue, "\n")
		lastLine := lines[len(lines)-1]
		match := multiLineDirectiveRegex.FindStringSubmatch(lastLine)
		if match == nil {
			return
		}
		directiveType = match[1]
		description = match[2]
	} else {
		if match := singleLinePragmaRegex.FindStringSubmatch(commentText); match != nil {
			directiveType = match[1]
			description = match[2]
		} else {
			match := singleLineDirectiveRegex.FindStringSubmatch(commentValue)
			if match == nil {
				return
			}
			directiveType = match[1]
			description = match[2]
		}
	}

	if directiveType == "nocheck" && hasFirstStatement {
		commentLine, _ := scanner.GetECMALineAndCharacterOfPosition(ctx.SourceFile, commentStart)
		if firstStatementLine <= commentLine+1 {
			return
		}
	}

	directiveName := "ts-" + directiveType
	config, exists := configs[directiveName]
	if !exists || config == nil {
		return
	}

	reportRange := core.NewTextRange(commentStart, commentStart+len(commentText))

	switch config.Mode {
	case directiveModeDisabled:
		return
	case directiveModeBan:
		if directiveType == "ignore" {
			replacement := strings.Replace(commentText, "@ts-ignore", "@ts-expect-error", 1)
			ctx.ReportRangeWithSuggestions(
				reportRange,
				buildTsIgnoreInsteadOfExpectErrorMessage(),
				rule.RuleSuggestion{
					Message: buildReplaceTsIgnoreWithTsExpectErrorMessage(),
					FixesArr: []rule.RuleFix{
						rule.RuleFixReplaceRange(reportRange, replacement),
					},
				},
			)
			return
		}
		ctx.ReportRange(reportRange, buildTsDirectiveCommentMessage(directiveType))
	case directiveModeAllowWithDescription:
		if graphemeLength(strings.TrimSpace(description)) < minDescLength {
			ctx.ReportRange(reportRange, buildTsDirectiveCommentRequiresDescriptionMessage(directiveType, minDescLength))
			return
		}
		if config.DescriptionRegex != nil && !config.DescriptionRegex.MatchString(description) {
			ctx.ReportRange(reportRange, buildTsDirectiveCommentDescriptionNotMatchPatternMessage(directiveType, config.DescriptionFormat))
		}
	}
}

// graphemeLength returns the number of grapheme clusters in a string
// This properly handles Unicode characters including emojis
func graphemeLength(s string) int {
	count := 0
	previousWasZWJ := false

	for _, r := range s {
		// Zero-width joiner joins this rune with previous grapheme cluster.
		if r == '\u200d' {
			previousWasZWJ = true
			continue
		}
		// Variation selectors and combining marks are part of previous grapheme.
		if (r >= 0xFE00 && r <= 0xFE0F) || unicode.Is(unicode.Mn, r) {
			continue
		}
		if previousWasZWJ {
			previousWasZWJ = false
			continue
		}
		count++
	}

	return count
}

// formatInt converts an integer to a string
func formatInt(n int) string {
	if n < 0 {
		return "-" + formatInt(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return formatInt(n/10) + string(rune('0'+n%10))
}
