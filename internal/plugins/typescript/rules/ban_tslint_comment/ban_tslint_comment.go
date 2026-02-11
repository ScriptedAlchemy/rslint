package ban_tslint_comment

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
)

var enableDisableRegex = regexp.MustCompile(`^\s*tslint:(enable|disable)(?:-(line|next-line))?(:|\s|$)`)

// BanTslintCommentRule disallows tslint enable/disable comments.
var BanTslintCommentRule = rule.CreateRule(rule.Rule{
	Name: "ban-tslint-comment",
	Run:  run,
})

func run(ctx rule.RuleContext, _ any) rule.RuleListeners {
	processComments(ctx)
	return rule.RuleListeners{}
}

func processComments(ctx rule.RuleContext) {
	text := ctx.SourceFile.Text()
	length := len(text)

	pos := 0
	for pos < length {
		if pos+1 >= length {
			pos++
			continue
		}

		if text[pos] == '/' && text[pos+1] == '/' {
			commentStart := pos
			commentEnd := pos + 2
			for commentEnd < length && text[commentEnd] != '\n' && text[commentEnd] != '\r' {
				commentEnd++
			}

			commentValue := text[commentStart+2 : commentEnd]
			reportIfMatched(ctx, text, commentStart, commentEnd, commentValue, true)
			pos = commentEnd
			continue
		}

		if text[pos] == '/' && text[pos+1] == '*' {
			commentStart := pos
			commentEnd := pos + 2
			for commentEnd+1 < length && (text[commentEnd] != '*' || text[commentEnd+1] != '/') {
				commentEnd++
			}
			if commentEnd+1 < length {
				commentEnd += 2
			} else {
				commentEnd = length
			}

			commentValue := ""
			if commentEnd >= commentStart+4 {
				commentValue = text[commentStart+2 : commentEnd-2]
			}
			reportIfMatched(ctx, text, commentStart, commentEnd, commentValue, false)
			pos = commentEnd
			continue
		}

		pos++
	}
}

func reportIfMatched(
	ctx rule.RuleContext,
	sourceText string,
	commentStart int,
	commentEnd int,
	commentValue string,
	isLineComment bool,
) {
	if !enableDisableRegex.MatchString(commentValue) {
		return
	}

	commentRange := core.NewTextRange(commentStart, commentEnd)
	removeStart := commentStart
	if lineStart := getLineStartOffset(sourceText, commentStart); commentStart > lineStart {
		removeStart = commentStart - 1
	}
	removeEnd := commentEnd
	if removeEnd < len(sourceText) {
		switch sourceText[removeEnd] {
		case '\r':
			removeEnd++
			if removeEnd < len(sourceText) && sourceText[removeEnd] == '\n' {
				removeEnd++
			}
		case '\n':
			removeEnd++
		}
	}

	ctx.ReportRangeWithFixes(commentRange, rule.RuleMessage{
		Id:          "commentDetected",
		Description: "tslint comment detected: \"" + toText(commentValue, isLineComment) + "\"",
	}, rule.RuleFixRemoveRange(core.NewTextRange(removeStart, removeEnd)))
}

func getLineStartOffset(text string, pos int) int {
	if pos <= 0 {
		return 0
	}
	for i := pos - 1; i >= 0; i-- {
		if text[i] == '\n' {
			return i + 1
		}
		if text[i] == '\r' {
			return i + 1
		}
	}
	return 0
}

func toText(commentValue string, isLineComment bool) string {
	trimmed := strings.TrimSpace(commentValue)
	if isLineComment {
		return "// " + trimmed
	}
	return "/* " + trimmed + " */"
}
