package ban_tslint_comment

import (
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
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
	sourceText := ctx.SourceFile.Text()
	utils.ForEachComment(ctx.SourceFile.AsNode(), func(comment *ast.CommentRange) {
		if comment == nil {
			return
		}
		commentText := sourceText[comment.Pos():comment.End()]
		commentValue, isLineComment, ok := extractCommentValue(commentText, comment.Kind)
		if !ok {
			return
		}
		reportIfMatched(ctx, sourceText, comment.Pos(), comment.End(), commentValue, isLineComment)
	}, ctx.SourceFile)
}

func extractCommentValue(commentText string, kind ast.Kind) (string, bool, bool) {
	switch kind {
	case ast.KindSingleLineCommentTrivia:
		if len(commentText) < 2 || !strings.HasPrefix(commentText, "//") {
			return "", false, false
		}
		return commentText[2:], true, true
	case ast.KindMultiLineCommentTrivia:
		if len(commentText) < 4 || !strings.HasPrefix(commentText, "/*") || !strings.HasSuffix(commentText, "*/") {
			return "", false, false
		}
		return commentText[2 : len(commentText)-2], false, true
	default:
		return "", false, false
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
		previousChar := sourceText[commentStart-1]
		if previousChar == ' ' || previousChar == '\t' {
			removeStart = commentStart - 1
		}
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
