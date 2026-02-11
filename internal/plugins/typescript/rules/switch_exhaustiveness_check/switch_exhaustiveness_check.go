package switch_exhaustiveness_check

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type SwitchExhaustivenessCheckOptions struct {
	AllowDefaultCaseForExhaustiveSwitch *bool  `json:"allowDefaultCaseForExhaustiveSwitch"`
	RequireDefaultForNonUnion           *bool  `json:"requireDefaultForNonUnion"`
	ConsiderDefaultExhaustiveForUnions  *bool  `json:"considerDefaultExhaustiveForUnions"`
	DefaultCaseCommentPattern           string `json:"defaultCaseCommentPattern"`
}

type defaultCaseInfo struct {
	node    *ast.Node
	comment *ast.CommentRange
}

func parseOptions(options any) SwitchExhaustivenessCheckOptions {
	opts := SwitchExhaustivenessCheckOptions{
		AllowDefaultCaseForExhaustiveSwitch: utils.Ref(true),
		RequireDefaultForNonUnion:           utils.Ref(false),
		ConsiderDefaultExhaustiveForUnions:  utils.Ref(false),
		DefaultCaseCommentPattern:           "",
	}

	switch value := options.(type) {
	case SwitchExhaustivenessCheckOptions:
		if value.AllowDefaultCaseForExhaustiveSwitch != nil {
			opts.AllowDefaultCaseForExhaustiveSwitch = value.AllowDefaultCaseForExhaustiveSwitch
		}
		if value.RequireDefaultForNonUnion != nil {
			opts.RequireDefaultForNonUnion = value.RequireDefaultForNonUnion
		}
		if value.ConsiderDefaultExhaustiveForUnions != nil {
			opts.ConsiderDefaultExhaustiveForUnions = value.ConsiderDefaultExhaustiveForUnions
		}
		if value.DefaultCaseCommentPattern != "" {
			opts.DefaultCaseCommentPattern = value.DefaultCaseCommentPattern
		}
		return opts
	case *SwitchExhaustivenessCheckOptions:
		if value != nil {
			return parseOptions(*value)
		}
	}

	applyMap := func(raw map[string]interface{}) {
		if raw == nil {
			return
		}
		if value, ok := raw["allowDefaultCaseForExhaustiveSwitch"].(bool); ok {
			opts.AllowDefaultCaseForExhaustiveSwitch = utils.Ref(value)
		}
		if value, ok := raw["requireDefaultForNonUnion"].(bool); ok {
			opts.RequireDefaultForNonUnion = utils.Ref(value)
		}
		if value, ok := raw["considerDefaultExhaustiveForUnions"].(bool); ok {
			opts.ConsiderDefaultExhaustiveForUnions = utils.Ref(value)
		}
		if value, ok := raw["defaultCaseCommentPattern"].(string); ok {
			opts.DefaultCaseCommentPattern = value
		}
	}

	switch value := options.(type) {
	case map[string]interface{}:
		applyMap(value)
	case []interface{}:
		if len(value) > 0 {
			if firstMap, ok := value[0].(map[string]interface{}); ok {
				applyMap(firstMap)
			}
		}
	default:
		if value != nil {
			raw := map[string]interface{}{}
			if payload, err := json.Marshal(value); err == nil {
				if err := json.Unmarshal(payload, &raw); err == nil {
					applyMap(raw)
				}
			}
		}
	}

	return opts
}

func buildDangerousDefaultCaseMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "dangerousDefaultCase",
		Description: "The switch statement is exhaustive, so the default case is unnecessary.",
	}
}

func buildSwitchIsNotExhaustiveMessage(missingBranches string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "switchIsNotExhaustive",
		Description: "Switch is not exhaustive. Cases not matched: " + missingBranches,
	}
}

func isTypeLiteralLikeType(t *checker.Type) bool {
	return utils.IsTypeFlagSet(
		t,
		checker.TypeFlagsLiteral|
			checker.TypeFlagsUndefined|
			checker.TypeFlagsNull|
			checker.TypeFlagsUniqueESSymbol,
	)
}

func doesTypeContainNonLiteralType(t *checker.Type) bool {
	return utils.Some(utils.UnionTypeParts(t), func(part *checker.Type) bool {
		return utils.Every(utils.IntersectionTypeParts(part), func(subPart *checker.Type) bool {
			return !isTypeLiteralLikeType(subPart)
		})
	})
}

func commentContent(sourceText string, comment *ast.CommentRange) string {
	if comment == nil {
		return ""
	}
	start := comment.Pos()
	end := comment.End()
	if start < 0 || end > len(sourceText) || start >= end {
		return ""
	}
	switch comment.Kind {
	case ast.KindSingleLineCommentTrivia:
		if start+2 <= end {
			return strings.TrimSpace(sourceText[start+2 : end])
		}
	case ast.KindMultiLineCommentTrivia:
		if start+2 <= end-2 {
			return strings.TrimSpace(sourceText[start+2 : end-2])
		}
	}
	return ""
}

func getDefaultCaseInfo(
	sourceFile *ast.SourceFile,
	switchStmt *ast.SwitchStatement,
	commentPattern *regexp.Regexp,
) *defaultCaseInfo {
	if switchStmt == nil || switchStmt.CaseBlock == nil || switchStmt.CaseBlock.AsCaseBlock() == nil || switchStmt.CaseBlock.AsCaseBlock().Clauses == nil {
		return nil
	}
	clauses := switchStmt.CaseBlock.AsCaseBlock().Clauses.Nodes
	if len(clauses) == 0 {
		return nil
	}
	for _, clause := range clauses {
		if clause.Kind == ast.KindDefaultClause {
			return &defaultCaseInfo{node: clause}
		}
	}

	lastCase := clauses[len(clauses)-1]
	commentsAfterLastCase := []*ast.CommentRange{}
	commentSearchRange := core.NewTextRange(lastCase.End(), switchStmt.End())
	for comment := range utils.GetCommentsInRange(sourceFile, commentSearchRange) {
		commentCopy := comment
		commentsAfterLastCase = append(commentsAfterLastCase, &commentCopy)
	}
	if len(commentsAfterLastCase) == 0 {
		return nil
	}
	lastComment := commentsAfterLastCase[len(commentsAfterLastCase)-1]
	if commentPattern.MatchString(commentContent(sourceFile.Text(), lastComment)) {
		return &defaultCaseInfo{comment: lastComment}
	}
	return nil
}

func formatMissingBranchType(typeChecker *checker.Checker, missingType *checker.Type) string {
	if utils.IsTypeFlagSet(missingType, checker.TypeFlagsESSymbolLike) {
		symbol := checker.Type_symbol(missingType)
		if symbol != nil && symbol.Name != "" {
			return "typeof " + symbol.Name
		}
	}
	return typeChecker.TypeToString(missingType)
}

// SwitchExhaustivenessCheckRule implements the switch-exhaustiveness-check rule
// Require exhaustive switch statements
var SwitchExhaustivenessCheckRule = rule.CreateRule(rule.Rule{
	Name: "switch-exhaustiveness-check",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := parseOptions(options)

	commentPattern := regexp.MustCompile(`(?i)^no default$`)
	if opts.DefaultCaseCommentPattern != "" {
		if compiled, err := regexp.Compile(opts.DefaultCaseCommentPattern); err == nil {
			commentPattern = compiled
		}
	}

	return rule.RuleListeners{
		ast.KindSwitchStatement: func(node *ast.Node) {
			// This rule requires type information
			if ctx.TypeChecker == nil {
				return
			}

			switchStmt := node.AsSwitchStatement()
			if switchStmt == nil {
				return
			}
			discriminantType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, switchStmt.Expression)
			containsNonLiteralType := doesTypeContainNonLiteralType(discriminantType)
			defaultCase := getDefaultCaseInfo(ctx.SourceFile, switchStmt, commentPattern)

			caseTypes := map[*checker.Type]struct{}{}
			hasUndefinedCase := false
			if switchStmt.CaseBlock != nil && switchStmt.CaseBlock.AsCaseBlock() != nil && switchStmt.CaseBlock.AsCaseBlock().Clauses != nil {
				for _, clause := range switchStmt.CaseBlock.AsCaseBlock().Clauses.Nodes {
					if clause.Kind != ast.KindCaseClause || clause.Expression() == nil {
						continue
					}
					caseType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, clause.Expression())
					caseTypes[caseType] = struct{}{}
					if utils.IsTypeFlagSet(caseType, checker.TypeFlagsUndefined) {
						hasUndefinedCase = true
					}
				}
			}

			missingLiteralBranchTypes := []*checker.Type{}
			for _, unionPart := range utils.UnionTypeParts(discriminantType) {
				for _, intersectionPart := range utils.IntersectionTypeParts(unionPart) {
					if _, covered := caseTypes[intersectionPart]; covered {
						continue
					}
					if !isTypeLiteralLikeType(intersectionPart) {
						continue
					}
					if hasUndefinedCase && utils.IsTypeFlagSet(intersectionPart, checker.TypeFlagsUndefined) {
						continue
					}
					missingLiteralBranchTypes = append(missingLiteralBranchTypes, intersectionPart)
				}
			}

			if (!*opts.ConsiderDefaultExhaustiveForUnions || defaultCase == nil) && len(missingLiteralBranchTypes) > 0 {
				missingBranches := utils.Map(missingLiteralBranchTypes, func(missingType *checker.Type) string {
					return formatMissingBranchType(ctx.TypeChecker, missingType)
				})
				ctx.ReportNode(
					switchStmt.Expression,
					buildSwitchIsNotExhaustiveMessage(strings.Join(missingBranches, " | ")),
				)
			}

			if !*opts.AllowDefaultCaseForExhaustiveSwitch &&
				len(missingLiteralBranchTypes) == 0 &&
				defaultCase != nil &&
				!containsNonLiteralType {
				if defaultCase.node != nil {
					ctx.ReportNode(defaultCase.node, buildDangerousDefaultCaseMessage())
				} else if defaultCase.comment != nil {
					ctx.ReportRange(core.NewTextRange(defaultCase.comment.Pos(), defaultCase.comment.End()), buildDangerousDefaultCaseMessage())
				}
			}

			if *opts.RequireDefaultForNonUnion && containsNonLiteralType && defaultCase == nil {
				ctx.ReportNode(switchStmt.Expression, buildSwitchIsNotExhaustiveMessage("default"))
			}
		},
	}
}
