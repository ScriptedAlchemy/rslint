package sort_type_constituents

import (
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildNotSortedMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "notSorted",
		Description: "Type constituents are not sorted.",
	}
}

func nodeText(ctx rule.RuleContext, node *ast.Node) string {
	if ctx.SourceFile == nil || node == nil {
		return ""
	}
	r := utils.TrimNodeTextRange(ctx.SourceFile, node)
	return strings.TrimSpace(ctx.SourceFile.Text()[r.Pos():r.End()])
}

func isSorted(values []string) bool {
	for i := 1; i < len(values); i++ {
		if strings.Compare(values[i-1], values[i]) > 0 {
			return false
		}
	}
	return true
}

func checkConstituents(ctx rule.RuleContext, nodes []*ast.Node, reportNode *ast.Node) {
	if len(nodes) < 2 {
		return
	}
	values := make([]string, 0, len(nodes))
	for _, n := range nodes {
		values = append(values, nodeText(ctx, n))
	}
	if !isSorted(values) {
		ctx.ReportNode(reportNode, buildNotSortedMessage())
	}
}

var SortTypeConstituentsRule = rule.CreateRule(rule.Rule{
	Name: "sort-type-constituents",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindUnionType: func(node *ast.Node) {
				unionType := node.AsUnionTypeNode()
				if unionType == nil || unionType.Types == nil {
					return
				}
				checkConstituents(ctx, unionType.Types.Nodes, node)
			},
			ast.KindIntersectionType: func(node *ast.Node) {
				intersectionType := node.AsIntersectionTypeNode()
				if intersectionType == nil || intersectionType.Types == nil {
					return
				}
				checkConstituents(ctx, intersectionType.Types.Nodes, node)
			},
		}
	},
})
