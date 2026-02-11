package require_array_sort_compare

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildRequireCompareMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "requireCompare",
		Description: "Require 'compare' argument.",
	}
}

type RequireArraySortCompareOptions struct {
	IgnoreStringArrays *bool
}

func parseOptions(options any) RequireArraySortCompareOptions {
	opts := RequireArraySortCompareOptions{}

	applyMap := func(raw map[string]interface{}) {
		if raw == nil {
			return
		}
		if ignoreStringArrays, ok := raw["ignoreStringArrays"].(bool); ok {
			opts.IgnoreStringArrays = utils.Ref(ignoreStringArrays)
		}
	}

	switch raw := options.(type) {
	case RequireArraySortCompareOptions:
		opts = raw
	case *RequireArraySortCompareOptions:
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

	if opts.IgnoreStringArrays == nil {
		opts.IgnoreStringArrays = utils.Ref(true)
	}

	return opts
}

var RequireArraySortCompareRule = rule.CreateRule(rule.Rule{
	Name: "require-array-sort-compare",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		opts := parseOptions(options)

		return rule.RuleListeners{
			ast.KindCallExpression: func(node *ast.Node) {
				expr := node.AsCallExpression()
				if len(expr.Arguments.Nodes) != 0 {
					return
				}
				callee := expr.Expression

				if !ast.IsAccessExpression(callee) {
					return
				}

				if propertyName, found := checker.Checker_getAccessedPropertyName(ctx.TypeChecker, callee); !found || (propertyName != "sort" && propertyName != "toSorted") {
					return
				}

				calleeObjType := ctx.TypeChecker.GetTypeAtLocation(callee.Expression())
				if calleeObjType == nil || utils.IsTypeFlagSet(calleeObjType, checker.TypeFlagsTypeParameter) {
					calleeObjType = utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, callee.Expression())
				}
				if calleeObjType == nil {
					return
				}

				if *opts.IgnoreStringArrays && checker.Checker_isArrayOrTupleType(ctx.TypeChecker, calleeObjType) {
					if utils.Every(checker.Checker_getTypeArguments(ctx.TypeChecker, calleeObjType), func(t *checker.Type) bool {
						return utils.IsTypeFlagSet(t, checker.TypeFlagsString)
					}) {
						return
					}
				}

				if utils.Every(utils.UnionTypeParts(calleeObjType), func(t *checker.Type) bool {
					return checker.Checker_isArrayOrTupleType(ctx.TypeChecker, t)
				}) {
					ctx.ReportNode(node, buildRequireCompareMessage())
				}
			},
		}
	},
})
