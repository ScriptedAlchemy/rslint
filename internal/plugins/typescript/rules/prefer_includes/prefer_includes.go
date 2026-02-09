package prefer_includes

import (
	"strconv"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func buildPreferIncludesMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferIncludes",
		Description: "Use 'includes()' method instead.",
	}
}

// PreferIncludesRule checks for indexOf comparisons that can use includes instead.
var PreferIncludesRule = rule.CreateRule(rule.Rule{
	Name: "prefer-includes",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		getNodeText := func(n *ast.Node) string {
			if n == nil {
				return ""
			}
			sf := ast.GetSourceFileOfNode(n)
			if sf == nil {
				return ""
			}
			rng := utils.TrimNodeTextRange(sf, n)
			return sf.Text()[rng.Pos():rng.End()]
		}

		isNumber := func(node *ast.Node, value int) bool {
			if node == nil {
				return false
			}
			switch node.Kind {
			case ast.KindPrefixUnaryExpression:
				pref := node.AsPrefixUnaryExpression()
				if pref != nil && pref.Operator == ast.KindMinusToken {
					if ast.IsNumericLiteral(pref.Operand) {
						v, err := strconv.Atoi(pref.Operand.AsNumericLiteral().Text)
						return err == nil && -v == value
					}
				}
			case ast.KindNumericLiteral:
				v, err := strconv.Atoi(node.AsNumericLiteral().Text)
				return err == nil && v == value
			}
			return false
		}

		isPositiveCheck := func(node *ast.Node) bool {
			if node == nil || node.Kind != ast.KindBinaryExpression {
				return false
			}
			bin := node.AsBinaryExpression()
			switch bin.OperatorToken.Kind {
			case ast.KindExclamationEqualsEqualsToken, ast.KindExclamationEqualsToken, ast.KindGreaterThanToken:
				return isNumber(bin.Right, -1)
			case ast.KindGreaterThanEqualsToken:
				return isNumber(bin.Right, 0)
			}
			return false
		}

		isNegativeCheck := func(node *ast.Node) bool {
			if node == nil || node.Kind != ast.KindBinaryExpression {
				return false
			}
			bin := node.AsBinaryExpression()
			switch bin.OperatorToken.Kind {
			case ast.KindEqualsEqualsEqualsToken, ast.KindEqualsEqualsToken, ast.KindLessThanEqualsToken:
				return isNumber(bin.Right, -1)
			case ast.KindLessThanToken:
				return isNumber(bin.Right, 0)
			}
			return false
		}

		hasSameParameters := func(nodeA, nodeB *ast.Node) bool {
			if nodeA == nil || nodeB == nil || !ast.IsFunctionLike(nodeA) || !ast.IsFunctionLike(nodeB) {
				return false
			}
			paramsA := nodeA.Parameters()
			paramsB := nodeB.Parameters()
			if paramsA == nil || paramsB == nil || len(paramsA) != len(paramsB) {
				return false
			}
			for i := range paramsA {
				if getNodeText(paramsA[i]) != getNodeText(paramsB[i]) {
					return false
				}
			}
			return true
		}

		checkArrayIndexOf := func(prop *ast.Node, allowFix bool, bin *ast.Node) {
			if prop == nil || prop.Kind != ast.KindPropertyAccessExpression {
				return
			}
			pae := prop.AsPropertyAccessExpression()
			nameNode := pae.Name()
			if pae == nil || nameNode == nil || nameNode.Text() != "indexOf" {
				return
			}
			call := prop.Parent
			if call == nil || call.Kind != ast.KindCallExpression {
				return
			}
			negative := isNegativeCheck(bin)
			if !negative && !isPositiveCheck(bin) {
				return
			}
			name := nameNode
			sym := ctx.TypeChecker.GetSymbolAtLocation(name)
			if sym == nil || sym.Declarations == nil || len(sym.Declarations) == 0 {
				return
			}
			for _, decl := range sym.Declarations {
				typeDecl := decl.Parent
				t := ctx.TypeChecker.GetTypeAtLocation(typeDecl)
				includesSym := checker.Checker_getPropertyOfType(ctx.TypeChecker, t, "includes")
				if includesSym == nil || includesSym.Declarations == nil {
					return
				}
				ok := false
				for _, incDecl := range includesSym.Declarations {
					if hasSameParameters(incDecl, decl) {
						ok = true
						break
					}
				}
				if !ok {
					return
				}
			}
			fixes := []rule.RuleFix{}
			if allowFix {
				if negative {
					fixes = append(fixes, rule.RuleFixInsertBefore(ctx.SourceFile, call, "!"))
				}
				fixes = append(fixes, rule.RuleFixReplace(ctx.SourceFile, name, "includes"))
				fixes = append(fixes, rule.RuleFixRemoveRange(core.NewTextRange(call.End(), bin.End())))
			}
			ctx.ReportNodeWithFixes(bin, buildPreferIncludesMessage(), fixes...)
		}

		return rule.RuleListeners{
			ast.KindBinaryExpression: func(node *ast.Node) {
				bin := node.AsBinaryExpression()
				left := ast.SkipParentheses(bin.Left)
				if left.Kind != ast.KindCallExpression {
					return
				}
				call := left.AsCallExpression()
				expr := ast.SkipParentheses(call.Expression)
				if expr.Kind != ast.KindPropertyAccessExpression {
					return
				}
				prop := expr
				allowFix := expr.AsPropertyAccessExpression().QuestionDotToken == nil
				checkArrayIndexOf(prop, allowFix, node)
			},
		}
	},
})
