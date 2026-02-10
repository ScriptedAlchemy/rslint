package no_invalid_this

import (
	"unicode"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnexpectedThisMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unexpectedThis",
		Description: "Unexpected 'this' usage outside a valid class/object context.",
	}
}

func hasExplicitThisParameter(fnNode *ast.Node) bool {
	if fnNode == nil {
		return false
	}
	parameters := fnNode.Parameters()
	if len(parameters) == 0 {
		return false
	}
	firstParam := parameters[0]
	if firstParam == nil || firstParam.Kind != ast.KindParameter {
		return false
	}
	param := firstParam.AsParameterDeclaration()
	return param != nil && param.Name() != nil && param.Name().Kind == ast.KindIdentifier && param.Name().AsIdentifier().Text == "this"
}

func isLikelyConstructorFunction(fn *ast.Node) bool {
	if fn == nil || fn.Kind != ast.KindFunctionDeclaration {
		return false
	}
	functionDecl := fn.AsFunctionDeclaration()
	if functionDecl == nil || functionDecl.Name() == nil || functionDecl.Name().Kind != ast.KindIdentifier {
		return false
	}
	name := functionDecl.Name().AsIdentifier().Text
	if name == "" {
		return false
	}
	return unicode.IsUpper([]rune(name)[0])
}

func isFunctionExpressionInMethodLikePosition(fn *ast.Node) bool {
	if fn == nil {
		return false
	}
	parent := fn.Parent
	if parent == nil {
		return false
	}
	switch parent.Kind {
	case ast.KindPropertyAssignment, ast.KindMethodDeclaration, ast.KindGetAccessor, ast.KindSetAccessor:
		return true
	case ast.KindBinaryExpression:
		binaryExpr := parent.AsBinaryExpression()
		if binaryExpr == nil || binaryExpr.OperatorToken.Kind != ast.KindEqualsToken {
			return false
		}
		return binaryExpr.Right == fn && (binaryExpr.Left.Kind == ast.KindPropertyAccessExpression || binaryExpr.Left.Kind == ast.KindElementAccessExpression)
	default:
		return false
	}
}

func isInsideClassMember(node *ast.Node) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		switch current.Kind {
		case ast.KindConstructor, ast.KindMethodDeclaration, ast.KindGetAccessor, ast.KindSetAccessor, ast.KindPropertyDeclaration:
			return true
		case ast.KindClassDeclaration, ast.KindClassExpression:
			return false
		}
	}
	return false
}

func nearestNonArrowFunction(node *ast.Node) *ast.Node {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindArrowFunction {
			continue
		}
		if current.Kind == ast.KindFunctionDeclaration || current.Kind == ast.KindFunctionExpression {
			return current
		}
	}
	return nil
}

var NoInvalidThisRule = rule.CreateRule(rule.Rule{
	Name: "no-invalid-this",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options
		return rule.RuleListeners{
			ast.KindThisKeyword: func(node *ast.Node) {
				if isInsideClassMember(node) {
					return
				}

				fn := nearestNonArrowFunction(node)
				if fn == nil {
					ctx.ReportNode(node, buildUnexpectedThisMessage())
					return
				}

				switch fn.Kind {
				case ast.KindFunctionDeclaration:
					if hasExplicitThisParameter(fn) {
						return
					}
					if isLikelyConstructorFunction(fn) {
						return
					}
				case ast.KindFunctionExpression:
					if hasExplicitThisParameter(fn) {
						return
					}
					if isFunctionExpressionInMethodLikePosition(fn) {
						return
					}
				}

				ctx.ReportNode(node, buildUnexpectedThisMessage())
			},
		}
	},
})
