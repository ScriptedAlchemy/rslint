package no_unnecessary_type_constraint

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryConstraintMessage(name string, constraint string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryConstraint",
		Description: "Type parameter `" + name + "` has an unnecessary `extends " + constraint + "` constraint.",
	}
}

func constraintText(kind ast.Kind) string {
	switch kind {
	case ast.KindAnyKeyword:
		return "any"
	case ast.KindUnknownKeyword:
		return "unknown"
	default:
		return ""
	}
}

var NoUnnecessaryTypeConstraintRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-type-constraint",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		return rule.RuleListeners{
			ast.KindTypeParameter: func(node *ast.Node) {
				typeParam := node.AsTypeParameter()
				if typeParam == nil || typeParam.Constraint == nil {
					return
				}

				constraintKind := typeParam.Constraint.Kind
				if constraintKind != ast.KindAnyKeyword && constraintKind != ast.KindUnknownKeyword {
					return
				}

				typeName := "T"
				if name := typeParam.Name(); name != nil && name.Kind == ast.KindIdentifier {
					typeName = name.AsIdentifier().Text
				}

				ctx.ReportNode(node, buildUnnecessaryConstraintMessage(typeName, constraintText(constraintKind)))
			},
		}
	},
})
