package restrict_template_expressions

import (
	"encoding/json"
	"fmt"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type RestrictTemplateExpressionsOptions struct {
	AllowNumber  bool     `json:"allowNumber"`
	AllowBoolean bool     `json:"allowBoolean"`
	AllowAny     bool     `json:"allowAny"`
	AllowNullish bool     `json:"allowNullish"`
	AllowRegExp  bool     `json:"allowRegExp"`
	AllowNever   bool     `json:"allowNever"`
	AllowArray   bool     `json:"allowArray"`
	Allow        []string `json:"allow"`
}

type restrictTemplateParsedOptions struct {
	AllowNumber  bool
	AllowBoolean bool
	AllowAny     bool
	AllowNullish bool
	AllowRegExp  bool
	AllowNever   bool
	AllowArray   bool
	Allow        []utils.TypeOrValueSpecifier
}

func parseOptions(options any) restrictTemplateParsedOptions {
	opts := restrictTemplateParsedOptions{
		AllowNumber:  true,
		AllowBoolean: true,
		AllowAny:     true,
		AllowNullish: true,
		AllowRegExp:  true,
		AllowNever:   false,
		AllowArray:   false,
		Allow: []utils.TypeOrValueSpecifier{
			{
				From: utils.TypeOrValueSpecifierFromLib,
				Name: utils.NameList{"Error", "URL", "URLSearchParams"},
			},
		},
	}

	raw := map[string]any{}
	applyRaw := func(payload any) {
		if payload == nil {
			return
		}
		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			return
		}
		_ = json.Unmarshal(jsonBytes, &raw)
	}

	switch value := options.(type) {
	case map[string]any:
		applyRaw(value)
	case []any:
		if len(value) > 0 {
			applyRaw(value[0])
		}
	default:
		if value != nil {
			applyRaw(value)
		}
	}

	if value, ok := raw["allowNumber"].(bool); ok {
		opts.AllowNumber = value
	}
	if value, ok := raw["allowBoolean"].(bool); ok {
		opts.AllowBoolean = value
	}
	if value, ok := raw["allowAny"].(bool); ok {
		opts.AllowAny = value
	}
	if value, ok := raw["allowNullish"].(bool); ok {
		opts.AllowNullish = value
	}
	if value, ok := raw["allowRegExp"].(bool); ok {
		opts.AllowRegExp = value
	}
	if value, ok := raw["allowNever"].(bool); ok {
		opts.AllowNever = value
	}
	if value, ok := raw["allowArray"].(bool); ok {
		opts.AllowArray = value
	}
	if allowValue, exists := raw["allow"]; exists {
		opts.Allow = []utils.TypeOrValueSpecifier{}
		allowJSON, err := json.Marshal(allowValue)
		if err == nil {
			_ = json.Unmarshal(allowJSON, &opts.Allow)
		}
	}

	return opts
}

func buildInvalidTypeMessage(typeName string) rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "invalidType",
		Description: fmt.Sprintf("Invalid type %q of template literal expression.", typeName),
	}
}

func matchesAllowedTypeOrBaseType(ctx rule.RuleContext, t *checker.Type, allow []utils.TypeOrValueSpecifier) bool {
	visited := map[*checker.Type]bool{}
	var walk func(*checker.Type) bool
	walk = func(current *checker.Type) bool {
		if current == nil || visited[current] {
			return false
		}
		visited[current] = true

		if utils.TypeMatchesSomeSpecifier(current, allow, nil, ctx.Program) {
			return true
		}

		symbol := checker.Type_symbol(current)
		if symbol == nil || symbol.Flags&(ast.SymbolFlagsClass|ast.SymbolFlagsInterface) == 0 {
			return false
		}
		declaredType := checker.Checker_getDeclaredTypeOfSymbol(ctx.TypeChecker, symbol)
		for _, baseType := range checker.Checker_getBaseTypes(ctx.TypeChecker, declaredType) {
			if walk(baseType) {
				return true
			}
		}
		return false
	}

	return walk(t)
}

// RestrictTemplateExpressionsRule implements the restrict-template-expressions rule
// Enforce template literal expressions to be of string type
var RestrictTemplateExpressionsRule = rule.CreateRule(rule.Rule{
	Name: "restrict-template-expressions",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := parseOptions(options)

	checkType := func(t *checker.Type, recursivelyCheckType func(*checker.Type) bool) bool {
		switch {
		case utils.IsTypeFlagSet(t, checker.TypeFlagsStringLike):
			return true
		case matchesAllowedTypeOrBaseType(ctx, t, opts.Allow):
			return true
		case opts.AllowAny && utils.IsTypeAnyType(t):
			return true
		case opts.AllowArray && checker.Checker_isArrayOrTupleType(ctx.TypeChecker, t):
			numberIndexType := utils.GetNumberIndexType(ctx.TypeChecker, t)
			if numberIndexType == nil {
				return false
			}
			return recursivelyCheckType(numberIndexType)
		case opts.AllowBoolean && utils.IsTypeFlagSet(t, checker.TypeFlagsBooleanLike):
			return true
		case opts.AllowNullish && utils.IsTypeFlagSet(t, checker.TypeFlagsNull|checker.TypeFlagsUndefined):
			return true
		case opts.AllowNumber && utils.IsTypeFlagSet(t, checker.TypeFlagsNumberLike|checker.TypeFlagsBigIntLike):
			return true
		case opts.AllowRegExp && utils.GetTypeName(ctx.TypeChecker, t) == "RegExp":
			return true
		case opts.AllowNever && utils.IsTypeFlagSet(t, checker.TypeFlagsNever):
			return true
		default:
			return false
		}
	}

	var recursivelyCheckType func(*checker.Type) bool
	recursivelyCheckType = func(t *checker.Type) bool {
		if t == nil {
			return false
		}
		if utils.IsUnionType(t) {
			return utils.Every(utils.UnionTypeParts(t), recursivelyCheckType)
		}
		if utils.IsIntersectionType(t) {
			return utils.Some(utils.IntersectionTypeParts(t), recursivelyCheckType)
		}
		return checkType(t, recursivelyCheckType)
	}

	return rule.RuleListeners{
		ast.KindTemplateExpression: func(node *ast.Node) {
			// This rule requires type information
			if ctx.TypeChecker == nil {
				return
			}

			templateExpr := node.AsTemplateExpression()
			if templateExpr == nil || templateExpr.TemplateSpans == nil {
				return
			}
			if node.Parent != nil && node.Parent.Kind == ast.KindTaggedTemplateExpression {
				return
			}

			// Check each template span's expression
			for _, span := range templateExpr.TemplateSpans.Nodes {
				templateSpan := span.AsTemplateSpan()
				if templateSpan == nil || templateSpan.Expression == nil {
					continue
				}
				expressionType := utils.GetConstrainedTypeAtLocation(ctx.TypeChecker, templateSpan.Expression)
				if recursivelyCheckType(expressionType) {
					continue
				}
				ctx.ReportNode(templateSpan.Expression, buildInvalidTypeMessage(ctx.TypeChecker.TypeToString(expressionType)))
			}
		},
	}
}
