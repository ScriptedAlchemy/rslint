package consistent_generic_constructors

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ConsistentGenericConstructorsOptions struct {
	Style string `json:"style"`
}

const (
	styleConstructor    = "constructor"
	styleTypeAnnotation = "type-annotation"
)

func buildPreferConstructorMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferConstructor",
		Description: "The generic type arguments should be specified as part of the constructor type arguments.",
	}
}

func buildPreferTypeAnnotationMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferTypeAnnotation",
		Description: "The generic type arguments should be specified as part of the type annotation.",
	}
}

func parseStyle(options any) string {
	style := styleConstructor
	if options == nil {
		return style
	}
	if array, ok := options.([]interface{}); ok && len(array) > 0 {
		if value, ok := array[0].(string); ok && (value == styleConstructor || value == styleTypeAnnotation) {
			return value
		}
		return style
	}
	if value, ok := options.(string); ok && (value == styleConstructor || value == styleTypeAnnotation) {
		return value
	}
	return style
}

func hasTypeArguments(list *ast.NodeList) bool {
	return list != nil && len(list.Nodes) > 0
}

func tokenRange(sourceFile *ast.SourceFile, node *ast.Node) core.TextRange {
	return utils.TrimNodeTextRange(sourceFile, node)
}

func findFirstToken(node *ast.Node, kind ast.Kind, predicate func(token *ast.Node) bool, sourceFile *ast.SourceFile) *ast.Node {
	var found *ast.Node
	utils.ForEachToken(node, func(token *ast.Node) {
		if found != nil || token == nil || token.Kind != kind {
			return
		}
		if predicate == nil || predicate(token) {
			found = token
		}
	}, sourceFile)
	return found
}

func findLastToken(node *ast.Node, kind ast.Kind, predicate func(token *ast.Node) bool, sourceFile *ast.SourceFile) *ast.Node {
	var found *ast.Node
	utils.ForEachToken(node, func(token *ast.Node) {
		if token == nil || token.Kind != kind {
			return
		}
		if predicate == nil || predicate(token) {
			found = token
		}
	}, sourceFile)
	return found
}

func typeArgumentsRange(container *ast.Node, args []*ast.Node, sourceFile *ast.SourceFile) (core.TextRange, bool) {
	if container == nil || sourceFile == nil || len(args) == 0 {
		return core.TextRange{}, false
	}
	firstArg := args[0]
	lastArg := args[len(args)-1]
	if firstArg == nil || lastArg == nil {
		return core.TextRange{}, false
	}
	firstRange := tokenRange(sourceFile, firstArg)
	lastRange := tokenRange(sourceFile, lastArg)
	lessToken := findLastToken(container, ast.KindLessThanToken, func(token *ast.Node) bool {
		return tokenRange(sourceFile, token).End() <= firstRange.Pos()
	}, sourceFile)
	greaterToken := findFirstToken(container, ast.KindGreaterThanToken, func(token *ast.Node) bool {
		return tokenRange(sourceFile, token).Pos() >= lastRange.End()
	}, sourceFile)
	if lessToken == nil || greaterToken == nil {
		return core.TextRange{}, false
	}
	lessRange := tokenRange(sourceFile, lessToken)
	greaterRange := tokenRange(sourceFile, greaterToken)
	return lessRange.WithEnd(greaterRange.End()), true
}

func findTypeAnnotationRange(declarationNode *ast.Node, typeAnnotation *ast.Node, sourceFile *ast.SourceFile) (core.TextRange, core.TextRange, bool) {
	if declarationNode == nil || typeAnnotation == nil || sourceFile == nil {
		return core.TextRange{}, core.TextRange{}, false
	}
	typeRange := tokenRange(sourceFile, typeAnnotation)
	colonToken := findLastToken(declarationNode, ast.KindColonToken, func(token *ast.Node) bool {
		return tokenRange(sourceFile, token).End() <= typeRange.Pos()
	}, sourceFile)
	if colonToken == nil {
		return core.TextRange{}, core.TextRange{}, false
	}
	colonRange := tokenRange(sourceFile, colonToken)
	return colonRange.WithEnd(typeRange.End()), colonRange, true
}

func extractCommentsOutsideRange(source string, start int, end int, exclude core.TextRange) string {
	if start < 0 || end > len(source) || start >= end {
		return ""
	}
	commentText := ""
	for i := start; i+1 < end; {
		if source[i] == '/' && source[i+1] == '*' {
			j := i + 2
			for j+1 < end {
				if source[j] == '*' && source[j+1] == '/' {
					j += 2
					break
				}
				j++
			}
			if j > end {
				j = end
			}
			if j <= exclude.Pos() || i >= exclude.End() {
				commentText += source[i:j]
			}
			i = j
			continue
		}
		if source[i] == '/' && source[i+1] == '/' {
			j := i + 2
			for j < end && source[j] != '\n' && source[j] != '\r' {
				j++
			}
			if j <= exclude.Pos() || i >= exclude.End() {
				commentText += source[i:j]
			}
			i = j
			continue
		}
		i++
	}
	return commentText
}

type newExpressionInfo struct {
	callee        *ast.Node
	calleeName    string
	calleeText    string
	hasTypeArgs   bool
	typeArgsRange core.TextRange
	typeArgsText  string
	hasParens     bool
}

func extractNewExpressionInfo(initializer *ast.Node, sourceFile *ast.SourceFile, sourceText string) (newExpressionInfo, bool) {
	if initializer == nil || initializer.Kind != ast.KindNewExpression || sourceFile == nil {
		return newExpressionInfo{}, false
	}
	newExpr := initializer.AsNewExpression()
	if newExpr == nil || newExpr.Expression == nil || newExpr.Expression.Kind != ast.KindIdentifier {
		return newExpressionInfo{}, false
	}
	calleeRange := tokenRange(sourceFile, newExpr.Expression)
	info := newExpressionInfo{
		callee:     newExpr.Expression,
		calleeName: newExpr.Expression.AsIdentifier().Text,
		calleeText: sourceText[calleeRange.Pos():calleeRange.End()],
		hasParens:  newExpr.Arguments != nil,
	}
	if hasTypeArguments(newExpr.TypeArguments) {
		argsRange, ok := typeArgumentsRange(initializer, newExpr.TypeArguments.Nodes, sourceFile)
		if !ok {
			return newExpressionInfo{}, false
		}
		info.hasTypeArgs = true
		info.typeArgsRange = argsRange
		info.typeArgsText = sourceText[argsRange.Pos():argsRange.End()]
	}
	return info, true
}

type typeReferenceInfo struct {
	typeName      string
	hasTypeArgs   bool
	typeArgsRange core.TextRange
	typeArgsText  string
}

func extractTypeReferenceInfo(typeAnnotation *ast.Node, sourceFile *ast.SourceFile, sourceText string) (typeReferenceInfo, bool) {
	if typeAnnotation == nil || typeAnnotation.Kind != ast.KindTypeReference {
		return typeReferenceInfo{}, false
	}
	typeRef := typeAnnotation.AsTypeReference()
	if typeRef == nil || typeRef.TypeName == nil || typeRef.TypeName.Kind != ast.KindIdentifier {
		return typeReferenceInfo{}, false
	}
	info := typeReferenceInfo{
		typeName: typeRef.TypeName.AsIdentifier().Text,
	}
	if hasTypeArguments(typeRef.TypeArguments) {
		argsRange, ok := typeArgumentsRange(typeAnnotation, typeRef.TypeArguments.Nodes, sourceFile)
		if !ok {
			return typeReferenceInfo{}, false
		}
		info.hasTypeArgs = true
		info.typeArgsRange = argsRange
		info.typeArgsText = sourceText[argsRange.Pos():argsRange.End()]
	}
	return info, true
}

func buildPreferConstructorFixes(
	ctx rule.RuleContext,
	declarationNode *ast.Node,
	typeAnnotation *ast.Node,
	newInfo newExpressionInfo,
	typeInfo typeReferenceInfo,
) ([]rule.RuleFix, bool) {
	if ctx.SourceFile == nil || declarationNode == nil || typeAnnotation == nil {
		return nil, false
	}
	sourceText := ctx.SourceFile.Text()
	typeRange := tokenRange(ctx.SourceFile, typeAnnotation)
	annotationRange, colonRange, ok := findTypeAnnotationRange(declarationNode, typeAnnotation, ctx.SourceFile)
	if !ok {
		return nil, false
	}
	extraComments := extractCommentsOutsideRange(sourceText, colonRange.End(), typeRange.End(), typeInfo.typeArgsRange)
	insertion := extraComments + typeInfo.typeArgsText
	if !newInfo.hasParens {
		insertion += "()"
	}
	calleeRange := tokenRange(ctx.SourceFile, newInfo.callee)
	insertAtCalleeEnd := calleeRange.WithPos(calleeRange.End()).WithEnd(calleeRange.End())
	return []rule.RuleFix{
		rule.RuleFixRemoveRange(annotationRange),
		rule.RuleFixReplaceRange(insertAtCalleeEnd, insertion),
	}, true
}

func buildPreferTypeAnnotationFixes(
	ctx rule.RuleContext,
	lhsName *ast.Node,
	newInfo newExpressionInfo,
) ([]rule.RuleFix, bool) {
	if ctx.SourceFile == nil || lhsName == nil || !newInfo.hasTypeArgs {
		return nil, false
	}
	lhsRange := tokenRange(ctx.SourceFile, lhsName)
	insertAtLhsEnd := lhsRange.WithPos(lhsRange.End()).WithEnd(lhsRange.End())
	typeAnnotationText := ": " + newInfo.calleeText + newInfo.typeArgsText
	return []rule.RuleFix{
		rule.RuleFixRemoveRange(newInfo.typeArgsRange),
		rule.RuleFixReplaceRange(insertAtLhsEnd, typeAnnotationText),
	}, true
}

// ConsistentGenericConstructorsRule enforces consistent generic specifier style in constructor signatures
var ConsistentGenericConstructorsRule = rule.CreateRule(rule.Rule{
	Name: "consistent-generic-constructors",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := ConsistentGenericConstructorsOptions{
		Style: styleConstructor,
	}
	isIsolatedDeclarations := ctx.ParserOptions != nil && ctx.ParserOptions.IsolatedDeclarations
	opts.Style = parseStyle(options)
	sourceFile := ctx.SourceFile
	sourceText := ""
	if sourceFile != nil {
		sourceText = sourceFile.Text()
	}

	checkNode := func(node *ast.Node, lhsName *ast.Node, typeAnnotation *ast.Node, initializer *ast.Node, isBindingElement bool) {
		if initializer == nil {
			return
		}
		newInfo, ok := extractNewExpressionInfo(initializer, sourceFile, sourceText)
		if !ok {
			return
		}

		// Handle case where there's no type annotation
		if typeAnnotation == nil {
			if opts.Style == styleTypeAnnotation && newInfo.hasTypeArgs && !isBindingElement {
				msg := buildPreferTypeAnnotationMessage()
				if fixes, ok := buildPreferTypeAnnotationFixes(ctx, lhsName, newInfo); ok {
					ctx.ReportNodeWithFixes(node, msg, fixes...)
				} else {
					ctx.ReportNode(node, msg)
				}
			}
			return
		}

		typeInfo, ok := extractTypeReferenceInfo(typeAnnotation, sourceFile, sourceText)
		if !ok || typeInfo.typeName != newInfo.calleeName {
			return
		}

		if opts.Style == styleTypeAnnotation {
			return
		}

		if !(typeInfo.hasTypeArgs && !newInfo.hasTypeArgs) {
			return
		}
		if isIsolatedDeclarations {
			return
		}
		msg := buildPreferConstructorMessage()
		if fixes, ok := buildPreferConstructorFixes(ctx, node, typeAnnotation, newInfo, typeInfo); ok {
			ctx.ReportNodeWithFixes(node, msg, fixes...)
		} else {
			ctx.ReportNode(node, msg)
		}
	}

	return rule.RuleListeners{
		// Variable declarations
		ast.KindVariableDeclaration: func(node *ast.Node) {
			if node.Kind != ast.KindVariableDeclaration {
				return
			}
			varDecl := node.AsVariableDeclaration()
			if varDecl == nil {
				return
			}

			// For destructuring patterns, we need to be careful:
			// - `const {a}: Foo<string> = new Foo()` - has type annotation, should check
			// - `const {a} = new Foo<string>()` - the BindingElement listener handles elements inside
			// - `const [a = new Foo<string>()] = []` - the BindingElement listener handles elements inside
			// Since VariableDeclaration's initializer is the whole RHS (e.g., `[]`), not the BindingElement's initializer,
			// we can check if the name is a binding pattern without type annotation and skip
			if varDecl.Type == nil && varDecl.Name() != nil {
				nameKind := varDecl.Name().Kind
				if nameKind == ast.KindArrayBindingPattern || nameKind == ast.KindObjectBindingPattern {
					return
				}
			}

			checkNode(node, varDecl.Name(), varDecl.Type, varDecl.Initializer, false)
		},

		// Property declarations (class properties, including accessor properties)
		ast.KindPropertyDeclaration: func(node *ast.Node) {
			if node.Kind != ast.KindPropertyDeclaration {
				return
			}
			propDecl := node.AsPropertyDeclaration()
			if propDecl == nil {
				return
			}
			checkNode(node, node.Name(), propDecl.Type, propDecl.Initializer, false)
		},

		// Parameters (for functions, constructors, methods, arrow functions)
		ast.KindParameter: func(node *ast.Node) {
			if node.Kind != ast.KindParameter {
				return
			}
			param := node.AsParameterDeclaration()
			if param == nil {
				return
			}

			// Skip if the name is a binding pattern (destructuring), there's no type annotation,
			// AND there's no initializer on the parameter itself
			// If there's a type annotation, we should check it (e.g., `function foo({a}: Foo<string> = new Foo()) {}`)
			// If there's an initializer on the parameter, we should check it (e.g., `function foo({a} = new Foo<string>()) {}`)
			// Only skip when the BindingElement listener will handle initializers inside the pattern (e.g., `function foo([a = new Foo<string>()]) {}`)
			if param.Type == nil && param.Initializer == nil && param.Name() != nil {
				nameKind := param.Name().Kind
				if nameKind == ast.KindArrayBindingPattern || nameKind == ast.KindObjectBindingPattern {
					return
				}
			}

			checkNode(node, param.Name(), param.Type, param.Initializer, false)
		},

		// Binding elements (for destructuring patterns)
		ast.KindBindingElement: func(node *ast.Node) {
			if node.Kind != ast.KindBindingElement {
				return
			}
			bindingElem := node.AsBindingElement()
			if bindingElem == nil {
				return
			}
			// BindingElement doesn't have a Type field, it can only have an initializer
			checkNode(node, nil, nil, bindingElem.Initializer, true)
		},
	}
}
