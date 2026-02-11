package prefer_readonly_parameter_types

import (
	"encoding/json"
	"strings"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/checker"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type readonlyness uint8

const (
	readonlynessUnknown readonlyness = iota
	readonlynessMutable
	readonlynessReadonly
)

type PreferReadonlyParameterTypesOptions struct {
	CheckParameterProperties bool                         `json:"checkParameterProperties"`
	IgnoreInferredTypes      bool                         `json:"ignoreInferredTypes"`
	TreatMethodsAsReadonly   bool                         `json:"treatMethodsAsReadonly"`
	Allow                    []utils.TypeOrValueSpecifier `json:"allow"`
	AllowInline              []string
}

func buildShouldBeReadonlyMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "shouldBeReadonly",
		Description: "Parameter should be a read only type.",
	}
}

func parseOptions(options any) PreferReadonlyParameterTypesOptions {
	opts := PreferReadonlyParameterTypesOptions{
		CheckParameterProperties: true,
		IgnoreInferredTypes:      false,
		TreatMethodsAsReadonly:   false,
		Allow:                    []utils.TypeOrValueSpecifier{},
		AllowInline:              []string{},
	}
	if options == nil {
		return opts
	}

	raw := options
	if arr, ok := options.([]interface{}); ok {
		if len(arr) == 0 {
			return opts
		}
		raw = arr[0]
	}

	optsMap, ok := raw.(map[string]interface{})
	if !ok || optsMap == nil {
		return opts
	}

	if v, ok := optsMap["checkParameterProperties"].(bool); ok {
		opts.CheckParameterProperties = v
	}
	if v, ok := optsMap["ignoreInferredTypes"].(bool); ok {
		opts.IgnoreInferredTypes = v
	}
	if v, ok := optsMap["treatMethodsAsReadonly"].(bool); ok {
		opts.TreatMethodsAsReadonly = v
	}
	if allowRaw, ok := optsMap["allow"].([]interface{}); ok {
		for _, item := range allowRaw {
			switch entry := item.(type) {
			case string:
				opts.AllowInline = append(opts.AllowInline, entry)
			default:
				data, err := json.Marshal(entry)
				if err != nil {
					continue
				}
				var specifier utils.TypeOrValueSpecifier
				if err := json.Unmarshal(data, &specifier); err == nil {
					opts.Allow = append(opts.Allow, specifier)
				}
			}
		}
	}
	return opts
}

func isLiteralOrTaggablePrimitiveLike(t *checker.Type) bool {
	if t == nil {
		return false
	}
	if checker.Type_flags(t)&checker.TypeFlagsLiteral != 0 {
		return true
	}
	return utils.IsTypeFlagSet(t, checker.TypeFlagsBigInt|checker.TypeFlagsNumber|checker.TypeFlagsString|checker.TypeFlagsTemplateLiteral)
}

func isObjectLiteralLike(typeChecker *checker.Checker, t *checker.Type) bool {
	if t == nil || typeChecker == nil {
		return false
	}
	return len(checker.Checker_getSignaturesOfType(typeChecker, t, checker.SignatureKindCall)) == 0 &&
		len(checker.Checker_getSignaturesOfType(typeChecker, t, checker.SignatureKindConstruct)) == 0 &&
		utils.IsTypeFlagSet(t, checker.TypeFlagsObject)
}

func isTypeBrandedLiteral(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil || checker.Type_flags(t)&checker.TypeFlagsIntersection == 0 {
		return false
	}
	hadObjectLike := false
	hadPrimitiveLike := false
	for _, constituent := range t.Types() {
		if isObjectLiteralLike(typeChecker, constituent) {
			hadObjectLike = true
		} else if isLiteralOrTaggablePrimitiveLike(constituent) {
			hadPrimitiveLike = true
		} else {
			return false
		}
	}
	return hadObjectLike && hadPrimitiveLike
}

func isTypeBrandedLiteralLike(t *checker.Type, typeChecker *checker.Checker) bool {
	if t == nil {
		return false
	}
	if checker.Type_flags(t)&checker.TypeFlagsUnion != 0 {
		for _, part := range t.Types() {
			if !isTypeBrandedLiteral(part, typeChecker) {
				return false
			}
		}
		return true
	}
	return isTypeBrandedLiteral(t, typeChecker)
}

func isSymbolMethodLike(symbol *ast.Symbol) bool {
	if symbol == nil {
		return false
	}
	return symbol.Flags&(ast.SymbolFlagsMethod|ast.SymbolFlagsGetAccessor|ast.SymbolFlagsSetAccessor) != 0
}

func symbolIsPrivateIdentifier(symbol *ast.Symbol) bool {
	if symbol == nil {
		return false
	}
	for _, declaration := range symbol.Declarations {
		if declaration == nil || declaration.Name() == nil {
			continue
		}
		if declaration.Name().Kind == ast.KindPrivateIdentifier {
			return true
		}
	}
	return false
}

func symbolIsReadonly(symbol *ast.Symbol) bool {
	if symbol == nil {
		return false
	}
	if symbol.CheckFlags&ast.CheckFlagsReadonly != 0 {
		return true
	}
	for _, declaration := range symbol.Declarations {
		if declaration == nil {
			continue
		}
		if ast.GetCombinedModifierFlags(declaration)&ast.ModifierFlagsReadonly != 0 {
			return true
		}
	}
	return false
}

func getPropertyType(typeChecker *checker.Checker, property *ast.Symbol) *checker.Type {
	if typeChecker == nil || property == nil {
		return nil
	}
	for _, declaration := range property.Declarations {
		if declaration == nil {
			continue
		}
		if declaration.Type() != nil &&
			declaration.Kind != ast.KindMethodSignature &&
			declaration.Kind != ast.KindMethodDeclaration &&
			declaration.Kind != ast.KindFunctionDeclaration &&
			declaration.Kind != ast.KindFunctionExpression &&
			declaration.Kind != ast.KindArrowFunction {
			if fromTypeNode := checker.Checker_getTypeFromTypeNode(typeChecker, declaration.Type()); fromTypeNode != nil {
				return fromTypeNode
			}
		}
	}
	if declared := checker.Checker_getDeclaredTypeOfSymbol(typeChecker, property); declared != nil {
		return declared
	}
	if property.ValueDeclaration != nil {
		return typeChecker.GetTypeOfSymbolAtLocation(property, property.ValueDeclaration)
	}
	for _, declaration := range property.Declarations {
		if declaration == nil {
			continue
		}
		return typeChecker.GetTypeOfSymbolAtLocation(property, declaration)
	}
	return nil
}

func isTypeReadonlyArrayOrTuple(
	ctx rule.RuleContext,
	t *checker.Type,
	opts PreferReadonlyParameterTypesOptions,
	seenTypes map[*checker.Type]bool,
) readonlyness {
	if t == nil || ctx.TypeChecker == nil {
		return readonlynessUnknown
	}
	typeText := strings.TrimSpace(ctx.TypeChecker.TypeToString(t))

	checkTypeArguments := func(arrayLikeType *checker.Type) readonlyness {
		typeArguments := checker.Checker_getTypeArguments(ctx.TypeChecker, arrayLikeType)
		if len(typeArguments) == 0 {
			return readonlynessReadonly
		}
		for _, typeArgument := range typeArguments {
			argResult := isTypeReadonlyRecurser(ctx, typeArgument, opts, seenTypes)
			if argResult == readonlynessMutable {
				return readonlynessMutable
			}
		}
		return readonlynessReadonly
	}

	if strings.HasPrefix(typeText, "readonly [") {
		return checkTypeArguments(t)
	}
	if strings.HasPrefix(typeText, "[") {
		return readonlynessMutable
	}

	if checker.Type_objectFlags(t)&checker.ObjectFlagsTuple != 0 {
		if !strings.HasPrefix(typeText, "readonly [") {
			return readonlynessMutable
		}
		return checkTypeArguments(t)
	}

	if checker.Checker_isArrayType(ctx.TypeChecker, t) {
		typeText := strings.TrimSpace(ctx.TypeChecker.TypeToString(t))
		if strings.HasPrefix(typeText, "readonly ") {
			return checkTypeArguments(t)
		}
		symbol := checker.Type_symbol(t)
		if symbol != nil && symbol.Name == "Array" {
			return readonlynessMutable
		}
		return checkTypeArguments(t)
	}

	if utils.IsBuiltinSymbolLike(ctx.Program, ctx.TypeChecker, t, "ReadonlyArray") {
		return checkTypeArguments(t)
	}

	return readonlynessUnknown
}

func isTypeReadonlyObject(
	ctx rule.RuleContext,
	t *checker.Type,
	opts PreferReadonlyParameterTypesOptions,
	seenTypes map[*checker.Type]bool,
) readonlyness {
	return isTypeReadonlyObjectWithMode(ctx, t, opts, seenTypes, false)
}

func isTypeReadonlyObjectWithMode(
	ctx rule.RuleContext,
	t *checker.Type,
	opts PreferReadonlyParameterTypesOptions,
	seenTypes map[*checker.Type]bool,
	assumePropertiesReadonly bool,
) readonlyness {
	if ctx.TypeChecker == nil || t == nil {
		return readonlynessUnknown
	}

	properties := checker.Checker_getPropertiesOfType(ctx.TypeChecker, t)
	if len(properties) > 0 {
		for _, property := range properties {
			if property == nil {
				continue
			}
			if !assumePropertiesReadonly {
				if opts.TreatMethodsAsReadonly && isSymbolMethodLike(property) {
					continue
				}
				if symbolIsReadonly(property) {
					continue
				}
				if symbolIsPrivateIdentifier(property) {
					continue
				}
				return readonlynessMutable
			}
		}

		for _, property := range properties {
			if property == nil {
				continue
			}
			if assumePropertiesReadonly && strings.Contains(property.Name, "@unscopables") {
				continue
			}
			propertyType := getPropertyType(ctx.TypeChecker, property)
			if propertyType == nil {
				continue
			}
			if propertyType == t {
				if assumePropertiesReadonly {
					return readonlynessMutable
				}
				continue
			}
			if seenTypes[propertyType] {
				if utils.IsTypeFlagSet(propertyType, checker.TypeFlagsObject) && hasShallowMutableMembers(ctx, propertyType, opts) {
					return readonlynessMutable
				}
				continue
			}
			if isTypeReadonlyRecurser(ctx, propertyType, opts, seenTypes) == readonlynessMutable {
				return readonlynessMutable
			}
		}
	}

	indexInfos := checker.Checker_getIndexInfosOfType(ctx.TypeChecker, t)
	for _, indexInfo := range indexInfos {
		if indexInfo == nil {
			continue
		}
		if !assumePropertiesReadonly && !checker.IndexInfo_isReadonly(indexInfo) {
			return readonlynessMutable
		}
		valueType := checker.IndexInfo_valueType(indexInfo)
		if valueType == nil || valueType == t || seenTypes[valueType] {
			continue
		}
		if isTypeReadonlyRecurser(ctx, valueType, opts, seenTypes) == readonlynessMutable {
			return readonlynessMutable
		}
	}

	return readonlynessReadonly
}

func readonlyWrapperTypeArgument(ctx rule.RuleContext, t *checker.Type) (*checker.Type, bool) {
	if t == nil || ctx.TypeChecker == nil {
		return nil, false
	}
	if alias := checker.Type_alias(t); alias != nil && alias.Symbol() != nil && alias.Symbol().Name == "Readonly" && len(alias.TypeArguments()) > 0 {
		return alias.TypeArguments()[0], true
	}
	typeText := strings.TrimSpace(ctx.TypeChecker.TypeToString(t))
	if !strings.HasPrefix(typeText, "Readonly<") {
		return nil, false
	}
	typeArguments := checker.Checker_getTypeArguments(ctx.TypeChecker, t)
	if len(typeArguments) == 0 {
		return nil, false
	}
	return typeArguments[0], true
}

func isReadonlyWrappedTypeArgument(
	ctx rule.RuleContext,
	typeArgument *checker.Type,
	opts PreferReadonlyParameterTypesOptions,
	seenTypes map[*checker.Type]bool,
) readonlyness {
	if typeArgument == nil {
		return readonlynessMutable
	}
	if checker.Checker_isArrayOrTupleType(ctx.TypeChecker, typeArgument) ||
		strings.HasPrefix(strings.TrimSpace(ctx.TypeChecker.TypeToString(typeArgument)), "[") ||
		strings.HasPrefix(strings.TrimSpace(ctx.TypeChecker.TypeToString(typeArgument)), "readonly [") {
		typeArguments := checker.Checker_getTypeArguments(ctx.TypeChecker, typeArgument)
		for _, innerTypeArgument := range typeArguments {
			if isTypeReadonlyRecurser(ctx, innerTypeArgument, opts, seenTypes) == readonlynessMutable {
				return readonlynessMutable
			}
		}
		return readonlynessReadonly
	}
	if utils.IsTypeFlagSet(typeArgument, checker.TypeFlagsObject) {
		if seenTypes[typeArgument] {
			return readonlynessMutable
		}
		seenTypes[typeArgument] = true
		return isTypeReadonlyObjectWithMode(ctx, typeArgument, opts, seenTypes, true)
	}
	return isTypeReadonlyRecurser(ctx, typeArgument, opts, seenTypes)
}

func isTypeReadonlyRecurser(
	ctx rule.RuleContext,
	t *checker.Type,
	opts PreferReadonlyParameterTypesOptions,
	seenTypes map[*checker.Type]bool,
) readonlyness {
	if t == nil {
		return readonlynessMutable
	}
	if seenTypes[t] {
		if utils.IsTypeFlagSet(t, checker.TypeFlagsObject) && hasShallowMutableMembers(ctx, t, opts) {
			return readonlynessMutable
		}
		return readonlynessReadonly
	}
	seenTypes[t] = true

	if utils.TypeMatchesSomeSpecifier(t, opts.Allow, opts.AllowInline, ctx.Program) {
		return readonlynessReadonly
	}
	if utils.IsTypeFlagSet(t, checker.TypeFlagsAny|checker.TypeFlagsUnknown|checker.TypeFlagsStringLike|checker.TypeFlagsNumberLike|checker.TypeFlagsBooleanLike|checker.TypeFlagsBigIntLike|checker.TypeFlagsNull|checker.TypeFlagsUndefined|checker.TypeFlagsNever|checker.TypeFlagsESSymbolLike|checker.TypeFlagsVoidLike) {
		return readonlynessReadonly
	}
	if typeArgument, ok := readonlyWrapperTypeArgument(ctx, t); ok {
		return isReadonlyWrappedTypeArgument(ctx, typeArgument, opts, seenTypes)
	}
	if utils.IsReadonlyTypeLike(ctx.Program, ctx.TypeChecker, t, func(subType *checker.Type) bool {
		alias := checker.Type_alias(subType)
		if alias == nil || len(alias.TypeArguments()) == 0 {
			return false
		}
		typeArgument := alias.TypeArguments()[0]
		return isTypeReadonlyRecurser(ctx, typeArgument, opts, seenTypes) == readonlynessReadonly
	}) {
		return readonlynessReadonly
	}

	if checker.Type_flags(t)&checker.TypeFlagsUnion != 0 {
		for _, memberType := range t.Types() {
			if seenTypes[memberType] {
				continue
			}
			memberResult := isTypeReadonlyRecurser(ctx, memberType, opts, seenTypes)
			if memberResult == readonlynessMutable {
				return readonlynessMutable
			}
		}
		return readonlynessReadonly
	}

	if checker.Type_flags(t)&checker.TypeFlagsIntersection != 0 {
		hasArrayOrTuple := false
		for _, part := range t.Types() {
			if checker.Checker_isArrayOrTupleType(ctx.TypeChecker, part) || checker.Type_objectFlags(part)&checker.ObjectFlagsTuple != 0 {
				hasArrayOrTuple = true
				break
			}
		}
		if hasArrayOrTuple {
			for _, part := range t.Types() {
				if !seenTypes[part] && isTypeReadonlyRecurser(ctx, part, opts, seenTypes) == readonlynessMutable {
					return readonlynessMutable
				}
			}
			return readonlynessReadonly
		}

		if objectReadonlyness := isTypeReadonlyObject(ctx, t, opts, seenTypes); objectReadonlyness != readonlynessUnknown {
			return objectReadonlyness
		}
	}

	if !utils.IsTypeFlagSet(t, checker.TypeFlagsObject) {
		return readonlynessReadonly
	}

	if len(checker.Checker_getSignaturesOfType(ctx.TypeChecker, t, checker.SignatureKindCall)) > 0 &&
		len(checker.Checker_getPropertiesOfType(ctx.TypeChecker, t)) == 0 {
		return readonlynessReadonly
	}

	if arrayReadonlyness := isTypeReadonlyArrayOrTuple(ctx, t, opts, seenTypes); arrayReadonlyness != readonlynessUnknown {
		return arrayReadonlyness
	}

	if objectReadonlyness := isTypeReadonlyObject(ctx, t, opts, seenTypes); objectReadonlyness != readonlynessUnknown {
		return objectReadonlyness
	}

	return readonlynessReadonly
}

func hasShallowMutableMembers(ctx rule.RuleContext, t *checker.Type, opts PreferReadonlyParameterTypesOptions) bool {
	if ctx.TypeChecker == nil || t == nil {
		return false
	}
	for _, property := range checker.Checker_getPropertiesOfType(ctx.TypeChecker, t) {
		if property == nil {
			continue
		}
		if opts.TreatMethodsAsReadonly && isSymbolMethodLike(property) {
			continue
		}
		if symbolIsReadonly(property) || symbolIsPrivateIdentifier(property) {
			continue
		}
		return true
	}
	for _, indexInfo := range checker.Checker_getIndexInfosOfType(ctx.TypeChecker, t) {
		if indexInfo == nil {
			continue
		}
		if !checker.IndexInfo_isReadonly(indexInfo) {
			return true
		}
	}
	return false
}

func isTypeReadonly(ctx rule.RuleContext, t *checker.Type, opts PreferReadonlyParameterTypesOptions) bool {
	return isTypeReadonlyRecurser(ctx, t, opts, map[*checker.Type]bool{}) == readonlynessReadonly
}

func isParameterProperty(param *ast.Node) bool {
	if param == nil || param.Kind != ast.KindParameter {
		return false
	}
	if param.Parent == nil || param.Parent.Kind != ast.KindConstructor {
		return false
	}
	flags := ast.GetCombinedModifierFlags(param)
	return flags&(ast.ModifierFlagsPublic|ast.ModifierFlagsPrivate|ast.ModifierFlagsProtected|ast.ModifierFlagsReadonly) != 0
}

func checkParameter(ctx rule.RuleContext, param *ast.Node, opts PreferReadonlyParameterTypesOptions) {
	if param == nil || ctx.TypeChecker == nil {
		return
	}
	paramDecl := param.AsParameterDeclaration()
	if paramDecl == nil {
		return
	}
	if !opts.CheckParameterProperties && isParameterProperty(param) {
		return
	}
	if opts.IgnoreInferredTypes && paramDecl.Type == nil {
		return
	}
	if paramDecl.Type != nil {
		typeStart := paramDecl.Type.Pos()
		typeEnd := paramDecl.Type.End()
		if typeStart >= 0 && typeEnd <= len(ctx.SourceFile.Text()) && typeStart < typeEnd {
			typeAnnotationText := strings.TrimSpace(ctx.SourceFile.Text()[typeStart:typeEnd])
			if strings.HasPrefix(typeAnnotationText, "readonly [") {
				return
			}
		}
	}

	paramType := ctx.TypeChecker.GetTypeAtLocation(param)
	if paramType == nil {
		return
	}

	if !isTypeReadonly(ctx, paramType, opts) && !isTypeBrandedLiteralLike(paramType, ctx.TypeChecker) {
		ctx.ReportRange(parameterReportRange(ctx.SourceFile, param, paramDecl), buildShouldBeReadonlyMessage())
	}
}

func parameterReportRange(sourceFile *ast.SourceFile, param *ast.Node, decl *ast.ParameterDeclaration) core.TextRange {
	if sourceFile == nil || param == nil || decl == nil {
		return core.NewTextRange(0, 0)
	}
	start := utils.TrimNodeTextRange(sourceFile, param).Pos()
	if decl.DotDotDotToken != nil {
		start = decl.DotDotDotToken.Pos()
	} else if decl.Name() != nil {
		start = scanner.GetTokenPosOfNode(decl.Name(), sourceFile, false)
	}
	end := param.End()
	if end < start {
		end = start
	}
	return core.NewTextRange(start, end)
}

func checkNodeParameters(ctx rule.RuleContext, node *ast.Node, opts PreferReadonlyParameterTypesOptions) {
	if node == nil {
		return
	}
	for _, param := range node.Parameters() {
		checkParameter(ctx, param, opts)
	}
}

func isTypeLikeFunctionNode(node *ast.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case ast.KindFunctionType,
		ast.KindCallSignature,
		ast.KindConstructSignature,
		ast.KindMethodSignature:
		return true
	default:
		return false
	}
}

func checkTypeLikeFunctionNodes(ctx rule.RuleContext, opts PreferReadonlyParameterTypesOptions, node *ast.Node) {
	if node == nil {
		return
	}
	if isTypeLikeFunctionNode(node) {
		checkNodeParameters(ctx, node, opts)
	}
	node.ForEachChild(func(child *ast.Node) bool {
		checkTypeLikeFunctionNodes(ctx, opts, child)
		return false
	})
}

var PreferReadonlyParameterTypesRule = rule.CreateRule(rule.Rule{
	Name: "prefer-readonly-parameter-types",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		if ctx.TypeChecker == nil {
			return rule.RuleListeners{}
		}
		opts := parseOptions(options)
		checkRuntimeFunctionNode := func(node *ast.Node) {
			checkNodeParameters(ctx, node, opts)
		}
		return rule.RuleListeners{
			ast.KindFunctionDeclaration: checkRuntimeFunctionNode,
			ast.KindFunctionExpression:  checkRuntimeFunctionNode,
			ast.KindArrowFunction:       checkRuntimeFunctionNode,
			ast.KindMethodDeclaration:   checkRuntimeFunctionNode,
			ast.KindConstructor:         checkRuntimeFunctionNode,
			ast.KindFunctionType:        checkRuntimeFunctionNode,
			ast.KindCallSignature:       checkRuntimeFunctionNode,
			ast.KindConstructSignature:  checkRuntimeFunctionNode,
			ast.KindMethodSignature:     checkRuntimeFunctionNode,
		}
	},
})
