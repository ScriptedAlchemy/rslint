package consistent_indexed_object_style

import (
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

type ConsistentIndexedObjectStyleOptions struct {
	Style string `json:"style"`
}

func buildPreferRecordMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferRecord",
		Description: "A record is preferred over an index signature.",
	}
}

func buildPreferIndexSignatureMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "preferIndexSignature",
		Description: "An index signature is preferred over a record.",
	}
}

func nodeText(sourceFile *ast.SourceFile, node *ast.Node) string {
	if sourceFile == nil || node == nil {
		return ""
	}
	textRange := utils.TrimNodeTextRange(sourceFile, node)
	return sourceFile.Text()[textRange.Pos():textRange.End()]
}

func hasInterfaceExtends(interfaceDecl *ast.InterfaceDeclaration) bool {
	if interfaceDecl == nil || interfaceDecl.HeritageClauses == nil {
		return false
	}
	for _, clauseNode := range interfaceDecl.HeritageClauses.Nodes {
		clause := clauseNode.AsHeritageClause()
		if clause == nil || clause.Token != ast.KindExtendsKeyword || clause.Types == nil {
			continue
		}
		if len(clause.Types.Nodes) > 0 {
			return true
		}
	}
	return false
}

func typeParametersText(sourceFile *ast.SourceFile, typeParameters *ast.NodeList) string {
	if sourceFile == nil || typeParameters == nil || len(typeParameters.Nodes) == 0 {
		return ""
	}
	text := "<"
	for i, param := range typeParameters.Nodes {
		if param == nil {
			continue
		}
		if i > 0 {
			text += ", "
		}
		text += nodeText(sourceFile, param)
	}
	text += ">"
	return text
}

func indexSignatureRecordText(sourceFile *ast.SourceFile, member *ast.Node) (string, bool) {
	if sourceFile == nil || member == nil || member.Kind != ast.KindIndexSignature {
		return "", false
	}
	indexSig := member.AsIndexSignatureDeclaration()
	if indexSig == nil || indexSig.Parameters == nil || len(indexSig.Parameters.Nodes) != 1 {
		return "", false
	}
	parameter := indexSig.Parameters.Nodes[0]
	if parameter == nil || parameter.Kind != ast.KindParameter {
		return "", false
	}
	paramDecl := parameter.AsParameterDeclaration()
	if paramDecl == nil || paramDecl.Name() == nil || paramDecl.Name().Kind != ast.KindIdentifier || paramDecl.Type == nil {
		return "", false
	}
	if indexSig.Type == nil {
		return "", false
	}
	keyText := nodeText(sourceFile, paramDecl.Type)
	valueText := nodeText(sourceFile, indexSig.Type)
	recordText := "Record<" + keyText + ", " + valueText + ">"
	if ast.HasSyntacticModifier(member, ast.ModifierFlagsReadonly) {
		recordText = "Readonly<" + recordText + ">"
	}
	return recordText, true
}

func unwrapParenthesizedType(node *ast.Node) *ast.Node {
	for node != nil && node.Kind == ast.KindParenthesizedType {
		parenthesized := node.AsParenthesizedTypeNode()
		if parenthesized == nil {
			return nil
		}
		node = parenthesized.Type
	}
	return node
}

func mappedTypeRecordText(sourceFile *ast.SourceFile, mappedType *ast.MappedTypeNode) (string, bool, bool) {
	if sourceFile == nil || mappedType == nil || mappedType.TypeParameter == nil || mappedType.TypeParameter.Kind != ast.KindTypeParameter {
		return "", false, false
	}
	typeParam := mappedType.TypeParameter.AsTypeParameter()
	if typeParam == nil || typeParam.Constraint == nil {
		return "", false, false
	}
	keyConstraint := unwrapParenthesizedType(typeParam.Constraint)
	if keyConstraint == nil {
		keyConstraint = typeParam.Constraint
	}
	keyText := nodeText(sourceFile, keyConstraint)
	valueText := "any"
	if mappedType.Type != nil {
		valueText = nodeText(sourceFile, mappedType.Type)
	}

	recordText := "Record<" + keyText + ", " + valueText + ">"
	canFix := true

	if mappedType.QuestionToken != nil {
		if mappedType.QuestionToken.Kind == ast.KindMinusToken {
			recordText = "Required<" + recordText + ">"
		} else {
			recordText = "Partial<" + recordText + ">"
		}
	}

	if mappedType.ReadonlyToken != nil {
		if mappedType.ReadonlyToken.Kind == ast.KindMinusToken {
			canFix = false
		} else {
			recordText = "Readonly<" + recordText + ">"
		}
	}

	return recordText, canFix, true
}

// ConsistentIndexedObjectStyleRule enforces consistent usage of type imports
var ConsistentIndexedObjectStyleRule = rule.CreateRule(rule.Rule{
	Name: "consistent-indexed-object-style",
	Run:  run,
})

func run(ctx rule.RuleContext, options any) rule.RuleListeners {
	opts := ConsistentIndexedObjectStyleOptions{
		Style: "record", // default
	}

	// Parse options
	if options != nil {
		// Handle array format: ["index-signature"]
		if optArray, isArray := options.([]interface{}); isArray && len(optArray) > 0 {
			if style, ok := optArray[0].(string); ok {
				opts.Style = style
			}
		} else if optsMap, ok := options.(map[string]interface{}); ok {
			if style, exists := optsMap["style"].(string); exists {
				opts.Style = style
			}
		} else if style, ok := options.(string); ok {
			opts.Style = style
		}
	}
	if opts.Style != "record" && opts.Style != "index-signature" {
		opts.Style = "record"
	}

	typeDeclarations := map[string]*ast.Node{}
	sourceFile := ctx.SourceFile.AsSourceFile()
	if sourceFile != nil && sourceFile.Statements != nil {
		for _, stmt := range sourceFile.Statements.Nodes {
			if stmt == nil {
				continue
			}
			switch stmt.Kind {
			case ast.KindInterfaceDeclaration:
				interfaceDecl := stmt.AsInterfaceDeclaration()
				if interfaceDecl != nil && interfaceDecl.Name() != nil && interfaceDecl.Name().Kind == ast.KindIdentifier {
					name := interfaceDecl.Name().AsIdentifier()
					if name != nil {
						typeDeclarations[name.Text] = stmt
					}
				}
			case ast.KindTypeAliasDeclaration:
				typeAliasDecl := stmt.AsTypeAliasDeclaration()
				if typeAliasDecl != nil && typeAliasDecl.Name() != nil && typeAliasDecl.Name().Kind == ast.KindIdentifier {
					name := typeAliasDecl.Name().AsIdentifier()
					if name != nil {
						typeDeclarations[name.Text] = stmt
					}
				}
			}
		}
	}

	return rule.RuleListeners{
		// Check interfaces with index signatures
		ast.KindInterfaceDeclaration: func(node *ast.Node) {
			if opts.Style != "record" {
				return
			}

			if node.Kind != ast.KindInterfaceDeclaration {
				return
			}

			interfaceDecl := node.AsInterfaceDeclaration()
			if interfaceDecl == nil {
				return
			}

			// Check if interface has exactly one member and it's an index signature
			if interfaceDecl.Members == nil || len(interfaceDecl.Members.Nodes) != 1 {
				return
			}

			member := interfaceDecl.Members.Nodes[0]
			if member.Kind != ast.KindIndexSignature {
				return
			}

			indexSig := member.AsIndexSignatureDeclaration()
			if indexSig == nil || indexSig.Type == nil || indexSig.Parameters == nil || len(indexSig.Parameters.Nodes) != 1 {
				return
			}
			parameter := indexSig.Parameters.Nodes[0]
			if parameter == nil || parameter.Kind != ast.KindParameter {
				return
			}
			paramDecl := parameter.AsParameterDeclaration()
			if paramDecl == nil || paramDecl.Name() == nil || paramDecl.Name().Kind != ast.KindIdentifier || paramDecl.Type == nil {
				return
			}

			// Check for circular references
			if isDeeplyReferencingType(interfaceDecl.Name(), indexSig.Type, typeDeclarations, map[*ast.Node]bool{}) {
				return
			}

			message := buildPreferRecordMessage()
			recordText, canBuildRecord := indexSignatureRecordText(ctx.SourceFile, member)
			safeFix := canBuildRecord &&
				!hasInterfaceExtends(interfaceDecl) &&
				!ast.HasSyntacticModifier(node, ast.ModifierFlagsDefault)
			if safeFix && interfaceDecl.Name() != nil {
				replacement := "type " + interfaceDecl.Name().Text() + typeParametersText(ctx.SourceFile, interfaceDecl.TypeParameters) + " = " + recordText + ";"
				ctx.ReportNodeWithFixes(node, message, rule.RuleFixReplace(ctx.SourceFile, node, replacement))
			} else {
				ctx.ReportNode(node, message)
			}
		},

		// Check type literals with index signatures
		ast.KindTypeLiteral: func(node *ast.Node) {
			if opts.Style != "record" {
				return
			}

			if node.Kind != ast.KindTypeLiteral {
				return
			}

			typeLiteral := node.AsTypeLiteralNode()
			if typeLiteral == nil {
				return
			}

			// Check if type literal has exactly one member and it's an index signature
			if typeLiteral.Members == nil || len(typeLiteral.Members.Nodes) != 1 {
				return
			}

			member := typeLiteral.Members.Nodes[0]
			if member.Kind != ast.KindIndexSignature {
				return
			}

			indexSig := member.AsIndexSignatureDeclaration()
			if indexSig == nil || indexSig.Type == nil || indexSig.Parameters == nil || len(indexSig.Parameters.Nodes) != 1 {
				return
			}
			parameter := indexSig.Parameters.Nodes[0]
			if parameter == nil || parameter.Kind != ast.KindParameter {
				return
			}
			paramDecl := parameter.AsParameterDeclaration()
			if paramDecl == nil || paramDecl.Name() == nil || paramDecl.Name().Kind != ast.KindIdentifier || paramDecl.Type == nil {
				return
			}

			// Check for circular references - need to find the type alias name
			if isCircularTypeReference(node, indexSig.Type, typeDeclarations) {
				return
			}

			message := buildPreferRecordMessage()
			recordText, canFix := indexSignatureRecordText(ctx.SourceFile, member)
			if canFix {
				ctx.ReportNodeWithFixes(node, message, rule.RuleFixReplace(ctx.SourceFile, node, recordText))
			} else {
				ctx.ReportNode(node, message)
			}
		},

		// Check mapped types
		ast.KindMappedType: func(node *ast.Node) {
			if opts.Style != "record" {
				return
			}

			if node.Kind != ast.KindMappedType {
				return
			}

			mappedType := node.AsMappedTypeNode()
			if mappedType == nil {
				return
			}
			if mappedType.TypeParameter == nil || mappedType.TypeParameter.Kind != ast.KindTypeParameter {
				return
			}
			typeParam := mappedType.TypeParameter.AsTypeParameter()
			if typeParam == nil || typeParam.Constraint == nil {
				return
			}
			if typeParam.Constraint.Kind == ast.KindTypeOperator {
				typeOperator := typeParam.Constraint.AsTypeOperatorNode()
				if typeOperator != nil && typeOperator.Operator == ast.KindKeyOfKeyword {
					// `[k in keyof T]` mapped types are not generally equivalent to `Record`.
					return
				}
			}

			// Check if mapped type can be converted to Record
			if !canConvertMappedTypeToRecord(mappedType) {
				return
			}
			// Skip circular references for mapped types in aliases,
			// e.g. type Foo = { [key in string]: Foo };
			if isCircularTypeReference(node, mappedType.Type, typeDeclarations) {
				return
			}

			message := buildPreferRecordMessage()
			recordText, canFix, ok := mappedTypeRecordText(ctx.SourceFile, mappedType)
			if ok && canFix {
				ctx.ReportNodeWithFixes(node, message, rule.RuleFixReplace(ctx.SourceFile, node, recordText))
			} else {
				ctx.ReportNode(node, message)
			}
		},

		// Check Record types when in index-signature mode
		ast.KindTypeReference: func(node *ast.Node) {
			if opts.Style != "index-signature" {
				return
			}

			if node.Kind != ast.KindTypeReference {
				return
			}

			typeRef := node.AsTypeReference()
			if typeRef == nil {
				return
			}

			// Check if this is a Record type reference
			if !isRecordType(typeRef) {
				return
			}

			message := buildPreferIndexSignatureMessage()
			keyType := typeRef.TypeArguments.Nodes[0]
			valueType := typeRef.TypeArguments.Nodes[1]
			if keyType == nil || valueType == nil {
				return
			}
			switch keyType.Kind {
			case ast.KindStringKeyword, ast.KindNumberKeyword, ast.KindSymbolKeyword:
				replacement := "{ [key: " + nodeText(ctx.SourceFile, keyType) + "]: " + nodeText(ctx.SourceFile, valueType) + " }"
				ctx.ReportNodeWithFixes(node, message, rule.RuleFixReplace(ctx.SourceFile, node, replacement))
			default:
				ctx.ReportNode(node, message)
			}
		},
	}
}

// isRecordType checks if a type reference is a Record type
func isRecordType(typeRef *ast.TypeReferenceNode) bool {
	if typeRef.TypeName == nil {
		return false
	}

	if typeRef.TypeName.Kind != ast.KindIdentifier {
		return false
	}

	ident := typeRef.TypeName.AsIdentifier()
	if ident == nil {
		return false
	}

	// Check if it's "Record"
	if ident.Text != "Record" {
		return false
	}

	// Must have type arguments
	if typeRef.TypeArguments == nil || len(typeRef.TypeArguments.Nodes) != 2 {
		return false
	}

	return true
}

// canConvertMappedTypeToRecord checks if a mapped type can be converted to Record
func canConvertMappedTypeToRecord(mappedType *ast.MappedTypeNode) bool {
	// Check if the type parameter constraint is string, number, or symbol
	if mappedType.TypeParameter == nil {
		return false
	}

	// TypeParameter is already a *Node, check if it's a valid type parameter
	if mappedType.TypeParameter.Kind != ast.KindTypeParameter {
		return false
	}

	typeParam := mappedType.TypeParameter.AsTypeParameter()
	if typeParam == nil {
		return false
	}

	// Constraint is required for conversion.
	if typeParam.Constraint == nil {
		return false
	}

	// Check if the mapped type references the type parameter in a way that prevents conversion
	if mappedType.Type != nil && isDeeplyReferencingTypeParam(typeParam.Name(), mappedType.Type) {
		return false
	}

	return true
}

// isDeeplyReferencingType checks if a type deeply references another type (circular reference)
func isDeeplyReferencingType(
	name *ast.Node,
	typeNode *ast.Node,
	declarations map[string]*ast.Node,
	visited map[*ast.Node]bool,
) bool {
	if name == nil || typeNode == nil {
		return false
	}

	nameIdent := name.AsIdentifier()
	if nameIdent == nil {
		return false
	}

	return checkTypeReference(nameIdent.Text, typeNode, declarations, visited)
}

// isDeeplyReferencingTypeParam checks if a type references a type parameter
func isDeeplyReferencingTypeParam(name *ast.Node, typeNode *ast.Node) bool {
	if name == nil || typeNode == nil {
		return false
	}

	nameIdent := name.AsIdentifier()
	if nameIdent == nil {
		return false
	}

	return checkTypeReferenceAny(nameIdent.Text, typeNode, map[*ast.Node]bool{})
}

// checkTypeReference recursively checks if a type references a given identifier
func checkTypeReference(
	targetName string,
	typeNode *ast.Node,
	declarations map[string]*ast.Node,
	visited map[*ast.Node]bool,
) bool {
	if typeNode == nil {
		return false
	}
	if visited[typeNode] {
		return false
	}
	visited[typeNode] = true

	switch typeNode.Kind {
	case ast.KindIdentifier:
		ident := typeNode.AsIdentifier()
		if ident == nil {
			return false
		}
		if ident.Text == targetName {
			return true
		}
		if decl, ok := declarations[ident.Text]; ok && decl != nil {
			return checkTypeReference(targetName, decl, declarations, visited)
		}
		return false

	case ast.KindQualifiedName:
		qualified := typeNode.AsQualifiedName()
		if qualified == nil || qualified.Left == nil {
			return false
		}
		// Skip checking the right identifier to avoid treating namespace members
		// (e.g. A.Foo) as direct references to local declarations.
		return checkTypeReference(targetName, qualified.Left, declarations, visited)

	case ast.KindTypeAliasDeclaration:
		typeAlias := typeNode.AsTypeAliasDeclaration()
		if typeAlias != nil && typeAlias.Type != nil {
			return checkTypeReference(targetName, typeAlias.Type, declarations, visited)
		}
		return false

	case ast.KindInterfaceDeclaration:
		interfaceDecl := typeNode.AsInterfaceDeclaration()
		if interfaceDecl != nil && interfaceDecl.Members != nil {
			for _, member := range interfaceDecl.Members.Nodes {
				if checkTypeReference(targetName, member, declarations, visited) {
					return true
				}
			}
		}
		return false

	case ast.KindTypeLiteral:
		typeLiteral := typeNode.AsTypeLiteralNode()
		if typeLiteral == nil || typeLiteral.Members == nil {
			return false
		}

		// Treat non-index-signature object literals as a boundary.
		hasIndexSignature := false
		for _, member := range typeLiteral.Members.Nodes {
			if member != nil && member.Kind == ast.KindIndexSignature {
				hasIndexSignature = true
				break
			}
		}
		if !hasIndexSignature {
			return false
		}

		for _, member := range typeLiteral.Members.Nodes {
			if checkMemberReference(targetName, member, declarations, visited) {
				return true
			}
		}
		return false

	case ast.KindIndexSignature:
		indexSig := typeNode.AsIndexSignatureDeclaration()
		if indexSig != nil && indexSig.Type != nil {
			return checkTypeReference(targetName, indexSig.Type, declarations, visited)
		}
		return false

	case ast.KindTypeReference:
		typeRef := typeNode.AsTypeReferenceNode()
		if typeRef == nil {
			return false
		}
		if typeRef.TypeName != nil && typeRef.TypeName.Kind == ast.KindIdentifier {
			typeName := typeRef.TypeName.AsIdentifier()
			if typeName != nil && (typeName.Text == "Array" || typeName.Text == "ReadonlyArray") {
				// Array wrappers shouldn't block conversion to Record.
				return false
			}
		}
		if typeRef.TypeName != nil && checkTypeReference(targetName, typeRef.TypeName, declarations, visited) {
			return true
		}
		if typeRef.TypeArguments != nil {
			for _, arg := range typeRef.TypeArguments.Nodes {
				if checkTypeReference(targetName, arg, declarations, visited) {
					return true
				}
			}
		}
		return false

	case ast.KindIndexedAccessType:
		indexedAccessType := typeNode.AsIndexedAccessTypeNode()
		if indexedAccessType == nil {
			return false
		}
		if indexedAccessType.ObjectType != nil && checkTypeReference(targetName, indexedAccessType.ObjectType, declarations, visited) {
			return true
		}
		if indexedAccessType.IndexType != nil && checkTypeReference(targetName, indexedAccessType.IndexType, declarations, visited) {
			return true
		}
		return false

	case ast.KindMappedType:
		mappedType := typeNode.AsMappedTypeNode()
		if mappedType == nil {
			return false
		}
		if mappedType.Type != nil && checkTypeReference(targetName, mappedType.Type, declarations, visited) {
			return true
		}
		return false

	case ast.KindConditionalType:
		conditionalType := typeNode.AsConditionalTypeNode()
		if conditionalType == nil {
			return false
		}
		if conditionalType.CheckType != nil && checkTypeReference(targetName, conditionalType.CheckType, declarations, visited) {
			return true
		}
		if conditionalType.ExtendsType != nil && checkTypeReference(targetName, conditionalType.ExtendsType, declarations, visited) {
			return true
		}
		if conditionalType.FalseType != nil && checkTypeReference(targetName, conditionalType.FalseType, declarations, visited) {
			return true
		}
		if conditionalType.TrueType != nil && checkTypeReference(targetName, conditionalType.TrueType, declarations, visited) {
			return true
		}
		return false

	case ast.KindUnionType:
		unionType := typeNode.AsUnionTypeNode()
		if unionType == nil || unionType.Types == nil {
			return false
		}
		for _, t := range unionType.Types.Nodes {
			if checkTypeReference(targetName, t, declarations, visited) {
				return true
			}
		}
		return false

	case ast.KindIntersectionType:
		intersectionType := typeNode.AsIntersectionTypeNode()
		if intersectionType == nil || intersectionType.Types == nil {
			return false
		}
		for _, t := range intersectionType.Types.Nodes {
			if checkTypeReference(targetName, t, declarations, visited) {
				return true
			}
		}
		return false

	case ast.KindArrayType:
		// Array wrappers (e.g. Foo[]) are not circular boundaries per upstream.
		// Record<string, Foo[]> is valid and reportable; do not recurse into element type.
		return false

	case ast.KindParenthesizedType:
		parenthesizedType := typeNode.AsParenthesizedTypeNode()
		if parenthesizedType != nil && parenthesizedType.Type != nil {
			return checkTypeReference(targetName, parenthesizedType.Type, declarations, visited)
		}
		return false
	}

	return false
}

func checkTypeReferenceAny(targetName string, typeNode *ast.Node, visited map[*ast.Node]bool) bool {
	if typeNode == nil {
		return false
	}
	if visited[typeNode] {
		return false
	}
	visited[typeNode] = true

	if typeNode.Kind == ast.KindIdentifier {
		ident := typeNode.AsIdentifier()
		if ident != nil && ident.Text == targetName {
			return true
		}
	}

	found := false
	typeNode.ForEachChild(func(child *ast.Node) bool {
		if checkTypeReferenceAny(targetName, child, visited) {
			found = true
			return true
		}
		return false
	})
	return found
}

// checkMemberReference checks if a type member references a given identifier
func checkMemberReference(
	targetName string,
	member *ast.Node,
	declarations map[string]*ast.Node,
	visited map[*ast.Node]bool,
) bool {
	if member == nil {
		return false
	}

	switch member.Kind {
	case ast.KindPropertySignature:
		propSig := member.AsPropertySignatureDeclaration()
		if propSig != nil && propSig.Type != nil {
			return checkTypeReference(targetName, propSig.Type, declarations, visited)
		}
		return false

	case ast.KindMethodSignature:
		methodSig := member.AsMethodSignatureDeclaration()
		if methodSig != nil && methodSig.Type != nil {
			return checkTypeReference(targetName, methodSig.Type, declarations, visited)
		}
		return false

	case ast.KindIndexSignature:
		indexSig := member.AsIndexSignatureDeclaration()
		if indexSig != nil && indexSig.Type != nil {
			return checkTypeReference(targetName, indexSig.Type, declarations, visited)
		}
		return false
	}

	found := false
	member.ForEachChild(func(child *ast.Node) bool {
		if checkTypeReference(targetName, child, declarations, visited) {
			found = true
			return true
		}
		return false
	})
	return found
}

// isCircularTypeReference checks if a type literal in a type alias has a circular reference
func isCircularTypeReference(typeLiteralNode *ast.Node, valueType *ast.Node, declarations map[string]*ast.Node) bool {
	if typeLiteralNode == nil || valueType == nil {
		return false
	}

	// Walk up the AST to find the type alias declaration
	parent := typeLiteralNode.Parent
	for parent != nil {
		if parent.Kind == ast.KindTypeAliasDeclaration {
			typeAlias := parent.AsTypeAliasDeclaration()
			if typeAlias != nil && typeAlias.Name() != nil {
				if !isPrimaryAliasTypeLiteral(typeAlias.Type, typeLiteralNode, typeAlias.Name()) {
					return false
				}
				// Check if the value type references the type alias name
				return isDeeplyReferencingType(typeAlias.Name(), valueType, declarations, map[*ast.Node]bool{
					typeAlias.Name(): true,
				})
			}
			break
		}
		parent = parent.Parent
	}

	return false
}

func isPrimaryAliasTypeLiteral(aliasType *ast.Node, candidate *ast.Node, aliasNameNode *ast.Node) bool {
	if aliasType == nil || candidate == nil {
		return false
	}
	for aliasType != nil && aliasType.Kind == ast.KindParenthesizedType {
		parenthesizedType := aliasType.AsParenthesizedTypeNode()
		if parenthesizedType == nil {
			break
		}
		aliasType = parenthesizedType.Type
	}
	if aliasType == candidate {
		return true
	}

	var unionOrIntersectionParts []*ast.Node
	switch aliasType.Kind {
	case ast.KindUnionType:
		unionType := aliasType.AsUnionTypeNode()
		if unionType == nil || unionType.Types == nil {
			return false
		}
		unionOrIntersectionParts = unionType.Types.Nodes
	case ast.KindIntersectionType:
		intersectionType := aliasType.AsIntersectionTypeNode()
		if intersectionType == nil || intersectionType.Types == nil {
			return false
		}
		unionOrIntersectionParts = intersectionType.Types.Nodes
	default:
		return false
	}

	aliasName := aliasNameNode.AsIdentifier()
	if aliasName == nil {
		return false
	}

	hasCandidate := false
	hasAliasInOtherBranch := false
	for _, part := range unionOrIntersectionParts {
		if part == nil {
			continue
		}
		if part == candidate {
			hasCandidate = true
			continue
		}
		if checkTypeReferenceAny(aliasName.Text, part, map[*ast.Node]bool{}) {
			hasAliasInOtherBranch = true
		}
	}
	return hasCandidate && hasAliasInOtherBranch
}
