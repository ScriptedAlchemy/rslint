package no_unnecessary_qualifier

import (
	"regexp"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnnecessaryQualifierMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unnecessaryQualifier",
		Description: "Qualifier is unnecessary and can be removed.",
	}
}

type namespaceScope struct {
	name string
	node *ast.Node
}

func reverseScopes(items []namespaceScope) []namespaceScope {
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return items
}

func getEnclosingNamespaceScopes(node *ast.Node) []namespaceScope {
	scopes := []namespaceScope{}
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind != ast.KindModuleDeclaration {
			continue
		}
		moduleDecl := current.AsModuleDeclaration()
		if moduleDecl == nil || moduleDecl.Name() == nil || moduleDecl.Name().Kind != ast.KindIdentifier {
			continue
		}
		scopes = append(scopes, namespaceScope{
			name: moduleDecl.Name().AsIdentifier().Text,
			node: current,
		})
	}
	return reverseScopes(scopes)
}

func getNamespaceChain(scopes []namespaceScope) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		result = append(result, scope.name)
	}
	return result
}

func isPrefix(prefix []string, values []string) bool {
	if len(prefix) == 0 || len(prefix) > len(values) {
		return false
	}
	for i := range prefix {
		if prefix[i] != values[i] {
			return false
		}
	}
	return true
}

func equalSlices(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func findNamespaceByChain(scopes []namespaceScope, chain []string) *ast.Node {
	if len(chain) == 0 {
		return nil
	}
	for i, scope := range scopes {
		if i+1 != len(chain) {
			continue
		}
		matches := true
		for j := 0; j <= i; j++ {
			if scopes[j].name != chain[j] {
				matches = false
				break
			}
		}
		if matches {
			return scope.node
		}
	}
	return nil
}

func getNamespaceBodyStatements(moduleDeclNode *ast.Node) []*ast.Node {
	if moduleDeclNode == nil || moduleDeclNode.Kind != ast.KindModuleDeclaration {
		return nil
	}
	moduleDecl := moduleDeclNode.AsModuleDeclaration()
	if moduleDecl == nil || moduleDecl.Body == nil {
		return nil
	}
	body := moduleDecl.Body
	for body != nil && body.Kind == ast.KindModuleDeclaration {
		next := body.AsModuleDeclaration()
		if next == nil || next.Body == nil {
			return nil
		}
		body = next.Body
	}
	if body == nil || body.Kind != ast.KindModuleBlock {
		return nil
	}
	return body.Statements()
}

func parseNamespaceImports(sourceText string) map[string]string {
	result := map[string]string{}
	re := regexp.MustCompile(`import\s*\*\s*as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]`)
	matches := re.FindAllStringSubmatch(sourceText, -1)
	for _, match := range matches {
		if len(match) == 3 {
			result[match[1]] = match[2]
		}
	}
	return result
}

func getCurrentModuleAugmentationPath(node *ast.Node) string {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind != ast.KindModuleDeclaration {
			continue
		}
		moduleDecl := current.AsModuleDeclaration()
		if moduleDecl == nil || moduleDecl.Name() == nil {
			continue
		}
		if moduleDecl.Name().Kind == ast.KindStringLiteral {
			return moduleDecl.Name().AsStringLiteral().Text
		}
	}
	return ""
}

func getNearestNamespaceBodyStatements(node *ast.Node) []*ast.Node {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindModuleDeclaration {
			stmts := getNamespaceBodyStatements(current)
			if len(stmts) > 0 {
				return stmts
			}
		}
		if current.Kind == ast.KindSourceFile {
			return current.Statements()
		}
	}
	return nil
}

func collectBindingNames(name *ast.Node) []*ast.Node {
	if name == nil {
		return nil
	}
	switch name.Kind {
	case ast.KindIdentifier:
		return []*ast.Node{name}
	case ast.KindObjectBindingPattern, ast.KindArrayBindingPattern:
		pattern := name.AsBindingPattern()
		if pattern == nil || pattern.Elements == nil {
			return nil
		}
		names := []*ast.Node{}
		for _, element := range pattern.Elements.Nodes {
			bindingElement := element.AsBindingElement()
			if bindingElement == nil {
				continue
			}
			names = append(names, collectBindingNames(bindingElement.Name())...)
		}
		return names
	default:
		return nil
	}
}

func collectTopLevelDeclarationNames(statement *ast.Node) []*ast.Node {
	if statement == nil {
		return nil
	}
	switch statement.Kind {
	case ast.KindTypeAliasDeclaration:
		typeAlias := statement.AsTypeAliasDeclaration()
		if typeAlias != nil && typeAlias.Name() != nil {
			return []*ast.Node{typeAlias.Name()}
		}
	case ast.KindInterfaceDeclaration:
		iface := statement.AsInterfaceDeclaration()
		if iface != nil && iface.Name() != nil {
			return []*ast.Node{iface.Name()}
		}
	case ast.KindClassDeclaration:
		classDecl := statement.AsClassDeclaration()
		if classDecl != nil && classDecl.Name() != nil {
			return []*ast.Node{classDecl.Name()}
		}
	case ast.KindEnumDeclaration:
		enumDecl := statement.AsEnumDeclaration()
		if enumDecl != nil && enumDecl.Name() != nil {
			return []*ast.Node{enumDecl.Name()}
		}
	case ast.KindFunctionDeclaration:
		functionDecl := statement.AsFunctionDeclaration()
		if functionDecl != nil && functionDecl.Name() != nil {
			return []*ast.Node{functionDecl.Name()}
		}
	case ast.KindModuleDeclaration:
		moduleDecl := statement.AsModuleDeclaration()
		if moduleDecl != nil && moduleDecl.Name() != nil && moduleDecl.Name().Kind == ast.KindIdentifier {
			return []*ast.Node{moduleDecl.Name()}
		}
	case ast.KindVariableStatement:
		varStmt := statement.AsVariableStatement()
		if varStmt == nil || varStmt.DeclarationList == nil {
			return nil
		}
		declList := varStmt.DeclarationList.AsVariableDeclarationList()
		if declList == nil || declList.Declarations == nil {
			return nil
		}
		names := []*ast.Node{}
		for _, declaration := range declList.Declarations.Nodes {
			varDecl := declaration.AsVariableDeclaration()
			if varDecl == nil || varDecl.Name() == nil {
				continue
			}
			names = append(names, collectBindingNames(varDecl.Name())...)
		}
		return names
	}
	return nil
}

func hasMatchingTopLevelDeclarationSymbol(
	ctx rule.RuleContext,
	statements []*ast.Node,
	name string,
	targetSymbol *ast.Symbol,
) bool {
	if targetSymbol == nil {
		return false
	}
	for _, statement := range statements {
		for _, declName := range collectTopLevelDeclarationNames(statement) {
			if declName == nil || declName.Kind != ast.KindIdentifier || declName.AsIdentifier().Text != name {
				continue
			}
			symbol := ctx.TypeChecker.GetSymbolAtLocation(declName)
			if symbol != nil && symbol == targetSymbol {
				return true
			}
		}
	}
	return false
}

func hasShadowingDeclarationWithDifferentSymbol(
	ctx rule.RuleContext,
	node *ast.Node,
	name string,
	targetSymbol *ast.Symbol,
) bool {
	if targetSymbol == nil {
		return false
	}
	statements := getNearestNamespaceBodyStatements(node)
	for _, statement := range statements {
		for _, declName := range collectTopLevelDeclarationNames(statement) {
			if declName == nil || declName.Kind != ast.KindIdentifier || declName.AsIdentifier().Text != name {
				continue
			}
			symbol := ctx.TypeChecker.GetSymbolAtLocation(declName)
			if symbol != nil && symbol != targetSymbol {
				return true
			}
		}
	}
	return false
}

func findNearestEnclosingEnum(node *ast.Node) *ast.Node {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == ast.KindEnumDeclaration {
			return current
		}
	}
	return nil
}

func enumHasMemberWithSymbol(
	ctx rule.RuleContext,
	enumDeclNode *ast.Node,
	memberName string,
	targetSymbol *ast.Symbol,
) bool {
	if enumDeclNode == nil || enumDeclNode.Kind != ast.KindEnumDeclaration || targetSymbol == nil {
		return false
	}
	enumDecl := enumDeclNode.AsEnumDeclaration()
	if enumDecl == nil || enumDecl.Members == nil {
		return false
	}
	for _, memberNode := range enumDecl.Members.Nodes {
		member := memberNode.AsEnumMember()
		if member == nil || member.Name() == nil || member.Name().Kind != ast.KindIdentifier {
			continue
		}
		if member.Name().AsIdentifier().Text != memberName {
			continue
		}
		symbol := ctx.TypeChecker.GetSymbolAtLocation(member.Name())
		if symbol != nil && symbol == targetSymbol {
			return true
		}
	}
	return false
}

func collectQualifiedNameSegments(node *ast.Node) ([]string, *ast.Node) {
	if node == nil {
		return nil, nil
	}
	switch node.Kind {
	case ast.KindIdentifier:
		return []string{node.AsIdentifier().Text}, node
	case ast.KindQualifiedName:
		qualifiedName := node.AsQualifiedName()
		if qualifiedName == nil || qualifiedName.Left == nil || qualifiedName.Right == nil {
			return nil, nil
		}
		left, _ := collectQualifiedNameSegments(qualifiedName.Left)
		right := qualifiedName.Right.Text()
		return append(left, right), qualifiedName.Right
	case ast.KindPropertyAccessExpression:
		property := node.AsPropertyAccessExpression()
		if property == nil || property.Expression == nil || property.Name() == nil || property.Name().Kind != ast.KindIdentifier {
			return nil, nil
		}
		left, _ := collectQualifiedNameSegments(property.Expression)
		right := property.Name().AsIdentifier().Text
		return append(left, right), property.Name()
	default:
		return nil, nil
	}
}

func isOutermostPropertyAccess(node *ast.Node) bool {
	if node == nil || node.Kind != ast.KindPropertyAccessExpression {
		return false
	}
	parent := node.Parent
	if parent == nil || parent.Kind != ast.KindPropertyAccessExpression {
		return true
	}
	parentAccess := parent.AsPropertyAccessExpression()
	return parentAccess == nil || parentAccess.Expression != node
}

func shouldReportUnnecessaryQualifier(
	ctx rule.RuleContext,
	node *ast.Node,
	segments []string,
	targetSymbol *ast.Symbol,
	namespaceImports map[string]string,
) bool {
	if len(segments) < 2 || targetSymbol == nil {
		return false
	}
	rightName := segments[len(segments)-1]
	qualifier := segments[:len(segments)-1]
	if hasShadowingDeclarationWithDifferentSymbol(ctx, node, rightName, targetSymbol) {
		return false
	}

	namespaceScopes := getEnclosingNamespaceScopes(node)
	namespaceChain := getNamespaceChain(namespaceScopes)
	if isPrefix(qualifier, namespaceChain) {
		matchedNamespace := findNamespaceByChain(namespaceScopes, qualifier)
		if matchedNamespace != nil && hasMatchingTopLevelDeclarationSymbol(ctx, getNamespaceBodyStatements(matchedNamespace), rightName, targetSymbol) {
			return true
		}
	}

	if enumNode := findNearestEnclosingEnum(node); enumNode != nil {
		enumDecl := enumNode.AsEnumDeclaration()
		if enumDecl != nil && enumDecl.Name() != nil && enumDecl.Name().Kind == ast.KindIdentifier {
			enumChain := append(append([]string{}, namespaceChain...), enumDecl.Name().AsIdentifier().Text)
			if equalSlices(qualifier, enumChain) && enumHasMemberWithSymbol(ctx, enumNode, rightName, targetSymbol) {
				return true
			}
		}
	}

	modulePath := getCurrentModuleAugmentationPath(node)
	if modulePath != "" && len(qualifier) == 1 && namespaceImports[qualifier[0]] == modulePath {
		return true
	}

	return false
}

var NoUnnecessaryQualifierRule = rule.CreateRule(rule.Rule{
	Name: "no-unnecessary-qualifier",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options
		if ctx.TypeChecker == nil {
			return rule.RuleListeners{}
		}

		namespaceImports := parseNamespaceImports(ctx.SourceFile.Text())

		return rule.RuleListeners{
			ast.KindTypeReference: func(node *ast.Node) {
				typeRef := node.AsTypeReferenceNode()
				if typeRef == nil || typeRef.TypeName == nil || typeRef.TypeName.Kind != ast.KindQualifiedName {
					return
				}
				segments, rightNode := collectQualifiedNameSegments(typeRef.TypeName)
				if len(segments) < 2 || rightNode == nil {
					return
				}
				targetSymbol := ctx.TypeChecker.GetSymbolAtLocation(rightNode)
				if !shouldReportUnnecessaryQualifier(ctx, node, segments, targetSymbol, namespaceImports) {
					return
				}
				ctx.ReportNode(node, buildUnnecessaryQualifierMessage())
			},
			ast.KindPropertyAccessExpression: func(node *ast.Node) {
				if !isOutermostPropertyAccess(node) {
					return
				}
				segments, rightNode := collectQualifiedNameSegments(node)
				if len(segments) < 2 || rightNode == nil {
					return
				}
				targetSymbol := ctx.TypeChecker.GetSymbolAtLocation(rightNode)
				if !shouldReportUnnecessaryQualifier(ctx, node, segments, targetSymbol, namespaceImports) {
					return
				}
				ctx.ReportNode(node, buildUnnecessaryQualifierMessage())
			},
		}
	},
})
