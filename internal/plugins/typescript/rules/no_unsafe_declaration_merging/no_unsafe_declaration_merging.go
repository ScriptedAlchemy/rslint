package no_unsafe_declaration_merging

import (
	"slices"

	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func buildUnsafeMergingMessage() rule.RuleMessage {
	return rule.RuleMessage{
		Id:          "unsafeMerging",
		Description: "Merging class and interface declarations with the same name is unsafe.",
	}
}

type declarationBucket struct {
	classNodes     []*ast.Node
	interfaceNodes []*ast.Node
}

var NoUnsafeDeclarationMergingRule = rule.CreateRule(rule.Rule{
	Name: "no-unsafe-declaration-merging",
	Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
		_ = options

		bucketsByScope := map[*ast.Node]map[string]*declarationBucket{}
		reported := map[*ast.Node]bool{}

		getScopeBuckets := func(scope *ast.Node) map[string]*declarationBucket {
			if scope == nil {
				scope = ctx.SourceFile.AsNode()
			}
			scopeBuckets, exists := bucketsByScope[scope]
			if !exists {
				scopeBuckets = map[string]*declarationBucket{}
				bucketsByScope[scope] = scopeBuckets
			}
			return scopeBuckets
		}

		getBucket := func(scope *ast.Node, name string) *declarationBucket {
			scopeBuckets := getScopeBuckets(scope)
			bucket, exists := scopeBuckets[name]
			if !exists {
				bucket = &declarationBucket{}
				scopeBuckets[name] = bucket
			}
			return bucket
		}

		reportNode := func(n *ast.Node) {
			if n == nil || reported[n] {
				return
			}
			reported[n] = true
			ctx.ReportNode(n.Name(), buildUnsafeMergingMessage())
		}

		reportMergedBucket := func(bucket *declarationBucket) {
			nodes := make([]*ast.Node, 0, len(bucket.classNodes)+len(bucket.interfaceNodes))
			nodes = append(nodes, bucket.classNodes...)
			nodes = append(nodes, bucket.interfaceNodes...)
			slices.SortFunc(nodes, func(a, b *ast.Node) int {
				if a.Pos() < b.Pos() {
					return -1
				}
				if a.Pos() > b.Pos() {
					return 1
				}
				return 0
			})
			for _, n := range nodes {
				reportNode(n)
			}
		}

		addDeclaration := func(node *ast.Node, isClass bool) {
			if node == nil || node.Name() == nil || node.Name().Kind != ast.KindIdentifier {
				return
			}
			scope := node.Parent
			name := node.Name().AsIdentifier().Text
			bucket := getBucket(scope, name)
			if isClass {
				bucket.classNodes = append(bucket.classNodes, node)
			} else {
				bucket.interfaceNodes = append(bucket.interfaceNodes, node)
			}
			if len(bucket.classNodes) == 0 || len(bucket.interfaceNodes) == 0 {
				return
			}
			reportMergedBucket(bucket)
		}

		return rule.RuleListeners{
			ast.KindClassDeclaration: func(node *ast.Node) {
				addDeclaration(node, true)
			},
			ast.KindInterfaceDeclaration: func(node *ast.Node) {
				addDeclaration(node, false)
			},
		}
	},
})
