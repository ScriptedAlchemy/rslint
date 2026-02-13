package config

import (
	"testing"

	"github.com/web-infra-dev/rslint/internal/rule"
)

func TestGetEnabledRulesInjectsLanguageOptionsIntoRuleContext(t *testing.T) {
	registry := NewRuleRegistry()

	var gotParserOptions *rule.RuleParserOptions
	var gotGlobals map[string]bool

	registry.Register("test-rule", rule.Rule{
		Name: "test-rule",
		Run: func(ctx rule.RuleContext, options any) rule.RuleListeners {
			gotParserOptions = ctx.ParserOptions
			gotGlobals = ctx.Globals
			return rule.RuleListeners{}
		},
	})

	cfg := RslintConfig{
		{
			Language: "javascript",
			Files:    []string{},
			LanguageOptions: &LanguageOptions{
				ParserOptions: &ParserOptions{
					IsolatedDeclarations:    true,
					IsolatedDeclarationsSet: true,
					JSXPragma:               "React",
					EcmaFeatures: &EcmaFeatures{
						JSX:    true,
						JSXSet: true,
					},
				},
				Globals: map[string]interface{}{
					"React": "readonly",
				},
			},
			Rules: Rules{
				"test-rule": "error",
			},
		},
	}

	enabled := registry.GetEnabledRules(cfg, "/repo/src/example.tsx")
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled rule, got %d", len(enabled))
	}

	enabled[0].Run(rule.RuleContext{})

	if gotParserOptions == nil {
		t.Fatalf("expected parser options to be injected into context")
	}
	if !gotParserOptions.IsolatedDeclarations {
		t.Fatalf("expected isolatedDeclarations to be true")
	}
	if gotParserOptions.EcmaFeatures == nil || !gotParserOptions.EcmaFeatures.JSX {
		t.Fatalf("expected ecmaFeatures.jsx to be true")
	}
	if gotParserOptions.JSXPragma != "React" {
		t.Fatalf("expected jsxPragma to be React, got %q", gotParserOptions.JSXPragma)
	}

	if gotGlobals == nil || !gotGlobals["React"] {
		t.Fatalf("expected React global to be injected, got %#v", gotGlobals)
	}
}
