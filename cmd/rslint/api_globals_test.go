package main

import (
	"reflect"
	"testing"

	ipc "github.com/web-infra-dev/rslint/internal/api"
	rslintconfig "github.com/web-infra-dev/rslint/internal/config"
)

func TestBuildRuleGlobals(t *testing.T) {
	tests := []struct {
		name            string
		languageOptions *ipc.LanguageOptions
		expected        map[string]bool
	}{
		{
			name:            "nil language options",
			languageOptions: nil,
			expected:        nil,
		},
		{
			name: "bool and string globals",
			languageOptions: &ipc.LanguageOptions{
				Globals: map[string]interface{}{
					"readonlyBool": false,
					"writableBool": true,
					"readonlyStr":  "readonly",
					"writableStr":  "writable",
					"offStr":       "off",
					"falseStr":     "false",
				},
			},
			expected: map[string]bool{
				"readonlyBool": true,
				"writableBool": true,
				"readonlyStr":  true,
				"writableStr":  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRuleGlobals(tt.languageOptions)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("buildRuleGlobals() = %#v, expected %#v", got, tt.expected)
			}
		})
	}
}

func TestResolveRuleLanguageOptions(t *testing.T) {
	configLanguageOptions := &rslintconfig.LanguageOptions{
		Globals: map[string]interface{}{
			"ConfigGlobal": "readonly",
		},
		ParserOptions: &rslintconfig.ParserOptions{
			SourceType:           "module",
			EcmaVersion:          2022,
			IsolatedDeclarations: true,
			EcmaFeatures: &rslintconfig.EcmaFeatures{
				JSX: true,
			},
		},
	}

	configEntries := rslintconfig.RslintConfig{
		{
			LanguageOptions: configLanguageOptions,
		},
	}

	reqLanguageOptions := &ipc.LanguageOptions{
		Globals: map[string]interface{}{
			"RequestGlobal": "readonly",
		},
	}

	resolved := resolveRuleLanguageOptions(reqLanguageOptions, configEntries)
	if resolved == nil {
		t.Fatalf("resolveRuleLanguageOptions() returned nil")
	}

	if resolved.Globals["ConfigGlobal"] != "readonly" {
		t.Fatalf("expected globals from merged config, got %#v", resolved.Globals)
	}

	if resolved.ParserOptions == nil {
		t.Fatalf("expected parser options from merged config")
	}

	if !resolved.ParserOptions.IsolatedDeclarations {
		t.Fatalf("expected IsolatedDeclarations to be true from merged config")
	}
}
