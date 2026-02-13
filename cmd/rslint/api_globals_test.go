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
		t.Fatalf("expected globals from config, got %#v", resolved.Globals)
	}

	if resolved.Globals["RequestGlobal"] != "readonly" {
		t.Fatalf("expected globals from request, got %#v", resolved.Globals)
	}

	if resolved.ParserOptions == nil {
		t.Fatalf("expected parser options from merged config")
	}

	if !resolved.ParserOptions.IsolatedDeclarations {
		t.Fatalf("expected IsolatedDeclarations to be true from merged config")
	}
}

func TestResolveRuleLanguageOptionsForFile(t *testing.T) {
	configEntries := rslintconfig.RslintConfig{
		{
			Files: []string{"src/**/*.ts"},
			LanguageOptions: &rslintconfig.LanguageOptions{
				Globals: map[string]interface{}{
					"SrcGlobal": "readonly",
				},
				ParserOptions: &rslintconfig.ParserOptions{
					SourceType: "module",
				},
			},
		},
		{
			Files: []string{"scripts/**/*.ts"},
			LanguageOptions: &rslintconfig.LanguageOptions{
				Globals: map[string]interface{}{
					"ScriptsGlobal": "readonly",
				},
				ParserOptions: &rslintconfig.ParserOptions{
					SourceType: "script",
				},
			},
		},
	}

	reqLanguageOptions := &ipc.LanguageOptions{
		Globals: map[string]interface{}{
			"RequestGlobal": "readonly",
		},
	}

	srcOptions := resolveRuleLanguageOptionsForFile(reqLanguageOptions, configEntries, "/repo/src/main.ts", "/repo")
	if srcOptions == nil {
		t.Fatalf("expected language options for src file")
	}
	if srcOptions.Globals["SrcGlobal"] != "readonly" {
		t.Fatalf("expected SrcGlobal for src file, got %#v", srcOptions.Globals)
	}
	if _, exists := srcOptions.Globals["ScriptsGlobal"]; exists {
		t.Fatalf("did not expect ScriptsGlobal for src file, got %#v", srcOptions.Globals)
	}
	if srcOptions.ParserOptions == nil || srcOptions.ParserOptions.SourceType != "module" {
		t.Fatalf("expected module source type for src file, got %#v", srcOptions.ParserOptions)
	}

	scriptOptions := resolveRuleLanguageOptionsForFile(reqLanguageOptions, configEntries, "/repo/scripts/build.ts", "/repo")
	if scriptOptions == nil {
		t.Fatalf("expected language options for scripts file")
	}
	if scriptOptions.Globals["ScriptsGlobal"] != "readonly" {
		t.Fatalf("expected ScriptsGlobal for scripts file, got %#v", scriptOptions.Globals)
	}
	if _, exists := scriptOptions.Globals["SrcGlobal"]; exists {
		t.Fatalf("did not expect SrcGlobal for scripts file, got %#v", scriptOptions.Globals)
	}
	if scriptOptions.ParserOptions == nil || scriptOptions.ParserOptions.SourceType != "script" {
		t.Fatalf("expected script source type for scripts file, got %#v", scriptOptions.ParserOptions)
	}

	if srcOptions.Globals["RequestGlobal"] != "readonly" || scriptOptions.Globals["RequestGlobal"] != "readonly" {
		t.Fatalf("expected RequestGlobal for both files, src=%#v scripts=%#v", srcOptions.Globals, scriptOptions.Globals)
	}
}
