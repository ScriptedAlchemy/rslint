package main

import (
	"encoding/json"
	"reflect"
	"testing"

	ipc "github.com/web-infra-dev/rslint/internal/api"
	rslintconfig "github.com/web-infra-dev/rslint/internal/config"
)

type testFileExistsFS map[string]bool

func (fs testFileExistsFS) FileExists(path string) bool {
	return fs[path]
}

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

func TestMergeParserOptionsAllowsExplicitFalseOverrides(t *testing.T) {
	var base ipc.ParserOptions
	if err := json.Unmarshal([]byte(`{
		"projectService": true,
		"isolatedDeclarations": true,
		"experimentalDecorators": true,
		"emitDecoratorMetadata": true,
		"ecmaFeatures": { "globalReturn": true, "jsx": true }
	}`), &base); err != nil {
		t.Fatalf("failed to unmarshal base parser options: %v", err)
	}

	var override ipc.ParserOptions
	if err := json.Unmarshal([]byte(`{
		"projectService": false,
		"isolatedDeclarations": false,
		"experimentalDecorators": false,
		"emitDecoratorMetadata": false,
		"ecmaFeatures": { "globalReturn": false, "jsx": false }
	}`), &override); err != nil {
		t.Fatalf("failed to unmarshal override parser options: %v", err)
	}

	merged := rslintconfig.MergeLanguageOptions(
		&rslintconfig.LanguageOptions{
			ParserOptions: apiParserOptionsToConfig(&base),
		},
		&rslintconfig.LanguageOptions{
			ParserOptions: apiParserOptionsToConfig(&override),
		},
	)
	if merged == nil || merged.ParserOptions == nil {
		t.Fatalf("expected merged parser options")
	}

	if merged.ParserOptions.ProjectService {
		t.Fatalf("expected projectService to be false after override")
	}
	if merged.ParserOptions.IsolatedDeclarations {
		t.Fatalf("expected isolatedDeclarations to be false after override")
	}
	if merged.ParserOptions.ExperimentalDecorators {
		t.Fatalf("expected experimentalDecorators to be false after override")
	}
	if merged.ParserOptions.EmitDecoratorMetadata {
		t.Fatalf("expected emitDecoratorMetadata to be false after override")
	}
	if merged.ParserOptions.EcmaFeatures == nil {
		t.Fatalf("expected ecmaFeatures in merged parser options")
	}
	if merged.ParserOptions.EcmaFeatures.GlobalReturn {
		t.Fatalf("expected ecmaFeatures.globalReturn to be false after override")
	}
	if merged.ParserOptions.EcmaFeatures.JSX {
		t.Fatalf("expected ecmaFeatures.jsx to be false after override")
	}
}

func TestMergeParserOptionsProjectOverrideSemantics(t *testing.T) {
	var base ipc.ParserOptions
	if err := json.Unmarshal([]byte(`{
		"project": ["./tsconfig.base.json"]
	}`), &base); err != nil {
		t.Fatalf("failed to unmarshal base parser options: %v", err)
	}

	var clearOverride ipc.ParserOptions
	if err := json.Unmarshal([]byte(`{
		"project": []
	}`), &clearOverride); err != nil {
		t.Fatalf("failed to unmarshal clear override parser options: %v", err)
	}

	mergedCleared := rslintconfig.MergeLanguageOptions(
		&rslintconfig.LanguageOptions{
			ParserOptions: apiParserOptionsToConfig(&base),
		},
		&rslintconfig.LanguageOptions{
			ParserOptions: apiParserOptionsToConfig(&clearOverride),
		},
	)
	if mergedCleared == nil || mergedCleared.ParserOptions == nil {
		t.Fatalf("expected merged parser options for clear override")
	}
	if len(mergedCleared.ParserOptions.Project) != 0 {
		t.Fatalf("expected explicit empty project override to clear projects, got %#v", mergedCleared.ParserOptions.Project)
	}

	var keepOverride ipc.ParserOptions
	if err := json.Unmarshal([]byte(`{
		"sourceType": "module"
	}`), &keepOverride); err != nil {
		t.Fatalf("failed to unmarshal keep override parser options: %v", err)
	}

	mergedKept := rslintconfig.MergeLanguageOptions(
		&rslintconfig.LanguageOptions{
			ParserOptions: apiParserOptionsToConfig(&base),
		},
		&rslintconfig.LanguageOptions{
			ParserOptions: apiParserOptionsToConfig(&keepOverride),
		},
	)
	if mergedKept == nil || mergedKept.ParserOptions == nil {
		t.Fatalf("expected merged parser options for keep override")
	}
	if len(mergedKept.ParserOptions.Project) != 1 || mergedKept.ParserOptions.Project[0] != "./tsconfig.base.json" {
		t.Fatalf("expected missing project override to keep base project, got %#v", mergedKept.ParserOptions.Project)
	}
}

func TestPatternMatchesFileSupportsDotPrefixedPatterns(t *testing.T) {
	if !rslintconfig.PatternMatchesFile("./src/**/*.ts", "/repo/src/main.ts", "src/main.ts") {
		t.Fatalf("expected ./src/**/*.ts to match src/main.ts")
	}
	if rslintconfig.PatternMatchesFile("./src/**/*.ts", "/repo/scripts/main.ts", "scripts/main.ts") {
		t.Fatalf("did not expect ./src/**/*.ts to match scripts/main.ts")
	}
}

func TestResolveRuleLanguageOptionsForFileConfigDirectoryFallback(t *testing.T) {
	configEntries := rslintconfig.RslintConfig{
		{
			Files: []string{"src/**/*.ts"},
			LanguageOptions: &rslintconfig.LanguageOptions{
				Globals: map[string]interface{}{
					"SrcGlobal": "readonly",
				},
			},
		},
	}

	resolved := resolveRuleLanguageOptionsForFile(nil, configEntries, "/repo/src/main.ts", "/repo")
	if resolved == nil {
		t.Fatalf("expected language options to resolve with configDirectory fallback")
	}
	if resolved.Globals["SrcGlobal"] != "readonly" {
		t.Fatalf("expected SrcGlobal with configDirectory fallback, got %#v", resolved.Globals)
	}
}

func TestCollectTsConfigsForRequestAppliesOverrideToAllEntries(t *testing.T) {
	configEntries := rslintconfig.RslintConfig{
		{
			Files: []string{"src/**/*.ts"},
			LanguageOptions: &rslintconfig.LanguageOptions{
				ParserOptions: &rslintconfig.ParserOptions{
					Project: rslintconfig.ProjectPaths{"./src.tsconfig.json"},
				},
			},
		},
		{
			Files: []string{"scripts/**/*.ts"},
			LanguageOptions: &rslintconfig.LanguageOptions{
				ParserOptions: &rslintconfig.ParserOptions{
					Project: rslintconfig.ProjectPaths{"./scripts.tsconfig.json"},
				},
			},
		},
	}

	requestOptions := &ipc.LanguageOptions{
		ParserOptions: &ipc.ParserOptions{
			Project: ipc.ProjectPaths{"./override.tsconfig.json"},
		},
	}

	tsconfigs, hasExplicitOverride := collectTsConfigsForRequest(
		configEntries,
		requestOptions,
		"/repo",
		testFileExistsFS{
			"/repo/override.tsconfig.json": true,
			"/repo/src.tsconfig.json":      true,
			"/repo/scripts.tsconfig.json":  true,
		},
		[]string{"/repo/src/main.ts", "/repo/scripts/build.ts"},
	)
	if !hasExplicitOverride {
		t.Fatalf("expected explicit project override to be detected")
	}
	if len(tsconfigs) != 1 || tsconfigs[0] != "/repo/override.tsconfig.json" {
		t.Fatalf("expected only override tsconfig path, got %#v", tsconfigs)
	}
}

func TestCollectTsConfigsForRequestSupportsExplicitEmptyProject(t *testing.T) {
	configEntries := rslintconfig.RslintConfig{
		{
			LanguageOptions: &rslintconfig.LanguageOptions{
				ParserOptions: &rslintconfig.ParserOptions{
					Project: rslintconfig.ProjectPaths{"./tsconfig.json"},
				},
			},
		},
	}

	requestOptions := &ipc.LanguageOptions{
		ParserOptions: &ipc.ParserOptions{
			Project: ipc.ProjectPaths{},
		},
	}

	tsconfigs, hasExplicitOverride := collectTsConfigsForRequest(
		configEntries,
		requestOptions,
		"/repo",
		testFileExistsFS{
			"/repo/tsconfig.json": true,
		},
		nil,
	)
	if !hasExplicitOverride {
		t.Fatalf("expected explicit project override to be detected")
	}
	if len(tsconfigs) != 0 {
		t.Fatalf("expected explicit empty project override to clear tsconfigs, got %#v", tsconfigs)
	}
}
