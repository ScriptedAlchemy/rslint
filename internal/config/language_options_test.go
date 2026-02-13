package config

import (
	"encoding/json"
	"testing"
)

func TestResolveLanguageOptionsForFileAllowsFalseOverrides(t *testing.T) {
	raw := `[
		{
			"language":"javascript",
			"files":[],
			"rules":{},
			"languageOptions":{
				"parserOptions":{
					"projectService":true,
					"isolatedDeclarations":true,
					"experimentalDecorators":true,
					"emitDecoratorMetadata":true,
					"ecmaFeatures":{
						"globalReturn":true,
						"jsx":true
					}
				}
			}
		},
		{
			"language":"javascript",
			"files":[],
			"rules":{},
			"languageOptions":{
				"parserOptions":{
					"projectService":false,
					"isolatedDeclarations":false,
					"experimentalDecorators":false,
					"emitDecoratorMetadata":false,
					"ecmaFeatures":{
						"globalReturn":false,
						"jsx":false
					}
				}
			}
		}
	]`

	var cfg RslintConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	resolved := ResolveLanguageOptionsForFile(cfg, "/repo/src/file.tsx")
	if resolved == nil || resolved.ParserOptions == nil {
		t.Fatalf("expected parser options to be resolved")
	}

	if resolved.ParserOptions.ProjectService {
		t.Fatalf("expected projectService to be false after override")
	}
	if resolved.ParserOptions.IsolatedDeclarations {
		t.Fatalf("expected isolatedDeclarations to be false after override")
	}
	if resolved.ParserOptions.ExperimentalDecorators {
		t.Fatalf("expected experimentalDecorators to be false after override")
	}
	if resolved.ParserOptions.EmitDecoratorMetadata {
		t.Fatalf("expected emitDecoratorMetadata to be false after override")
	}
	if resolved.ParserOptions.EcmaFeatures == nil {
		t.Fatalf("expected ecmaFeatures to be resolved")
	}
	if resolved.ParserOptions.EcmaFeatures.GlobalReturn {
		t.Fatalf("expected ecmaFeatures.globalReturn to be false after override")
	}
	if resolved.ParserOptions.EcmaFeatures.JSX {
		t.Fatalf("expected ecmaFeatures.jsx to be false after override")
	}
}

func TestBuildRuleGlobals(t *testing.T) {
	languageOptions := &LanguageOptions{
		Globals: map[string]interface{}{
			"ReadonlyBool": false,
			"WritableBool": true,
			"ReadonlyStr":  "readonly",
			"WritableStr":  "writable",
			"OffStr":       "off",
			"FalseStr":     "false",
		},
	}

	got := BuildRuleGlobals(languageOptions)
	if got["ReadonlyBool"] != true || got["WritableBool"] != true {
		t.Fatalf("expected bool globals to be present, got %#v", got)
	}
	if got["ReadonlyStr"] != true || got["WritableStr"] != true {
		t.Fatalf("expected string globals to be present, got %#v", got)
	}
	if got["OffStr"] || got["FalseStr"] {
		t.Fatalf("expected off/false string globals to be absent, got %#v", got)
	}
}

func TestResolveLanguageOptionsForFileRespectsFilesPatterns(t *testing.T) {
	cfg := RslintConfig{
		{
			Language:        "javascript",
			Files:           []string{"src/**/*.ts"},
			ConfigDirectory: "/repo",
			LanguageOptions: &LanguageOptions{
				Globals: map[string]interface{}{
					"SrcGlobal": "readonly",
				},
				ParserOptions: &ParserOptions{
					SourceType: "module",
				},
			},
		},
		{
			Language:        "javascript",
			Files:           []string{"scripts/**/*.ts"},
			ConfigDirectory: "/repo",
			LanguageOptions: &LanguageOptions{
				Globals: map[string]interface{}{
					"ScriptsGlobal": "readonly",
				},
				ParserOptions: &ParserOptions{
					SourceType: "script",
				},
			},
		},
	}

	srcResolved := ResolveLanguageOptionsForFile(cfg, "src/main.ts")
	if srcResolved == nil {
		t.Fatalf("expected language options for src/main.ts")
	}
	if srcResolved.Globals["SrcGlobal"] != "readonly" {
		t.Fatalf("expected SrcGlobal, got %#v", srcResolved.Globals)
	}
	if _, exists := srcResolved.Globals["ScriptsGlobal"]; exists {
		t.Fatalf("did not expect ScriptsGlobal for src/main.ts, got %#v", srcResolved.Globals)
	}
	if srcResolved.ParserOptions == nil || srcResolved.ParserOptions.SourceType != "module" {
		t.Fatalf("expected module parser options for src/main.ts, got %#v", srcResolved.ParserOptions)
	}

	scriptsResolved := ResolveLanguageOptionsForFile(cfg, "scripts/build.ts")
	if scriptsResolved == nil {
		t.Fatalf("expected language options for scripts/build.ts")
	}
	if scriptsResolved.Globals["ScriptsGlobal"] != "readonly" {
		t.Fatalf("expected ScriptsGlobal, got %#v", scriptsResolved.Globals)
	}
	if _, exists := scriptsResolved.Globals["SrcGlobal"]; exists {
		t.Fatalf("did not expect SrcGlobal for scripts/build.ts, got %#v", scriptsResolved.Globals)
	}
	if scriptsResolved.ParserOptions == nil || scriptsResolved.ParserOptions.SourceType != "script" {
		t.Fatalf("expected script parser options for scripts/build.ts, got %#v", scriptsResolved.ParserOptions)
	}
}

func TestConfigEntryMatchesFileSupportsDotPrefixedPatterns(t *testing.T) {
	entry := ConfigEntry{
		Language:        "javascript",
		Files:           []string{"./src/**/*.ts"},
		ConfigDirectory: "/repo",
	}

	if !configEntryMatchesFile(entry, "/repo/src/main.ts") {
		t.Fatalf("expected ./src/**/*.ts to match /repo/src/main.ts")
	}

	if configEntryMatchesFile(entry, "/repo/scripts/main.ts") {
		t.Fatalf("did not expect ./src/**/*.ts to match /repo/scripts/main.ts")
	}
}

func TestConfigEntryMatchesFileRespectsIgnores(t *testing.T) {
	entry := ConfigEntry{
		Language:        "javascript",
		Files:           []string{"src/**/*.ts"},
		Ignores:         []string{"src/generated/**"},
		ConfigDirectory: "/repo",
	}

	if ConfigEntryMatchesFile(entry, "/repo/src/main.ts") == false {
		t.Fatalf("expected /repo/src/main.ts to match")
	}
	if ConfigEntryMatchesFile(entry, "/repo/src/generated/types.ts") {
		t.Fatalf("did not expect ignored generated file to match")
	}
}

func TestGetRulesForFileRespectsEntryFiles(t *testing.T) {
	cfg := RslintConfig{
		{
			Language:        "javascript",
			Files:           []string{"src/**/*.ts"},
			ConfigDirectory: "/repo",
			Rules: Rules{
				"no-debugger": "error",
			},
		},
		{
			Language:        "javascript",
			Files:           []string{"scripts/**/*.ts"},
			ConfigDirectory: "/repo",
			Rules: Rules{
				"no-debugger": "off",
			},
		},
	}

	srcRules := cfg.GetRulesForFile("/repo/src/main.ts")
	if srcRules["no-debugger"] == nil || srcRules["no-debugger"].Level != "error" {
		t.Fatalf("expected src rule level error, got %#v", srcRules["no-debugger"])
	}

	scriptRules := cfg.GetRulesForFile("/repo/scripts/build.ts")
	if scriptRules["no-debugger"] == nil || scriptRules["no-debugger"].Level != "off" {
		t.Fatalf("expected scripts rule level off, got %#v", scriptRules["no-debugger"])
	}
}

func TestMergeParserOptionsProjectOverrideSemantics(t *testing.T) {
	var base ParserOptions
	if err := json.Unmarshal([]byte(`{
		"project": ["./tsconfig.base.json"]
	}`), &base); err != nil {
		t.Fatalf("failed to unmarshal base parser options: %v", err)
	}

	var clearOverride ParserOptions
	if err := json.Unmarshal([]byte(`{
		"project": []
	}`), &clearOverride); err != nil {
		t.Fatalf("failed to unmarshal clear override parser options: %v", err)
	}

	mergedCleared := mergeParserOptions(&base, &clearOverride)
	if mergedCleared == nil {
		t.Fatalf("expected merged parser options for clear override")
	}
	if len(mergedCleared.Project) != 0 {
		t.Fatalf("expected explicit empty project override to clear projects, got %#v", mergedCleared.Project)
	}

	var keepOverride ParserOptions
	if err := json.Unmarshal([]byte(`{
		"sourceType": "module"
	}`), &keepOverride); err != nil {
		t.Fatalf("failed to unmarshal keep override parser options: %v", err)
	}

	mergedKept := mergeParserOptions(&base, &keepOverride)
	if mergedKept == nil {
		t.Fatalf("expected merged parser options for keep override")
	}
	if len(mergedKept.Project) != 1 || mergedKept.Project[0] != "./tsconfig.base.json" {
		t.Fatalf("expected missing project override to keep base project, got %#v", mergedKept.Project)
	}
}
