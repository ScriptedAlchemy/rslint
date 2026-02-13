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
