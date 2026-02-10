package main

import (
	"reflect"
	"testing"

	ipc "github.com/web-infra-dev/rslint/internal/api"
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
