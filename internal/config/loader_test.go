package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/microsoft/typescript-go/shim/bundled"
	"github.com/microsoft/typescript-go/shim/vfs/cachedvfs"
	"github.com/microsoft/typescript-go/shim/vfs/osvfs"
)

func TestLoadTsConfigsFromRslintConfigDeduplicatesPaths(t *testing.T) {
	tempDir := t.TempDir()
	tsconfigPath := filepath.Join(tempDir, "tsconfig.json")
	if err := os.WriteFile(tsconfigPath, []byte(`{"compilerOptions":{"strict":true}}`), 0o644); err != nil {
		t.Fatalf("failed to write tsconfig fixture: %v", err)
	}

	loader := NewConfigLoader(bundled.WrapFS(cachedvfs.From(osvfs.FS())), tempDir)
	cfg := RslintConfig{
		{
			ConfigDirectory: tempDir,
			LanguageOptions: &LanguageOptions{
				ParserOptions: &ParserOptions{
					Project: ProjectPaths{"./tsconfig.json", "./tsconfig.json"},
				},
			},
		},
		{
			ConfigDirectory: tempDir,
			LanguageOptions: &LanguageOptions{
				ParserOptions: &ParserOptions{
					Project: ProjectPaths{"./tsconfig.json"},
				},
			},
		},
	}

	tsconfigs, err := loader.LoadTsConfigsFromRslintConfig(cfg, tempDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(tsconfigs) != 1 {
		t.Fatalf("expected deduplicated single tsconfig, got %#v", tsconfigs)
	}
	if tsconfigs[0] != tsconfigPath {
		t.Fatalf("expected %q, got %q", tsconfigPath, tsconfigs[0])
	}
}

func TestLoadTsConfigsFromRslintConfigForFilesSkipsUnmatchedEntries(t *testing.T) {
	tempDir := t.TempDir()
	srcTsconfigPath := filepath.Join(tempDir, "tsconfig.src.json")
	if err := os.WriteFile(srcTsconfigPath, []byte(`{"compilerOptions":{"strict":true}}`), 0o644); err != nil {
		t.Fatalf("failed to write tsconfig fixture: %v", err)
	}

	loader := NewConfigLoader(bundled.WrapFS(cachedvfs.From(osvfs.FS())), tempDir)
	cfg := RslintConfig{
		{
			ConfigDirectory: tempDir,
			Files:           []string{"src/**/*.ts"},
			LanguageOptions: &LanguageOptions{
				ParserOptions: &ParserOptions{
					Project: ProjectPaths{"./tsconfig.src.json"},
				},
			},
		},
		{
			ConfigDirectory: tempDir,
			Files:           []string{"scripts/**/*.ts"},
			LanguageOptions: &LanguageOptions{
				ParserOptions: &ParserOptions{
					Project: ProjectPaths{"./missing.tsconfig.json"},
				},
			},
		},
	}

	tsconfigs, err := loader.LoadTsConfigsFromRslintConfigForFiles(cfg, tempDir, []string{filepath.Join(tempDir, "src/main.ts")})
	if err != nil {
		t.Fatalf("expected no error for unmatched missing tsconfig entry, got %v", err)
	}
	if len(tsconfigs) != 1 || tsconfigs[0] != srcTsconfigPath {
		t.Fatalf("expected only src tsconfig, got %#v", tsconfigs)
	}
}
