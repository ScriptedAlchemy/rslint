package config

import (
	"errors"
	"fmt"
	iofs "io/fs"
	"os"
	"sort"
	"strings"

	"github.com/microsoft/typescript-go/shim/tspath"
	"github.com/microsoft/typescript-go/shim/vfs"
	"github.com/web-infra-dev/rslint/internal/utils"
)

// ConfigLoader handles loading and parsing of rslint and tsconfig files
type ConfigLoader struct {
	fs               vfs.FS
	currentDirectory string
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader(fs vfs.FS, currentDirectory string) *ConfigLoader {
	return &ConfigLoader{
		fs:               fs,
		currentDirectory: currentDirectory,
	}
}

// LoadRslintConfig loads and parses a rslint configuration file
func (loader *ConfigLoader) LoadRslintConfig(configPath string) (RslintConfig, string, error) {
	configFileName := tspath.ResolvePath(loader.currentDirectory, configPath)
	if !loader.fs.FileExists(configFileName) {
		return nil, "", fmt.Errorf("rslint config file %q doesn't exist", configFileName)
	}

	data, ok := loader.fs.ReadFile(configFileName)
	if !ok {
		return nil, "", fmt.Errorf("error reading rslint config file %q", configFileName)
	}

	var config RslintConfig
	// Use JSONC parser to support comments and trailing commas
	if err := utils.ParseJSONC([]byte(data), &config); err != nil {
		return nil, "", fmt.Errorf("error parsing rslint config file %q: %w", configFileName, err)
	}

	// Update current directory to the config file's directory
	configDirectory := tspath.GetDirectoryPath(configFileName)
	for i := range config {
		config[i].ConfigDirectory = configDirectory
	}
	return config, configDirectory, nil
}

// LoadDefaultRslintConfig attempts to load default configuration files
func (loader *ConfigLoader) LoadDefaultRslintConfig() (RslintConfig, string, error) {
	defaultConfigs := []string{"rslint.json", "rslint.jsonc"}

	for _, defaultConfig := range defaultConfigs {
		defaultConfigPath := tspath.ResolvePath(loader.currentDirectory, defaultConfig)
		if loader.fs.FileExists(defaultConfigPath) {
			return loader.LoadRslintConfig(defaultConfig)
		}
	}

	return nil, "", errors.New("no rslint config file found. Expected rslint.json or rslint.jsonc")
}

// LoadTsConfigsFromRslintConfig extracts and validates TypeScript configuration paths from rslint config
func (loader *ConfigLoader) LoadTsConfigsFromRslintConfig(rslintConfig RslintConfig, configDirectory string) ([]string, error) {
	return loader.loadTsConfigsFromRslintConfig(rslintConfig, configDirectory, nil)
}

func (loader *ConfigLoader) LoadTsConfigsFromRslintConfigForFiles(rslintConfig RslintConfig, configDirectory string, targetFiles []string) ([]string, error) {
	return loader.loadTsConfigsFromRslintConfig(rslintConfig, configDirectory, targetFiles)
}

func (loader *ConfigLoader) loadTsConfigsFromRslintConfig(rslintConfig RslintConfig, configDirectory string, targetFiles []string) ([]string, error) {
	tsConfigs := []string{}
	seenConfigs := map[string]bool{}

	for _, entry := range rslintConfig {
		if len(targetFiles) > 0 {
			isApplicable := false
			for _, filePath := range targetFiles {
				if configEntryMatchesFile(entry, filePath) {
					isApplicable = true
					break
				}
			}
			if !isApplicable {
				continue
			}
		}

		if entry.LanguageOptions == nil || entry.LanguageOptions.ParserOptions == nil {
			continue
		}

		for _, config := range entry.LanguageOptions.ParserOptions.Project {
			baseDir := configDirectory
			if entry.LanguageOptions.ParserOptions.TsconfigRootDir != "" {
				baseDir = tspath.ResolvePath(configDirectory, entry.LanguageOptions.ParserOptions.TsconfigRootDir)
			}
			resolvedPaths, err := loader.resolveProjectPaths(baseDir, config)
			if err != nil {
				return nil, err
			}
			for _, tsconfigPath := range resolvedPaths {
				if seenConfigs[tsconfigPath] {
					continue
				}
				seenConfigs[tsconfigPath] = true
				tsConfigs = append(tsConfigs, tsconfigPath)
			}
		}
	}

	if len(tsConfigs) == 0 {
		return nil, errors.New("no TypeScript configuration found in rslint config")
	}

	return tsConfigs, nil
}

func hasGlobPattern(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[{")
}

func (loader *ConfigLoader) resolveProjectPaths(baseDir string, projectPath string) ([]string, error) {
	if !hasGlobPattern(projectPath) {
		tsconfigPath := tspath.ResolvePath(baseDir, projectPath)
		if !loader.fs.FileExists(tsconfigPath) {
			return nil, fmt.Errorf("tsconfig file %q doesn't exist", tsconfigPath)
		}
		return []string{tsconfigPath}, nil
	}

	matches := []string{}
	walkErr := loader.fs.WalkDir(baseDir, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d == nil || d.IsDir() {
			return nil
		}
		normalizedPath := tspath.NormalizePath(path)
		relativePath := tspath.NormalizePath(tspath.ConvertToRelativePath(normalizedPath, tspath.ComparePathsOptions{
			UseCaseSensitiveFileNames: loader.fs.UseCaseSensitiveFileNames(),
			CurrentDirectory:          baseDir,
		}))
		if patternMatchesFile(projectPath, normalizedPath, relativePath) {
			matches = append(matches, normalizedPath)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return nil, fmt.Errorf("tsconfig file %q doesn't exist", tspath.ResolvePath(baseDir, projectPath))
	}
	return matches, nil
}

// LoadConfiguration is a convenience method that loads both rslint and tsconfig configurations
func (loader *ConfigLoader) LoadConfiguration(configPath string) (RslintConfig, []string, string, error) {
	var rslintConfig RslintConfig
	var configDirectory string
	var err error

	if configPath != "" {
		rslintConfig, configDirectory, err = loader.LoadRslintConfig(configPath)
	} else {
		rslintConfig, configDirectory, err = loader.LoadDefaultRslintConfig()
	}

	if err != nil {
		return nil, nil, "", err
	}

	tsConfigs, err := loader.LoadTsConfigsFromRslintConfig(rslintConfig, configDirectory)
	if err != nil {
		return nil, nil, "", err
	}

	return rslintConfig, tsConfigs, configDirectory, nil
}

// LoadConfigurationWithFallback loads configuration and handles errors by printing to stderr and exiting
// This is for backward compatibility with the existing cmd behavior
func LoadConfigurationWithFallback(configPath string, currentDirectory string, fs vfs.FS) (RslintConfig, []string, string) {
	loader := NewConfigLoader(fs, currentDirectory)

	rslintConfig, tsConfigs, configDirectory, err := loader.LoadConfiguration(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	return rslintConfig, tsConfigs, configDirectory
}
