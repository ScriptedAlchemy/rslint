package config

import (
	"os"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/web-infra-dev/rslint/internal/rule"
)

func cloneEcmaFeatures(features *EcmaFeatures) *EcmaFeatures {
	if features == nil {
		return nil
	}
	return &EcmaFeatures{
		GlobalReturn:    features.GlobalReturn,
		JSX:             features.JSX,
		GlobalReturnSet: features.GlobalReturnSet,
		JSXSet:          features.JSXSet,
	}
}

func cloneParserOptions(options *ParserOptions) *ParserOptions {
	if options == nil {
		return nil
	}
	return &ParserOptions{
		ProjectService:            options.ProjectService,
		Project:                   append(ProjectPaths(nil), options.Project...),
		TsconfigRootDir:           options.TsconfigRootDir,
		SourceType:                options.SourceType,
		EcmaVersion:               options.EcmaVersion,
		IsolatedDeclarations:      options.IsolatedDeclarations,
		ExperimentalDecorators:    options.ExperimentalDecorators,
		EmitDecoratorMetadata:     options.EmitDecoratorMetadata,
		JSXPragma:                 options.JSXPragma,
		JSXFragmentName:           options.JSXFragmentName,
		EcmaFeatures:              cloneEcmaFeatures(options.EcmaFeatures),
		ProjectServiceSet:         options.ProjectServiceSet,
		IsolatedDeclarationsSet:   options.IsolatedDeclarationsSet,
		ExperimentalDecoratorsSet: options.ExperimentalDecoratorsSet,
		EmitDecoratorMetadataSet:  options.EmitDecoratorMetadataSet,
	}
}

func cloneLanguageOptions(options *LanguageOptions) *LanguageOptions {
	if options == nil {
		return nil
	}
	languageOptions := &LanguageOptions{
		ParserOptions: cloneParserOptions(options.ParserOptions),
	}
	if len(options.Globals) > 0 {
		languageOptions.Globals = make(map[string]interface{}, len(options.Globals))
		for key, value := range options.Globals {
			languageOptions.Globals[key] = value
		}
	}
	if languageOptions.ParserOptions == nil && len(languageOptions.Globals) == 0 {
		return nil
	}
	return languageOptions
}

func mergeParserOptions(base *ParserOptions, override *ParserOptions) *ParserOptions {
	if base == nil {
		return cloneParserOptions(override)
	}
	if override == nil {
		return cloneParserOptions(base)
	}

	result := cloneParserOptions(base)
	if override.ProjectServiceSet || override.ProjectService {
		result.ProjectService = override.ProjectService
		result.ProjectServiceSet = override.ProjectServiceSet || override.ProjectService
	}
	if len(override.Project) > 0 {
		result.Project = append(ProjectPaths(nil), override.Project...)
	}
	if override.TsconfigRootDir != "" {
		result.TsconfigRootDir = override.TsconfigRootDir
	}
	if override.SourceType != "" {
		result.SourceType = override.SourceType
	}
	if override.EcmaVersion != 0 {
		result.EcmaVersion = override.EcmaVersion
	}
	if override.IsolatedDeclarationsSet || override.IsolatedDeclarations {
		result.IsolatedDeclarations = override.IsolatedDeclarations
		result.IsolatedDeclarationsSet = override.IsolatedDeclarationsSet || override.IsolatedDeclarations
	}
	if override.ExperimentalDecoratorsSet || override.ExperimentalDecorators {
		result.ExperimentalDecorators = override.ExperimentalDecorators
		result.ExperimentalDecoratorsSet = override.ExperimentalDecoratorsSet || override.ExperimentalDecorators
	}
	if override.EmitDecoratorMetadataSet || override.EmitDecoratorMetadata {
		result.EmitDecoratorMetadata = override.EmitDecoratorMetadata
		result.EmitDecoratorMetadataSet = override.EmitDecoratorMetadataSet || override.EmitDecoratorMetadata
	}
	if override.JSXPragma != "" {
		result.JSXPragma = override.JSXPragma
	}
	if override.JSXFragmentName != "" {
		result.JSXFragmentName = override.JSXFragmentName
	}
	if override.EcmaFeatures != nil {
		if result.EcmaFeatures == nil {
			result.EcmaFeatures = &EcmaFeatures{}
		}
		if override.EcmaFeatures.GlobalReturnSet || override.EcmaFeatures.GlobalReturn {
			result.EcmaFeatures.GlobalReturn = override.EcmaFeatures.GlobalReturn
			result.EcmaFeatures.GlobalReturnSet = override.EcmaFeatures.GlobalReturnSet || override.EcmaFeatures.GlobalReturn
		}
		if override.EcmaFeatures.JSXSet || override.EcmaFeatures.JSX {
			result.EcmaFeatures.JSX = override.EcmaFeatures.JSX
			result.EcmaFeatures.JSXSet = override.EcmaFeatures.JSXSet || override.EcmaFeatures.JSX
		}
	}
	return result
}

func mergeLanguageOptions(base *LanguageOptions, override *LanguageOptions) *LanguageOptions {
	if base == nil {
		return cloneLanguageOptions(override)
	}
	if override == nil {
		return cloneLanguageOptions(base)
	}

	result := cloneLanguageOptions(base)
	if len(override.Globals) > 0 {
		if result.Globals == nil {
			result.Globals = map[string]interface{}{}
		}
		for key, value := range override.Globals {
			result.Globals[key] = value
		}
	}
	result.ParserOptions = mergeParserOptions(result.ParserOptions, override.ParserOptions)
	if result.ParserOptions == nil && len(result.Globals) == 0 {
		return nil
	}
	return result
}

// ResolveLanguageOptionsForFile resolves file-level language options using the same
// entry inclusion behavior as rule resolution.
func ResolveLanguageOptionsForFile(config RslintConfig, filePath string) *LanguageOptions {
	var resolved *LanguageOptions
	for _, entry := range config {
		if !configEntryMatchesFile(entry, filePath) {
			continue
		}
		resolved = mergeLanguageOptions(resolved, entry.LanguageOptions)
	}
	return resolved
}

func configEntryMatchesFile(entry ConfigEntry, filePath string) bool {
	if isFileIgnored(filePath, entry.Ignores) {
		return false
	}
	if len(entry.Files) == 0 {
		return true
	}

	normalizedPath := filePath
	if cwd, err := os.Getwd(); err == nil {
		normalizedPath = normalizePath(filePath, cwd)
	}

	for _, filePattern := range entry.Files {
		if patternMatchesFile(filePattern, filePath, normalizedPath) {
			return true
		}
	}
	return false
}

func patternMatchesFile(pattern string, filePath string, normalizedPath string) bool {
	candidates := []string{
		normalizedPath,
		strings.ReplaceAll(normalizedPath, "\\", "/"),
		filePath,
		strings.ReplaceAll(filePath, "\\", "/"),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if matched, err := doublestar.Match(pattern, candidate); err == nil && matched {
			return true
		}
	}
	return false
}

func BuildRuleParserOptions(languageOptions *LanguageOptions) *rule.RuleParserOptions {
	if languageOptions == nil || languageOptions.ParserOptions == nil {
		return nil
	}
	parserOptions := languageOptions.ParserOptions
	result := &rule.RuleParserOptions{
		SourceType:             parserOptions.SourceType,
		EcmaVersion:            parserOptions.EcmaVersion,
		IsolatedDeclarations:   parserOptions.IsolatedDeclarations,
		ExperimentalDecorators: parserOptions.ExperimentalDecorators,
		EmitDecoratorMetadata:  parserOptions.EmitDecoratorMetadata,
		JSXPragma:              parserOptions.JSXPragma,
		JSXFragmentName:        parserOptions.JSXFragmentName,
	}
	if parserOptions.EcmaFeatures != nil {
		result.EcmaFeatures = &rule.RuleEcmaFeatures{
			GlobalReturn: parserOptions.EcmaFeatures.GlobalReturn,
			JSX:          parserOptions.EcmaFeatures.JSX,
		}
	}
	return result
}

func BuildRuleGlobals(languageOptions *LanguageOptions) map[string]bool {
	if languageOptions == nil || len(languageOptions.Globals) == 0 {
		return nil
	}
	globals := map[string]bool{}
	for name, raw := range languageOptions.Globals {
		switch v := raw.(type) {
		case bool:
			// Both true (writable) and false (readonly) declare globals.
			globals[name] = true
		case string:
			lower := strings.ToLower(v)
			if lower != "off" && lower != "false" {
				globals[name] = true
			}
		default:
			globals[name] = true
		}
	}
	if len(globals) == 0 {
		return nil
	}
	return globals
}

func ResolveRuleContextForFile(config RslintConfig, filePath string) (*rule.RuleParserOptions, map[string]bool) {
	languageOptions := ResolveLanguageOptionsForFile(config, filePath)
	return BuildRuleParserOptions(languageOptions), BuildRuleGlobals(languageOptions)
}
