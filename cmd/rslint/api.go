package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/microsoft/typescript-go/shim/ast"
	"github.com/microsoft/typescript-go/shim/bundled"
	"github.com/microsoft/typescript-go/shim/compiler"
	"github.com/microsoft/typescript-go/shim/core"
	"github.com/microsoft/typescript-go/shim/scanner"
	"github.com/microsoft/typescript-go/shim/tspath"
	"github.com/microsoft/typescript-go/shim/vfs/cachedvfs"
	"github.com/microsoft/typescript-go/shim/vfs/osvfs"
	api "github.com/web-infra-dev/rslint/internal/api"
	rslintconfig "github.com/web-infra-dev/rslint/internal/config"
	"github.com/web-infra-dev/rslint/internal/inspector"
	"github.com/web-infra-dev/rslint/internal/linter"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/utils"
)

func getUTF16LineAndCharacterOfPosition(sourceFile *ast.SourceFile, pos int) (line int, character int) {
	lineStarts := scanner.GetECMALineStarts(sourceFile)
	line = scanner.ComputeLineOfPosition(lineStarts, pos)
	if line < 0 || line >= len(lineStarts) {
		return line, 0
	}

	lineStart := int(lineStarts[line])
	if lineStart < 0 {
		lineStart = 0
	}

	sourceText := sourceFile.Text()
	if pos < lineStart {
		pos = lineStart
	}
	if pos > len(sourceText) {
		pos = len(sourceText)
	}
	if lineStart > len(sourceText) {
		return line, 0
	}

	for _, r := range sourceText[lineStart:pos] {
		if r <= 0xFFFF {
			character++
		} else {
			character += 2
		}
	}
	return line, character
}

// IPCHandler implements the ipc.Handler interface
type IPCHandler struct{}

// programCache holds a cached Program instance for AST info requests
type programCache struct {
	mu              sync.RWMutex
	fileContent     string
	compilerOptions string // JSON serialized for comparison
	program         *compiler.Program
	sourceFile      *ast.SourceFile
}

func buildRuleParserOptions(languageOptions *api.LanguageOptions) *rule.RuleParserOptions {
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

func buildRuleGlobals(languageOptions *api.LanguageOptions) map[string]bool {
	if languageOptions == nil || len(languageOptions.Globals) == 0 {
		return nil
	}
	globals := map[string]bool{}
	for name, raw := range languageOptions.Globals {
		switch v := raw.(type) {
		case bool:
			// ESLint semantics: both true (writable) and false (readonly) declare a global.
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

func configLanguageOptionsToAPI(languageOptions *rslintconfig.LanguageOptions) *api.LanguageOptions {
	if languageOptions == nil {
		return nil
	}

	result := &api.LanguageOptions{}

	if len(languageOptions.Globals) > 0 {
		result.Globals = make(map[string]interface{}, len(languageOptions.Globals))
		for key, value := range languageOptions.Globals {
			result.Globals[key] = value
		}
	}

	if languageOptions.ParserOptions != nil {
		parserOptions := languageOptions.ParserOptions
		result.ParserOptions = &api.ParserOptions{
			ProjectService:            parserOptions.ProjectService,
			Project:                   api.ProjectPaths(parserOptions.Project),
			TsconfigRootDir:           parserOptions.TsconfigRootDir,
			SourceType:                parserOptions.SourceType,
			EcmaVersion:               parserOptions.EcmaVersion,
			IsolatedDeclarations:      parserOptions.IsolatedDeclarations,
			ExperimentalDecorators:    parserOptions.ExperimentalDecorators,
			EmitDecoratorMetadata:     parserOptions.EmitDecoratorMetadata,
			JSXPragma:                 parserOptions.JSXPragma,
			JSXFragmentName:           parserOptions.JSXFragmentName,
			ProjectServiceSet:         parserOptions.ProjectServiceSet,
			IsolatedDeclarationsSet:   parserOptions.IsolatedDeclarationsSet,
			ExperimentalDecoratorsSet: parserOptions.ExperimentalDecoratorsSet,
			EmitDecoratorMetadataSet:  parserOptions.EmitDecoratorMetadataSet,
		}
		if parserOptions.EcmaFeatures != nil {
			result.ParserOptions.EcmaFeatures = &api.EcmaFeatures{
				GlobalReturn:    parserOptions.EcmaFeatures.GlobalReturn,
				JSX:             parserOptions.EcmaFeatures.JSX,
				GlobalReturnSet: parserOptions.EcmaFeatures.GlobalReturnSet,
				JSXSet:          parserOptions.EcmaFeatures.JSXSet,
			}
		}
	}

	if result.ParserOptions == nil && len(result.Globals) == 0 {
		return nil
	}

	return result
}

func cloneEcmaFeatures(features *api.EcmaFeatures) *api.EcmaFeatures {
	if features == nil {
		return nil
	}
	return &api.EcmaFeatures{
		GlobalReturn:    features.GlobalReturn,
		JSX:             features.JSX,
		GlobalReturnSet: features.GlobalReturnSet,
		JSXSet:          features.JSXSet,
	}
}

func cloneParserOptions(options *api.ParserOptions) *api.ParserOptions {
	if options == nil {
		return nil
	}
	parserOptions := &api.ParserOptions{
		ProjectService:            options.ProjectService,
		Project:                   append(api.ProjectPaths(nil), options.Project...),
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
	return parserOptions
}

func cloneLanguageOptions(options *api.LanguageOptions) *api.LanguageOptions {
	if options == nil {
		return nil
	}
	languageOptions := &api.LanguageOptions{
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

func mergeParserOptions(base *api.ParserOptions, override *api.ParserOptions) *api.ParserOptions {
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
	if override.Project != nil {
		result.Project = append(api.ProjectPaths(nil), override.Project...)
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
			result.EcmaFeatures = &api.EcmaFeatures{}
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

func mergeLanguageOptions(base *api.LanguageOptions, override *api.LanguageOptions) *api.LanguageOptions {
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

func patternMatchesFile(pattern string, filePath string, normalizedPath string) bool {
	candidates := []string{}
	appendCandidate := func(candidate string) {
		if candidate == "" {
			return
		}
		candidates = append(candidates, candidate)
		if !strings.HasPrefix(candidate, "./") {
			candidates = append(candidates, "./"+candidate)
		}
	}
	appendCandidate(normalizedPath)
	appendCandidate(strings.ReplaceAll(normalizedPath, "\\", "/"))
	appendCandidate(filePath)
	appendCandidate(strings.ReplaceAll(filePath, "\\", "/"))

	seen := map[string]bool{}
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		if matched, err := doublestar.Match(pattern, candidate); err == nil && matched {
			return true
		}
	}
	return false
}

func configEntryMatchesFile(entry rslintconfig.ConfigEntry, filePath string, configDirectory string) bool {
	normalizedPath := tspath.NormalizePath(tspath.ConvertToRelativePath(filePath, tspath.ComparePathsOptions{
		CurrentDirectory:          configDirectory,
		UseCaseSensitiveFileNames: true,
	}))

	for _, ignorePattern := range entry.Ignores {
		if patternMatchesFile(ignorePattern, filePath, normalizedPath) {
			return false
		}
	}

	if len(entry.Files) == 0 {
		return true
	}

	for _, filePattern := range entry.Files {
		if patternMatchesFile(filePattern, filePath, normalizedPath) {
			return true
		}
	}
	return false
}

func resolveRuleLanguageOptions(requestOptions *api.LanguageOptions, configEntries rslintconfig.RslintConfig) *api.LanguageOptions {
	var resolved *api.LanguageOptions
	for _, entry := range configEntries {
		resolved = mergeLanguageOptions(resolved, configLanguageOptionsToAPI(entry.LanguageOptions))
	}
	return mergeLanguageOptions(resolved, requestOptions)
}

func resolveRuleLanguageOptionsForFile(requestOptions *api.LanguageOptions, configEntries rslintconfig.RslintConfig, filePath string, configDirectory string) *api.LanguageOptions {
	var resolved *api.LanguageOptions
	for _, entry := range configEntries {
		if !configEntryMatchesFile(entry, filePath, configDirectory) {
			continue
		}
		resolved = mergeLanguageOptions(resolved, configLanguageOptionsToAPI(entry.LanguageOptions))
	}
	return mergeLanguageOptions(resolved, requestOptions)
}

func entryMatchesAnyTargetFile(entry rslintconfig.ConfigEntry, targetFiles []string, configDirectory string) bool {
	if len(targetFiles) == 0 {
		return true
	}
	for _, targetFile := range targetFiles {
		if configEntryMatchesFile(entry, targetFile, configDirectory) {
			return true
		}
	}
	return false
}

func collectTsConfigsForRequest(configEntries rslintconfig.RslintConfig, requestOptions *api.LanguageOptions, configDirectory string, fs interface{ FileExists(path string) bool }, targetFiles []string) ([]string, bool) {
	hasExplicitProjectOverride := requestOptions != nil && requestOptions.ParserOptions != nil && requestOptions.ParserOptions.Project != nil
	collected := []string{}
	seen := map[string]bool{}

	for _, entry := range configEntries {
		if !entryMatchesAnyTargetFile(entry, targetFiles, configDirectory) {
			continue
		}
		effectiveLanguageOptions := mergeLanguageOptions(configLanguageOptionsToAPI(entry.LanguageOptions), requestOptions)
		if effectiveLanguageOptions == nil || effectiveLanguageOptions.ParserOptions == nil {
			continue
		}
		baseDir := configDirectory
		if effectiveLanguageOptions.ParserOptions.TsconfigRootDir != "" {
			baseDir = tspath.ResolvePath(configDirectory, effectiveLanguageOptions.ParserOptions.TsconfigRootDir)
		}
		for _, config := range effectiveLanguageOptions.ParserOptions.Project {
			tsconfigPath := tspath.ResolvePath(baseDir, config)
			if !fs.FileExists(tsconfigPath) || seen[tsconfigPath] {
				continue
			}
			seen[tsconfigPath] = true
			collected = append(collected, tsconfigPath)
		}
	}

	return collected, hasExplicitProjectOverride
}

// Global program cache for AST info requests
var astInfoProgramCache = &programCache{}

// HandleLint handles lint requests in IPC mode
func (h *IPCHandler) HandleLint(req api.LintRequest) (*api.LintResponse, error) {

	// Format is not used for IPC mode as we return structured data
	_ = req.Format

	// Set working directory if provided
	if req.WorkingDirectory != "" {
		if err := os.Chdir(req.WorkingDirectory); err != nil {
			return nil, fmt.Errorf("failed to change directory: %w", err)
		}
	}

	// Get current directory
	currentDirectory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("error getting current directory: %w", err)
	}
	currentDirectory = tspath.NormalizePath(currentDirectory)

	// Create filesystem
	fs := bundled.WrapFS(cachedvfs.From(osvfs.FS()))
	allowedFiles := []string{}
	// Apply file contents if provided
	if len(req.FileContents) > 0 {
		fileContents := make(map[string]string, len(req.FileContents))
		for k, v := range req.FileContents {
			normalizePath := tspath.NormalizePath(k)
			fileContents[normalizePath] = v
			allowedFiles = append(allowedFiles, normalizePath)
		}
		fs = utils.NewOverlayVFS(fs, fileContents)

	}

	// Initialize rule registry with all available rules
	rslintconfig.RegisterAllRules()

	// Load rslint configuration and determine which tsconfig files to use
	loader := rslintconfig.NewConfigLoader(fs, currentDirectory)
	var (
		rslintConfig    rslintconfig.RslintConfig
		configDirectory string
	)
	if req.Config != "" {
		rslintConfig, configDirectory, err = loader.LoadRslintConfig(req.Config)
	} else {
		rslintConfig, configDirectory, err = loader.LoadDefaultRslintConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}

	var tsConfigs []string
	overrideTsconfigs, hasExplicitProjectOverride := collectTsConfigsForRequest(rslintConfig, req.LanguageOptions, configDirectory, fs, allowedFiles)
	if hasExplicitProjectOverride {
		tsConfigs = overrideTsconfigs
	} else {
		if len(allowedFiles) > 0 {
			tsConfigs, err = loader.LoadTsConfigsFromRslintConfigForFiles(rslintConfig, configDirectory, allowedFiles)
		} else {
			tsConfigs, err = loader.LoadTsConfigsFromRslintConfig(rslintConfig, configDirectory)
		}
		if err != nil {
			return nil, fmt.Errorf("error resolving tsconfig files: %w", err)
		}
		if len(overrideTsconfigs) > 0 {
			tsConfigs = overrideTsconfigs
		}
	}
	type RuleWithOption struct {
		rule   rule.Rule
		option interface{}
	}
	rulesWithOptions := []RuleWithOption{}
	// filter rule based on request.RuleOptions
	if len(req.RuleOptions) > 0 {
		for _, r := range rslintconfig.GlobalRuleRegistry.GetAllRules() {
			if option, ok := req.RuleOptions[r.Name]; ok {
				rulesWithOptions = append(rulesWithOptions, RuleWithOption{
					rule:   r,
					option: option,
				})
			}
		}
	}

	// Create compiler host
	host := utils.CreateCompilerHost(configDirectory, fs)
	comparePathOptions := tspath.ComparePathsOptions{
		CurrentDirectory:          host.GetCurrentDirectory(),
		UseCaseSensitiveFileNames: host.FS().UseCaseSensitiveFileNames(),
	}

	// Create programs from all tsconfig files found in rslint config
	programs := []*compiler.Program{}
	for _, configFileName := range tsConfigs {
		program, err := utils.CreateProgram(false, fs, configDirectory, configFileName, host)
		if err != nil {
			return nil, fmt.Errorf("error creating TS program for %s: %w", configFileName, err)
		}
		programs = append(programs, program)
	}

	// Collect diagnostics and source files
	var diagnostics []api.Diagnostic
	var diagnosticsLock sync.Mutex
	errorsCount := 0

	// Track source files for encoding
	sourceFiles := make(map[string]*ast.SourceFile)
	var sourceFilesLock sync.Mutex

	// Create collector function
	diagnosticCollector := func(d rule.RuleDiagnostic) {

		diagnosticsLock.Lock()
		defer diagnosticsLock.Unlock()

		diagnosticStart := d.Range.Pos()
		diagnosticEnd := d.Range.End()

		startLine, startColumn := getUTF16LineAndCharacterOfPosition(d.SourceFile, diagnosticStart)
		endLine, endColumn := getUTF16LineAndCharacterOfPosition(d.SourceFile, diagnosticEnd)

		diagnostic := api.Diagnostic{
			RuleName:  d.RuleName,
			MessageId: d.Message.Id,
			Message:   d.Message.Description,
			FilePath:  tspath.ConvertToRelativePath(d.SourceFile.FileName(), comparePathOptions),
			Range: api.Range{
				Start: api.Position{
					Line:   startLine + 1, // Convert to 1-based indexing
					Column: startColumn + 1,
				},
				End: api.Position{
					Line:   endLine + 1,
					Column: endColumn + 1,
				},
			},
		}

		// Add fixes if available
		if d.FixesPtr != nil && len(*d.FixesPtr) > 0 {
			var fixes []api.Fix
			for _, fix := range *d.FixesPtr {
				// Convert TextRange to character positions
				startPos := fix.Range.Pos()
				endPos := fix.Range.End()

				fixes = append(fixes, api.Fix{
					Text:     fix.Text,
					StartPos: startPos,
					EndPos:   endPos,
				})
			}
			diagnostic.Fixes = fixes
		}

		diagnostics = append(diagnostics, diagnostic)
		errorsCount++

	}

	// Run linter
	lintedFilesCount, err := linter.RunLinter(
		programs,
		false, // Don't use single-threaded mode for IPC
		allowedFiles,
		utils.ExcludePaths,
		func(sourceFile *ast.SourceFile) []linter.ConfiguredRule {
			// Track source file for encoding
			sourceFilesLock.Lock()
			filePath := tspath.ConvertToRelativePath(sourceFile.FileName(), comparePathOptions)
			sourceFiles[filePath] = sourceFile
			sourceFilesLock.Unlock()
			effectiveLanguageOptions := resolveRuleLanguageOptionsForFile(req.LanguageOptions, rslintConfig, sourceFile.FileName(), configDirectory)
			ruleParserOptions := buildRuleParserOptions(effectiveLanguageOptions)
			ruleGlobals := buildRuleGlobals(effectiveLanguageOptions)
			return utils.Map(rulesWithOptions, func(r RuleWithOption) linter.ConfiguredRule {

				return linter.ConfiguredRule{
					Name: r.rule.Name,
					Run: func(ctx rule.RuleContext) rule.RuleListeners {
						ctx.ParserOptions = ruleParserOptions
						ctx.Globals = ruleGlobals
						return r.rule.Run(ctx, r.option)
					},
				}
			})
		},
		diagnosticCollector,
	)
	if err != nil {
		return nil, fmt.Errorf("error running linter: %w", err)
	}

	if diagnostics == nil {
		diagnostics = []api.Diagnostic{}
	}
	// sort diagnostics
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].FilePath != diagnostics[j].FilePath {
			return diagnostics[i].FilePath < diagnostics[j].FilePath
		}
		if diagnostics[i].Range.Start.Line != diagnostics[j].Range.Start.Line {
			return diagnostics[i].Range.Start.Line < diagnostics[j].Range.Start.Line
		}
		return diagnostics[i].Range.Start.Column < diagnostics[j].Range.Start.Column
	})

	// Create response
	response := &api.LintResponse{
		Diagnostics: diagnostics,
		ErrorCount:  errorsCount,
		FileCount:   int(lintedFilesCount),
		RuleCount:   len(rulesWithOptions),
	}
	// Only include encoded source files if requested
	if req.IncludeEncodedSourceFiles {
		encodedSourceFiles := make(map[string]api.ByteArray)
		for filePath, sourceFile := range sourceFiles {
			encoded, err := api.EncodeAST(sourceFile, filePath)

			if err != nil {
				// Log error but don't fail the entire request
				fmt.Fprintf(os.Stderr, "warning: failed to encode source file %s: %v\n", filePath, err)
				continue
			}
			encodedSourceFiles[filePath] = encoded
		}
		response.EncodedSourceFiles = encodedSourceFiles
	}
	return response, nil
}

// HandleApplyFixes handles apply fixes requests in IPC mode
func (h *IPCHandler) HandleApplyFixes(req api.ApplyFixesRequest) (*api.ApplyFixesResponse, error) {
	// Convert API diagnostics to rule diagnostics for use with linter.ApplyRuleFixes
	var ruleDiagnostics []rule.RuleDiagnostic

	for _, clientDiag := range req.Diagnostics {
		if len(clientDiag.Fixes) == 0 {
			continue
		}

		// Convert API fixes to rule fixes
		var ruleFixes []rule.RuleFix
		for _, clientFix := range clientDiag.Fixes {
			// Create TextRange from start and end positions
			textRange := core.NewTextRange(clientFix.StartPos, clientFix.EndPos)

			ruleFix := rule.RuleFix{
				Text:  clientFix.Text,
				Range: textRange,
			}
			ruleFixes = append(ruleFixes, ruleFix)
		}

		// Create rule diagnostic
		ruleDiag := rule.RuleDiagnostic{
			Range:    core.NewTextRange(0, 0), // Not used by ApplyRuleFixes
			RuleName: clientDiag.RuleName,
			Message: rule.RuleMessage{
				Id:          clientDiag.MessageId,
				Description: clientDiag.Message,
			},
			FixesPtr: &ruleFixes,
		}

		ruleDiagnostics = append(ruleDiagnostics, ruleDiag)
	}

	// Use linter.ApplyRuleFixes to apply the fixes
	code := req.FileContent
	outputs := []string{}
	wasFixed := false

	// Apply fixes iteratively to handle overlapping fixes
	for {
		fixedContent, unapplied, fixed := linter.ApplyRuleFixes(code, ruleDiagnostics)
		if !fixed {
			break
		}

		outputs = append(outputs, fixedContent)
		code = fixedContent
		wasFixed = true

		// Update diagnostics to only include unapplied ones for next iteration
		ruleDiagnostics = unapplied
		if len(ruleDiagnostics) == 0 {
			break
		}
	}

	// Count applied and unapplied fixes
	appliedCount := len(req.Diagnostics) - len(ruleDiagnostics)
	unappliedCount := len(ruleDiagnostics)

	return &api.ApplyFixesResponse{
		FixedContent:   outputs,
		WasFixed:       wasFixed,
		AppliedCount:   appliedCount,
		UnappliedCount: unappliedCount,
	}, nil
}

// HandleGetAstInfo handles get AST info requests in IPC mode
func (h *IPCHandler) HandleGetAstInfo(req api.GetAstInfoRequest) (*api.GetAstInfoResponse, error) {
	// Fixed user file name for program creation
	const userFileName = "/index.ts"

	// Serialize compiler options for comparison
	compilerOptionsJSON := "{}"
	if req.CompilerOptions != nil {
		jsonBytes, err := json.Marshal(req.CompilerOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal compiler options: %w", err)
		}
		compilerOptionsJSON = string(jsonBytes)
	}

	// Check if we can use cached program
	program, userSourceFile := getCachedProgram(req.FileContent, compilerOptionsJSON)
	if program == nil || userSourceFile == nil {
		// Cache miss - create new program
		var err error
		program, userSourceFile, err = createAndCacheProgram(userFileName, req.FileContent, compilerOptionsJSON, req.CompilerOptions)
		if err != nil {
			return nil, err
		}
	}

	// Get type checker
	typeChecker, done := program.GetTypeChecker(context.Background())
	defer done()

	// Determine which source file to query
	// If FileName is set to an external file, query that file (e.g., lib.d.ts)
	// Otherwise, query the user's source file
	var targetSourceFile *ast.SourceFile
	if req.FileName != "" && req.FileName != userFileName {
		targetSourceFile = program.GetSourceFile(req.FileName)
		if targetSourceFile == nil {
			return &api.GetAstInfoResponse{}, nil
		}
	} else {
		targetSourceFile = userSourceFile
	}

	isExternalFile := targetSourceFile != userSourceFile

	// Build the response
	// Use userSourceFile as the "current" file for the builder
	// This determines which files are considered "external" (fileName will be set for nodes not in userSourceFile)
	builder := api.NewAstInfoBuilder(typeChecker, userSourceFile)
	response := &api.GetAstInfoResponse{}

	// Special case: if requesting SourceFile by kind, build it directly without Node conversion
	if req.Kind > 0 && ast.Kind(req.Kind) == ast.KindSourceFile {
		response.Node = builder.BuildSourceFileNodeInfo(targetSourceFile)
		// SourceFile doesn't have type/symbol/signature/flow, so return early
		return response, nil
	}

	// Find the node at the specified position (with optional end for exact matching)
	node := inspector.FindNodeAtPosition(targetSourceFile, req.Position, req.End, req.Kind)
	if node == nil {
		return &api.GetAstInfoResponse{}, nil
	}

	// Build node info
	response.Node = builder.BuildNodeInfo(node)

	// Build type info
	t := inspector.GetTypeAtNode(typeChecker, node)
	if t != nil {
		response.Type = builder.BuildTypeInfo(t)
	}

	// Build symbol info
	// First try to get symbol directly from node
	symbol := typeChecker.GetSymbolAtLocation(node)
	// If no symbol at node, try to get it from the type
	if symbol == nil && t != nil {
		symbol = t.Symbol()
	}
	if symbol != nil {
		response.Symbol = builder.BuildSymbolInfo(symbol)
	}

	// Build signature info
	sig := inspector.GetSignatureOfNode(typeChecker, node)
	if sig != nil {
		response.Signature = builder.BuildSignatureInfo(sig)
	}

	// Build flow info (only for nodes in user's source file)
	if !isExternalFile {
		flowNode := inspector.GetFlowNodeOfNode(node)
		if flowNode != nil {
			response.Flow = builder.BuildFlowInfo(flowNode)
		}
	}

	return response, nil
}

// getCachedProgram returns the cached program if it matches the current request
func getCachedProgram(fileContent, compilerOptionsJSON string) (*compiler.Program, *ast.SourceFile) {
	astInfoProgramCache.mu.RLock()
	defer astInfoProgramCache.mu.RUnlock()

	if astInfoProgramCache.program == nil {
		return nil, nil
	}

	// Check if cache is valid (only fileContent and compilerOptions matter)
	if astInfoProgramCache.fileContent == fileContent &&
		astInfoProgramCache.compilerOptions == compilerOptionsJSON {
		return astInfoProgramCache.program, astInfoProgramCache.sourceFile
	}

	return nil, nil
}

// createAndCacheProgram creates a new program and caches it
func createAndCacheProgram(fileName, fileContent, compilerOptionsJSON string, compilerOptions map[string]any) (*compiler.Program, *ast.SourceFile, error) {
	// Create a virtual filesystem with the provided file content
	fs := bundled.WrapFS(cachedvfs.From(osvfs.FS()))

	fileContents := map[string]string{
		fileName: fileContent,
	}
	fs = utils.NewOverlayVFS(fs, fileContents)

	// Build tsconfig from request options or use defaults
	tsconfigContent := buildTsConfigContent(fileName, compilerOptions)
	tsconfigPath := "/tsconfig.json"
	fs = utils.NewOverlayVFS(fs, map[string]string{
		tsconfigPath: tsconfigContent,
	})

	// Create compiler host and program
	host := utils.CreateCompilerHost("/", fs)
	program, err := utils.CreateProgram(false, fs, "/", tsconfigPath, host)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create program: %w", err)
	}

	// Get the source file
	sourceFile := program.GetSourceFile(fileName)
	if sourceFile == nil {
		return nil, nil, errors.New("failed to get source file")
	}

	// Update cache
	astInfoProgramCache.mu.Lock()
	astInfoProgramCache.fileContent = fileContent
	astInfoProgramCache.compilerOptions = compilerOptionsJSON
	astInfoProgramCache.program = program
	astInfoProgramCache.sourceFile = sourceFile
	astInfoProgramCache.mu.Unlock()

	return program, sourceFile, nil
}

// buildTsConfigContent creates a tsconfig.json content string from compiler options
func buildTsConfigContent(fileName string, compilerOptions map[string]any) string {
	// Default compiler options
	opts := map[string]any{
		"target":           "ESNext",
		"module":           "ESNext",
		"strict":           true,
		"strictNullChecks": true,
	}

	// Merge with provided options (provided options override defaults)
	for k, v := range compilerOptions {
		opts[k] = v
	}

	// Serialize compiler options to JSON
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		// Fallback to minimal config on error
		return fmt.Sprintf(`{"compilerOptions":{"target":"ESNext","module":"ESNext","strict":true},"files":["%s"]}`, fileName)
	}

	return fmt.Sprintf(`{"compilerOptions":%s,"files":["%s"]}`, string(optsJSON), fileName)
}

// runAPI runs the linter in IPC mode
func runAPI() int {
	handler := &IPCHandler{}
	service := api.NewService(os.Stdin, os.Stdout, handler)

	if err := service.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error in IPC mode: %v\n", err)
		return 1
	}
	return 0
}
