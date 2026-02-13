package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/microsoft/typescript-go/shim/tspath"
	importPlugin "github.com/web-infra-dev/rslint/internal/plugins/import"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/adjacent_overload_signatures"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/array_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/await_thenable"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/ban_ts_comment"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/ban_tslint_comment"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/ban_types"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/class_literal_property_style"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/class_methods_use_this"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_generic_constructors"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_indexed_object_style"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_return"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_type_assertions"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_type_definitions"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_type_exports"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/consistent_type_imports"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/default_param_last"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/dot_notation"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/explicit_function_return_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/explicit_member_accessibility"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/explicit_module_boundary_types"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/init_declarations"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/max_params"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/member_ordering"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/method_signature_style"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/naming_convention"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_array_constructor"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_array_delete"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_base_to_string"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_confusing_non_null_assertion"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_confusing_void_expression"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_deprecated"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_dupe_class_members"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_duplicate_enum_values"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_duplicate_type_constituents"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_dynamic_delete"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_empty_function"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_empty_interface"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_empty_object_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_explicit_any"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_extra_non_null_assertion"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_extraneous_class"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_floating_promises"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_for_in_array"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_implied_eval"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_import_type_side_effects"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_inferrable_types"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_invalid_this"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_invalid_void_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_loop_func"
	ts_no_loss_of_precision "github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_loss_of_precision"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_magic_numbers"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_meaningless_void_operator"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_misused_new"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_misused_promises"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_misused_spread"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_mixed_enums"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_namespace"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_non_null_asserted_nullish_coalescing"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_non_null_asserted_optional_chain"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_non_null_assertion"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_redeclare"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_redundant_type_constituents"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_require_imports"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_restricted_imports"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_restricted_types"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_shadow"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_this_alias"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_type_alias"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_boolean_literal_compare"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_condition"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_parameter_property_assignment"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_qualifier"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_template_expression"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_type_arguments"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_type_assertion"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_type_constraint"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_type_conversion"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unnecessary_type_parameters"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_argument"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_assignment"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_call"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_declaration_merging"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_enum_comparison"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_function_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_member_access"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_return"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_type_assertion"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unsafe_unary_minus"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unused_expressions"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unused_private_class_members"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_unused_vars"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_use_before_define"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_useless_constructor"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_useless_empty_export"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_var_requires"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/no_wrapper_object_types"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/non_nullable_type_assertion_style"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/only_throw_error"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/parameter_properties"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_as_const"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_destructuring"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_enum_initializers"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_find"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_for_of"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_function_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_includes"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_literal_enum_member"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_namespace_keyword"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_nullish_coalescing"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_optional_chain"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_promise_reject_errors"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_readonly"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_readonly_parameter_types"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_reduce_type_parameter"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_regexp_exec"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_return_this_type"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_string_starts_ends_with"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/prefer_ts_expect_error"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/promise_function_async"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/related_getter_setter_pairs"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/require_array_sort_compare"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/require_await"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/restrict_plus_operands"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/restrict_template_expressions"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/return_await"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/sort_type_constituents"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/strict_boolean_expressions"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/switch_exhaustiveness_check"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/triple_slash_reference"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/typedef"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/unbound_method"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/unified_signatures"
	"github.com/web-infra-dev/rslint/internal/plugins/typescript/rules/use_unknown_in_catch_callback_variable"
	"github.com/web-infra-dev/rslint/internal/rule"
	"github.com/web-infra-dev/rslint/internal/rules/array_callback_return"
	"github.com/web-infra-dev/rslint/internal/rules/constructor_super"
	"github.com/web-infra-dev/rslint/internal/rules/for_direction"
	"github.com/web-infra-dev/rslint/internal/rules/getter_return"
	"github.com/web-infra-dev/rslint/internal/rules/no_async_promise_executor"
	"github.com/web-infra-dev/rslint/internal/rules/no_await_in_loop"
	"github.com/web-infra-dev/rslint/internal/rules/no_class_assign"
	"github.com/web-infra-dev/rslint/internal/rules/no_compare_neg_zero"
	"github.com/web-infra-dev/rslint/internal/rules/no_cond_assign"
	"github.com/web-infra-dev/rslint/internal/rules/no_const_assign"
	"github.com/web-infra-dev/rslint/internal/rules/no_constant_binary_expression"
	"github.com/web-infra-dev/rslint/internal/rules/no_constant_condition"
	"github.com/web-infra-dev/rslint/internal/rules/no_constructor_return"
	"github.com/web-infra-dev/rslint/internal/rules/no_debugger"
	"github.com/web-infra-dev/rslint/internal/rules/no_loss_of_precision"
	"github.com/web-infra-dev/rslint/internal/rules/no_sparse_arrays"
	"github.com/web-infra-dev/rslint/internal/rules/no_template_curly_in_string"
)

// RslintConfig represents the top-level configuration array
type RslintConfig []ConfigEntry

// ConfigEntry represents a single configuration entry in the rslint.json array
type ConfigEntry struct {
	Language        string           `json:"language"`
	Files           []string         `json:"files"`
	Ignores         []string         `json:"ignores,omitempty"` // List of file patterns to ignore
	LanguageOptions *LanguageOptions `json:"languageOptions,omitempty"`
	Rules           Rules            `json:"rules"`
	Plugins         []string         `json:"plugins,omitempty"` // List of plugin names
	ConfigDirectory string           `json:"-"`
}

// LanguageOptions contains language-specific configuration options
type LanguageOptions struct {
	ParserOptions *ParserOptions         `json:"parserOptions,omitempty"`
	Globals       map[string]interface{} `json:"globals,omitempty"`
}

type EcmaFeatures struct {
	GlobalReturn    bool `json:"globalReturn,omitempty"`
	JSX             bool `json:"jsx,omitempty"`
	GlobalReturnSet bool `json:"-"`
	JSXSet          bool `json:"-"`
}

// ProjectPaths represents project paths that can be either a single string or an array of strings
type ProjectPaths []string

// UnmarshalJSON implements custom JSON unmarshaling to support both string and string[] formats
func (p *ProjectPaths) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var singlePath string
	if err := json.Unmarshal(data, &singlePath); err == nil {
		*p = []string{singlePath}
		return nil
	}

	// If that fails, try to unmarshal as array of strings
	var paths []string
	if err := json.Unmarshal(data, &paths); err != nil {
		return err
	}
	*p = paths
	return nil
}

// ParserOptions contains parser-specific configuration
type ParserOptions struct {
	ProjectService            bool          `json:"projectService"`
	Project                   ProjectPaths  `json:"project,omitempty"`
	TsconfigRootDir           string        `json:"tsconfigRootDir,omitempty"`
	SourceType                string        `json:"sourceType,omitempty"`
	EcmaVersion               int           `json:"ecmaVersion,omitempty"`
	IsolatedDeclarations      bool          `json:"isolatedDeclarations,omitempty"`
	ExperimentalDecorators    bool          `json:"experimentalDecorators,omitempty"`
	EmitDecoratorMetadata     bool          `json:"emitDecoratorMetadata,omitempty"`
	JSXPragma                 string        `json:"jsxPragma,omitempty"`
	JSXFragmentName           string        `json:"jsxFragmentName,omitempty"`
	EcmaFeatures              *EcmaFeatures `json:"ecmaFeatures,omitempty"`
	ProjectServiceSet         bool          `json:"-"`
	IsolatedDeclarationsSet   bool          `json:"-"`
	ExperimentalDecoratorsSet bool          `json:"-"`
	EmitDecoratorMetadataSet  bool          `json:"-"`
}

// UnmarshalJSON keeps track of whether boolean fields were explicitly configured.
func (e *EcmaFeatures) UnmarshalJSON(data []byte) error {
	type ecmaFeaturesAlias EcmaFeatures
	var alias ecmaFeaturesAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*e = EcmaFeatures(alias)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, e.GlobalReturnSet = raw["globalReturn"]
	_, e.JSXSet = raw["jsx"]
	return nil
}

// UnmarshalJSON keeps track of whether boolean fields were explicitly configured.
func (p *ParserOptions) UnmarshalJSON(data []byte) error {
	type parserOptionsAlias ParserOptions
	var alias parserOptionsAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*p = ParserOptions(alias)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, p.ProjectServiceSet = raw["projectService"]
	_, p.IsolatedDeclarationsSet = raw["isolatedDeclarations"]
	_, p.ExperimentalDecoratorsSet = raw["experimentalDecorators"]
	_, p.EmitDecoratorMetadataSet = raw["emitDecoratorMetadata"]
	return nil
}

// Rules represents the rules configuration
// This can be extended to include specific rule configurations
type Rules map[string]interface{}

// Alternative: If you want type-safe rule configurations
type TypedRules struct {
	// Example rule configurations - extend as needed
	AdjacentOverloadSignatures         *RuleConfig `json:"@typescript-eslint/adjacent-overload-signatures,omitempty"`
	ArrayType                          *RuleConfig `json:"@typescript-eslint/array-type,omitempty"`
	ClassLiteralPropertyStyle          *RuleConfig `json:"@typescript-eslint/class-literal-property-style,omitempty"`
	NoArrayDelete                      *RuleConfig `json:"@typescript-eslint/no-array-delete,omitempty"`
	NoBaseToString                     *RuleConfig `json:"@typescript-eslint/no-base-to-string,omitempty"`
	NoForInArray                       *RuleConfig `json:"@typescript-eslint/no-for-in-array,omitempty"`
	NoImpliedEval                      *RuleConfig `json:"@typescript-eslint/no-implied-eval,omitempty"`
	OnlyThrowError                     *RuleConfig `json:"@typescript-eslint/only-throw-error,omitempty"`
	AwaitThenable                      *RuleConfig `json:"@typescript-eslint/await-thenable,omitempty"`
	NoConfusingVoidExpression          *RuleConfig `json:"@typescript-eslint/no-confusing-void-expression,omitempty"`
	NoDuplicateTypeConstituents        *RuleConfig `json:"@typescript-eslint/no-duplicate-type-constituents,omitempty"`
	NoFloatingPromises                 *RuleConfig `json:"@typescript-eslint/no-floating-promises,omitempty"`
	NoMeaninglessVoidOperator          *RuleConfig `json:"@typescript-eslint/no-meaningless-void-operator,omitempty"`
	NoMisusedPromises                  *RuleConfig `json:"@typescript-eslint/no-misused-promises,omitempty"`
	NoMisusedSpread                    *RuleConfig `json:"@typescript-eslint/no-misused-spread,omitempty"`
	NoMixedEnums                       *RuleConfig `json:"@typescript-eslint/no-mixed-enums,omitempty"`
	NoRedundantTypeConstituents        *RuleConfig `json:"@typescript-eslint/no-redundant-type-constituents,omitempty"`
	NoUnnecessaryBooleanLiteralCompare *RuleConfig `json:"@typescript-eslint/no-unnecessary-boolean-literal-compare,omitempty"`
	NoUnnecessaryTemplateExpression    *RuleConfig `json:"@typescript-eslint/no-unnecessary-template-expression,omitempty"`
	NoUnnecessaryTypeArguments         *RuleConfig `json:"@typescript-eslint/no-unnecessary-type-arguments,omitempty"`
	NoUnnecessaryTypeAssertion         *RuleConfig `json:"@typescript-eslint/no-unnecessary-type-assertion,omitempty"`
	NoUnsafeArgument                   *RuleConfig `json:"@typescript-eslint/no-unsafe-argument,omitempty"`
	NoUnsafeAssignment                 *RuleConfig `json:"@typescript-eslint/no-unsafe-assignment,omitempty"`
	NoUnsafeCall                       *RuleConfig `json:"@typescript-eslint/no-unsafe-call,omitempty"`
	NoUnsafeEnumComparison             *RuleConfig `json:"@typescript-eslint/no-unsafe-enum-comparison,omitempty"`
	NoUnsafeMemberAccess               *RuleConfig `json:"@typescript-eslint/no-unsafe-member-access,omitempty"`
	NoUnsafeReturn                     *RuleConfig `json:"@typescript-eslint/no-unsafe-return,omitempty"`
	NoUnsafeTypeAssertion              *RuleConfig `json:"@typescript-eslint/no-unsafe-type-assertion,omitempty"`
	NoUnsafeUnaryMinus                 *RuleConfig `json:"@typescript-eslint/no-unsafe-unary-minus,omitempty"`
}

// RuleConfig represents individual rule configuration
type RuleConfig struct {
	Level   string                 `json:"level,omitempty"`   // "error", "warn", "off"
	Options map[string]interface{} `json:"options,omitempty"` // Rule-specific options
}

const defaultJsonc = `
[
  {
    // ignore files and folders for linting
    "ignores": [],
    "languageOptions": {
      "parserOptions": {
        // Rslint will lint all files included in your typescript projects defined here
        // support lint multi packages in monorepo
        "project": ["./tsconfig.json"]
      }
    },
    // same configuration as https://typescript-eslint.io/rules/
    "rules": {
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/no-unnecessary-type-assertion": "warn",
      "@typescript-eslint/array-type": ["warn", { "default": "array-simple" }]
    },
    "plugins": [
      "@typescript-eslint" // will enable all implemented @typescript-eslint rules by default
    ]
  }
]
`

// IsEnabled returns true if the rule is enabled (not "off")
func (rc *RuleConfig) IsEnabled() bool {
	if rc == nil {
		return false
	}
	return rc.Level != "off" && rc.Level != ""
}

// GetLevel returns the rule level, defaulting to "error" if not specified
func (rc *RuleConfig) GetLevel() string {
	if rc == nil || rc.Level == "" {
		return "error"
	}
	return rc.Level
}

// GetOptions returns the rule options, ensuring we return a usable value
func (rc *RuleConfig) GetOptions() map[string]interface{} {
	if rc == nil || rc.Options == nil {
		return make(map[string]interface{})
	}
	return rc.Options
}

// SetOptions sets the rule options
func (rc *RuleConfig) SetOptions(options map[string]interface{}) {
	if rc != nil {
		rc.Options = options
	}
}

// GetSeverity returns the diagnostic severity for this rule configuration
func (rc *RuleConfig) GetSeverity() rule.DiagnosticSeverity {
	if rc == nil {
		return rule.SeverityError
	}
	return rule.ParseSeverity(rc.Level)
}
func GetAllRulesForPlugin(plugin string) []rule.Rule {
	switch plugin {
	case "@typescript-eslint":
		return getAllTypeScriptEslintPluginRules()
	case "eslint-plugin-import":
		return importPlugin.GetAllRules()
	case "eslint-plugin-import/recommended":
		return importPlugin.GetRecommendedRules()
	default:
		return []rule.Rule{} // Return empty slice for unsupported plugins
	}
}

// parseArrayRuleConfig parses array-style rule configuration like ["error", {...options}]
// Supports ESLint-compatible formats:
// - ["off"] -> disabled rule
// - ["error"] -> enabled rule with error severity
// - ["warn"] -> enabled rule with warning severity
// - ["error", {...options}] -> enabled rule with error severity and options
// - ["warn", {...options}] -> enabled rule with warning severity and options
func parseArrayRuleConfig(ruleArray []interface{}) *RuleConfig {
	if len(ruleArray) == 0 {
		return nil
	}

	// First element should always be the severity level
	level, ok := ruleArray[0].(string)
	if !ok {
		return nil
	}

	ruleConfig := &RuleConfig{Level: level}

	// Second element (if present) should be the options object
	if len(ruleArray) > 1 {
		switch opts := ruleArray[1].(type) {
		case map[string]interface{}:
			ruleConfig.Options = opts
		case nil:
			// Explicitly null/nil options are valid
			ruleConfig.Options = make(map[string]interface{})
		default:
			// Invalid options type, but still create the rule config with just the level
			ruleConfig.Options = make(map[string]interface{})
		}
	}

	// Additional elements are ignored (following ESLint behavior)
	return ruleConfig
}

// GetRulesForFile returns enabled rules for a given file based on the configuration
func (config RslintConfig) GetRulesForFile(filePath string) map[string]*RuleConfig {
	enabledRules := make(map[string]*RuleConfig)

	for _, entry := range config {
		if !configEntryMatchesFile(entry, filePath) {
			continue
		}

		/// Merge rules from plugin
		for _, plugin := range entry.Plugins {
			for _, rule := range GetAllRulesForPlugin(plugin) {
				enabledRules[rule.Name] = &RuleConfig{Level: "error"} // Default level for plugin rules
			}
		}
		// Merge rules from this entry
		for ruleName, ruleValue := range entry.Rules {
			switch v := ruleValue.(type) {
			case string:
				// Handle simple string values like "error", "warn", "off"
				enabledRules[ruleName] = &RuleConfig{Level: v}
			case map[string]interface{}:
				// Handle object configuration
				ruleConfig := &RuleConfig{}
				if level, ok := v["level"].(string); ok {
					ruleConfig.Level = level
				}
				if options, ok := v["options"].(map[string]interface{}); ok {
					ruleConfig.Options = options
				}
				if ruleConfig.IsEnabled() {
					enabledRules[ruleName] = ruleConfig
				}
			case []interface{}:
				// Handle array format like ["error", {...options}] or ["warn"] or ["off"]
				ruleConfig := parseArrayRuleConfig(v)
				if ruleConfig != nil && ruleConfig.IsEnabled() {
					enabledRules[ruleName] = ruleConfig
				}
			}
		}
	}
	return enabledRules
}

func RegisterAllRules() {
	registerAllTypeScriptEslintPluginRules()
	registerAllEslintImportPluginRules()
	registerAllCoreEslintRules()
}

// registerAllTypeScriptEslintPluginRules registers all available rules in the global registry
func registerAllTypeScriptEslintPluginRules() {
	GlobalRuleRegistry.Register("@typescript-eslint/adjacent-overload-signatures", adjacent_overload_signatures.AdjacentOverloadSignaturesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/array-type", array_type.ArrayTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/await-thenable", await_thenable.AwaitThenableRule)
	GlobalRuleRegistry.Register("@typescript-eslint/ban-ts-comment", ban_ts_comment.BanTsCommentRule)
	GlobalRuleRegistry.Register("@typescript-eslint/ban-tslint-comment", ban_tslint_comment.BanTslintCommentRule)
	GlobalRuleRegistry.Register("@typescript-eslint/ban-types", ban_types.BanTypesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/class-methods-use-this", class_methods_use_this.ClassMethodsUseThisRule)
	GlobalRuleRegistry.Register("@typescript-eslint/class-literal-property-style", class_literal_property_style.ClassLiteralPropertyStyleRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-generic-constructors", consistent_generic_constructors.ConsistentGenericConstructorsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-indexed-object-style", consistent_indexed_object_style.ConsistentIndexedObjectStyleRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-return", consistent_return.ConsistentReturnRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-type-assertions", consistent_type_assertions.ConsistentTypeAssertionsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-type-definitions", consistent_type_definitions.ConsistentTypeDefinitionsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-type-exports", consistent_type_exports.ConsistentTypeExportsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/consistent-type-imports", consistent_type_imports.ConsistentTypeImportsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/default-param-last", default_param_last.DefaultParamLastRule)
	GlobalRuleRegistry.Register("@typescript-eslint/dot-notation", dot_notation.DotNotationRule)
	GlobalRuleRegistry.Register("@typescript-eslint/explicit-member-accessibility", explicit_member_accessibility.ExplicitMemberAccessibilityRule)
	GlobalRuleRegistry.Register("@typescript-eslint/explicit-function-return-type", explicit_function_return_type.ExplicitFunctionReturnTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/explicit-module-boundary-types", explicit_module_boundary_types.ExplicitModuleBoundaryTypesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/init-declarations", init_declarations.InitDeclarationsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/max-params", max_params.MaxParamsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/member-ordering", member_ordering.MemberOrderingRule)
	GlobalRuleRegistry.Register("@typescript-eslint/member-ordering-alphabetically-order", member_ordering.MemberOrderingAlphabeticallyOrderAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/member-ordering-alphabetically-case-insensitive-order", member_ordering.MemberOrderingAlphabeticallyCaseInsensitiveOrderAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/member-ordering-natural-order", member_ordering.MemberOrderingNaturalOrderAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/member-ordering-natural-case-insensitive-order", member_ordering.MemberOrderingNaturalCaseInsensitiveOrderAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/member-ordering-required", member_ordering.MemberOrderingRequiredAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/method-signature-style", method_signature_style.MethodSignatureStyleRule)
	GlobalRuleRegistry.Register("@typescript-eslint/naming-convention", naming_convention.NamingConventionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-array-constructor", no_array_constructor.NoArrayConstructorRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-array-delete", no_array_delete.NoArrayDeleteRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-base-to-string", no_base_to_string.NoBaseToStringRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-confusing-non-null-assertion", no_confusing_non_null_assertion.NoConfusingNonNullAssertionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-confusing-void-expression", no_confusing_void_expression.NoConfusingVoidExpressionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-deprecated", no_deprecated.NoDeprecatedRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-duplicate-enum-values", no_duplicate_enum_values.NoDuplicateEnumValuesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-duplicate-type-constituents", no_duplicate_type_constituents.NoDuplicateTypeConstituentsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-dupe-class-members", no_dupe_class_members.NoDupeClassMembersRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-dynamic-delete", no_dynamic_delete.NoDynamicDeleteRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-explicit-any", no_explicit_any.NoExplicitAnyRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-empty-function", no_empty_function.NoEmptyFunctionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-empty-interface", no_empty_interface.NoEmptyInterfaceRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-empty-object-type", no_empty_object_type.NoEmptyObjectTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-extra-non-null-assertion", no_extra_non_null_assertion.NoExtraNonNullAssertionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-extraneous-class", no_extraneous_class.NoExtraneousClassRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-invalid-this", no_invalid_this.NoInvalidThisRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-invalid-void-type", no_invalid_void_type.NoInvalidVoidTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-loop-func", no_loop_func.NoLoopFuncRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-loss-of-precision", ts_no_loss_of_precision.NoLossOfPrecisionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-floating-promises", no_floating_promises.NoFloatingPromisesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-for-in-array", no_for_in_array.NoForInArrayRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-import-type-side-effects", no_import_type_side_effects.NoImportTypeSideEffectsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-implied-eval", no_implied_eval.NoImpliedEvalRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-inferrable-types", no_inferrable_types.NoInferrableTypesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-meaningless-void-operator", no_meaningless_void_operator.NoMeaninglessVoidOperatorRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-misused-new", no_misused_new.NoMisusedNewRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-misused-promises", no_misused_promises.NoMisusedPromisesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-misused-spread", no_misused_spread.NoMisusedSpreadRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-magic-numbers", no_magic_numbers.NoMagicNumbersRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-mixed-enums", no_mixed_enums.NoMixedEnumsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-namespace", no_namespace.NoNamespaceRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-non-null-asserted-nullish-coalescing", no_non_null_asserted_nullish_coalescing.NoNonNullAssertedNullishCoalescingRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-non-null-asserted-optional-chain", no_non_null_asserted_optional_chain.NoNonNullAssertedOptionalChainRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-non-null-assertion", no_non_null_assertion.NoNonNullAssertionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-redeclare", no_redeclare.NoRedeclareRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-redundant-type-constituents", no_redundant_type_constituents.NoRedundantTypeConstituentsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-restricted-imports", no_restricted_imports.NoRestrictedImportsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-restricted-types", no_restricted_types.NoRestrictedTypesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-shadow", no_shadow.NoShadowRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-this-alias", no_this_alias.NoThisAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-type-alias", no_type_alias.NoTypeAliasRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-require-imports", no_require_imports.NoRequireImportsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-condition", no_unnecessary_condition.NoUnnecessaryConditionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-boolean-literal-compare", no_unnecessary_boolean_literal_compare.NoUnnecessaryBooleanLiteralCompareRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-template-expression", no_unnecessary_template_expression.NoUnnecessaryTemplateExpressionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-type-constraint", no_unnecessary_type_constraint.NoUnnecessaryTypeConstraintRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-type-arguments", no_unnecessary_type_arguments.NoUnnecessaryTypeArgumentsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-type-assertion", no_unnecessary_type_assertion.NoUnnecessaryTypeAssertionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-qualifier", no_unnecessary_qualifier.NoUnnecessaryQualifierRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-type-conversion", no_unnecessary_type_conversion.NoUnnecessaryTypeConversionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-type-parameters", no_unnecessary_type_parameters.NoUnnecessaryTypeParametersRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unnecessary-parameter-property-assignment", no_unnecessary_parameter_property_assignment.NoUnnecessaryParameterPropertyAssignmentRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-argument", no_unsafe_argument.NoUnsafeArgumentRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-assignment", no_unsafe_assignment.NoUnsafeAssignmentRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-call", no_unsafe_call.NoUnsafeCallRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-enum-comparison", no_unsafe_enum_comparison.NoUnsafeEnumComparisonRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-member-access", no_unsafe_member_access.NoUnsafeMemberAccessRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-return", no_unsafe_return.NoUnsafeReturnRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-declaration-merging", no_unsafe_declaration_merging.NoUnsafeDeclarationMergingRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-function-type", no_unsafe_function_type.NoUnsafeFunctionTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-type-assertion", no_unsafe_type_assertion.NoUnsafeTypeAssertionRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unsafe-unary-minus", no_unsafe_unary_minus.NoUnsafeUnaryMinusRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unused-vars", no_unused_vars.NoUnusedVarsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unused-expressions", no_unused_expressions.NoUnusedExpressionsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-unused-private-class-members", no_unused_private_class_members.NoUnusedPrivateClassMembersRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-use-before-define", no_use_before_define.NoUseBeforeDefineRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-useless-empty-export", no_useless_empty_export.NoUselessEmptyExportRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-useless-constructor", no_useless_constructor.NoUselessConstructorRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-var-requires", no_var_requires.NoVarRequiresRule)
	GlobalRuleRegistry.Register("@typescript-eslint/no-wrapper-object-types", no_wrapper_object_types.NoWrapperObjectTypesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/non-nullable-type-assertion-style", non_nullable_type_assertion_style.NonNullableTypeAssertionStyleRule)
	GlobalRuleRegistry.Register("@typescript-eslint/only-throw-error", only_throw_error.OnlyThrowErrorRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-as-const", prefer_as_const.PreferAsConstRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-destructuring", prefer_destructuring.PreferDestructuringRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-enum-initializers", prefer_enum_initializers.PreferEnumInitializersRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-find", prefer_find.PreferFindRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-for-of", prefer_for_of.PreferForOfRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-function-type", prefer_function_type.PreferFunctionTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-includes", prefer_includes.PreferIncludesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-literal-enum-member", prefer_literal_enum_member.PreferLiteralEnumMemberRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-nullish-coalescing", prefer_nullish_coalescing.PreferNullishCoalescingRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-promise-reject-errors", prefer_promise_reject_errors.PreferPromiseRejectErrorsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-readonly", prefer_readonly.PreferReadonlyRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-readonly-parameter-types", prefer_readonly_parameter_types.PreferReadonlyParameterTypesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-regexp-exec", prefer_regexp_exec.PreferRegExpExecRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-optional-chain", prefer_optional_chain.PreferOptionalChainRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-reduce-type-parameter", prefer_reduce_type_parameter.PreferReduceTypeParameterRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-return-this-type", prefer_return_this_type.PreferReturnThisTypeRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-namespace-keyword", prefer_namespace_keyword.PreferNamespaceKeywordRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-string-starts-ends-with", prefer_string_starts_ends_with.PreferStringStartsEndsWithRule)
	GlobalRuleRegistry.Register("@typescript-eslint/prefer-ts-expect-error", prefer_ts_expect_error.PreferTsExpectErrorRule)
	GlobalRuleRegistry.Register("@typescript-eslint/promise-function-async", promise_function_async.PromiseFunctionAsyncRule)
	GlobalRuleRegistry.Register("@typescript-eslint/parameter-properties", parameter_properties.ParameterPropertiesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/related-getter-setter-pairs", related_getter_setter_pairs.RelatedGetterSetterPairsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/require-array-sort-compare", require_array_sort_compare.RequireArraySortCompareRule)
	GlobalRuleRegistry.Register("@typescript-eslint/require-await", require_await.RequireAwaitRule)
	GlobalRuleRegistry.Register("@typescript-eslint/restrict-plus-operands", restrict_plus_operands.RestrictPlusOperandsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/restrict-template-expressions", restrict_template_expressions.RestrictTemplateExpressionsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/return-await", return_await.ReturnAwaitRule)
	GlobalRuleRegistry.Register("@typescript-eslint/sort-type-constituents", sort_type_constituents.SortTypeConstituentsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/strict-boolean-expressions", strict_boolean_expressions.StrictBooleanExpressionsRule)
	GlobalRuleRegistry.Register("@typescript-eslint/switch-exhaustiveness-check", switch_exhaustiveness_check.SwitchExhaustivenessCheckRule)
	GlobalRuleRegistry.Register("@typescript-eslint/triple-slash-reference", triple_slash_reference.TripleSlashReferenceRule)
	GlobalRuleRegistry.Register("@typescript-eslint/typedef", typedef.TypedefRule)
	GlobalRuleRegistry.Register("@typescript-eslint/unbound-method", unbound_method.UnboundMethodRule)
	GlobalRuleRegistry.Register("@typescript-eslint/unified-signatures", unified_signatures.UnifiedSignaturesRule)
	GlobalRuleRegistry.Register("@typescript-eslint/use-unknown-in-catch-callback-variable", use_unknown_in_catch_callback_variable.UseUnknownInCatchCallbackVariableRule)
}

func registerAllEslintImportPluginRules() {
	for _, rule := range importPlugin.GetAllRules() {
		GlobalRuleRegistry.Register(rule.Name, rule)
	}
}

// registerAllCoreEslintRules registers core ESLint rules
func registerAllCoreEslintRules() {
	GlobalRuleRegistry.Register("array-callback-return", array_callback_return.ArrayCallbackReturnRule)
	GlobalRuleRegistry.Register("constructor-super", constructor_super.ConstructorSuperRule)
	GlobalRuleRegistry.Register("for-direction", for_direction.ForDirectionRule)
	GlobalRuleRegistry.Register("getter-return", getter_return.GetterReturnRule)
	GlobalRuleRegistry.Register("no-async-promise-executor", no_async_promise_executor.NoAsyncPromiseExecutorRule)
	GlobalRuleRegistry.Register("no-await-in-loop", no_await_in_loop.NoAwaitInLoopRule)
	GlobalRuleRegistry.Register("no-class-assign", no_class_assign.NoClassAssignRule)
	GlobalRuleRegistry.Register("no-compare-neg-zero", no_compare_neg_zero.NoCompareNegZeroRule)
	GlobalRuleRegistry.Register("no-cond-assign", no_cond_assign.NoCondAssignRule)
	GlobalRuleRegistry.Register("no-const-assign", no_const_assign.NoConstAssignRule)
	GlobalRuleRegistry.Register("no-constant-binary-expression", no_constant_binary_expression.NoConstantBinaryExpressionRule)
	GlobalRuleRegistry.Register("no-constant-condition", no_constant_condition.NoConstantConditionRule)
	GlobalRuleRegistry.Register("no-constructor-return", no_constructor_return.NoConstructorReturnRule)
	GlobalRuleRegistry.Register("no-debugger", no_debugger.NoDebuggerRule)
	GlobalRuleRegistry.Register("no-loss-of-precision", no_loss_of_precision.NoLossOfPrecisionRule)
	GlobalRuleRegistry.Register("no-template-curly-in-string", no_template_curly_in_string.NoTemplateCurlyInString)
	GlobalRuleRegistry.Register("no-sparse-arrays", no_sparse_arrays.NoSparseArraysRule)
}

// getAllTypeScriptEslintPluginRules returns all registered rules (for backward compatibility when no config is provided)
func getAllTypeScriptEslintPluginRules() []rule.Rule {
	allRules := GlobalRuleRegistry.GetAllRules()
	var rules []rule.Rule
	for _, rule := range allRules {
		rules = append(rules, rule)
	}
	return rules
}

// isFileIgnored checks if a file should be ignored based on ignore patterns
func isFileIgnored(filePath string, ignorePatterns []string) bool {
	baseDir := ""
	cwd, err := os.Getwd()
	if err == nil {
		baseDir = cwd
	}
	return isFileIgnoredWithBase(filePath, ignorePatterns, baseDir)
}

func isFileIgnoredWithBase(filePath string, ignorePatterns []string, baseDir string) bool {
	normalizedPath := filePath
	if baseDir != "" {
		normalizedPath = normalizePath(filePath, baseDir)
	}
	for _, pattern := range ignorePatterns {
		if patternMatchesFile(pattern, filePath, normalizedPath) {
			return true
		}
	}
	return false
}

// normalizePath converts file path to be relative to cwd for consistent matching
func normalizePath(filePath, cwd string) string {
	return tspath.NormalizePath(tspath.ConvertToRelativePath(filePath, tspath.ComparePathsOptions{
		UseCaseSensitiveFileNames: true,
		CurrentDirectory:          cwd,
	}))
}

// initialize a default config in the directory
func InitDefaultConfig(directory string) error {
	configPath := filepath.Join(directory, "rslint.jsonc")

	// if the config exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("rslint.json already exists in %s", directory)
	}

	// write file content
	err := os.WriteFile(configPath, []byte(defaultJsonc), 0644)
	if err != nil {
		return fmt.Errorf("failed to create rslint.json: %w", err)
	}

	return nil
}
