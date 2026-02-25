package rules

import (
	"sort"

	"gopkg.in/yaml.v3"
)

// RulesConfig represents the complete rules configuration file structure.
// It contains global settings, rules that match specific CRs, global rules
// that apply to all CRs, and count rules for aggregate checks.
type RulesConfig struct {
	Version              string               `yaml:"version"`
	Description          string               `yaml:"description"`
	Settings             Settings             `yaml:"settings"`
	LabelAnnotationRules LabelAnnotationRules `yaml:"label_annotation_rules"`
	GlobalRules          []Rule               `yaml:"global_rules"`
	Rules                []Rule               `yaml:"rules"`
	CountRules           []CountRule          `yaml:"count_rules"`
}

// LabelAnnotationRules defines how labels and annotations should be evaluated.
// Labels/annotations matching rules in the lists use their specified impact,
// everything else gets the default impact (typically NotADeviation).
type LabelAnnotationRules struct {
	// Labels is a list of label rules to evaluate.
	Labels []LabelAnnotationRule `yaml:"labels"`
	// Annotations is a list of annotation rules to evaluate.
	Annotations []LabelAnnotationRule `yaml:"annotations"`
	// DefaultImpact is the impact for labels/annotations not matching any rule.
	DefaultImpact string `yaml:"default_impact"`
	// DefaultComment is the comment for labels/annotations not matching any rule.
	DefaultComment string `yaml:"default_comment"`
}

// LabelAnnotationRule defines a single rule for matching labels or annotations.
type LabelAnnotationRule struct {
	// Key is the label/annotation key pattern (required, supports glob).
	Key string `yaml:"key"`
	// Value is the label/annotation value pattern (optional, supports glob).
	// If omitted, matches any value.
	Value string `yaml:"value,omitempty"`
	// ValueRegex is a regular expression pattern for matching values (optional).
	// Takes precedence over Value when specified.
	ValueRegex string `yaml:"value_regex,omitempty"`
	// Description explains the impact of this label/annotation (required).
	Description string `yaml:"description"`
	// Impact determines the severity when this rule matches (required, supports versioning).
	Impact VersionedImpact `yaml:"impact"`
}

// Settings contains global configuration options for the rule engine.
type Settings struct {
	// DefaultImpact is used when no rule matches a diff (e.g., "NeedsReview").
	DefaultImpact string `yaml:"default_impact"`
	// DefaultSeverity is used for categorizing issues (e.g., "MEDIUM").
	DefaultSeverity string `yaml:"default_severity"`
}

// Rule represents a single validation rule that can match specific CRs
// and evaluate conditions against their diffs.
type Rule struct {
	// ID is a unique identifier for the rule (e.g., "R001-network-diagnostics").
	ID string `yaml:"id"`
	// Description explains what this rule validates.
	Description string `yaml:"description"`
	// Match defines which CRs this rule applies to.
	Match Match `yaml:"match"`
	// Conditions are the checks performed when this rule matches.
	Conditions []Condition `yaml:"conditions"`
}

// Match defines the criteria for selecting which CRs a rule applies to.
// Both fields support glob-style wildcards (*).
type Match struct {
	// TemplateFileName matches the reference template filename.
	TemplateFileName string `yaml:"templateFileName"`
	// CRName matches the Custom Resource identifier.
	CRName string `yaml:"crName"`
}

// Condition defines a specific check within a rule.
// Each condition looks for patterns in diff output and assigns an impact.
type Condition struct {
	// Type specifies which diff section to check:
	//   - "Any": all sections (FoundNotExpected, ExpectedNotFound, FoundValue)
	//   - "FoundNotExpected": lines found but not in template
	//   - "ExpectedNotFound": lines in template but not found
	//   - "ExpectedFound": value differences (checks FoundValue)
	Type string `yaml:"type"`

	// Contains is a simple substring match (can be multiline).
	Contains string `yaml:"contains,omitempty"`

	// Regex is a regular expression pattern (takes precedence over Contains).
	Regex string `yaml:"regex,omitempty"`

	// Impact determines the severity when this condition matches.
	// Can be a simple string or version-specific map.
	Impact VersionedImpact `yaml:"impact"`

	// Comment explains the impact and provides guidance.
	Comment string `yaml:"comment"`

	// SupportingDoc is an optional URL to documentation explaining this condition.
	SupportingDoc string `yaml:"supporting_doc,omitempty"`
}

// EvaluationResult represents the outcome of evaluating a diff against all rules.
type EvaluationResult struct {
	// Matched is true if at least one rule condition matched.
	Matched bool
	// RuleID is the identifier of the primary matching rule.
	RuleID string
	// Impact is the overall impact level (worst of all matching conditions).
	Impact string
	// Comment provides context about the evaluation result.
	Comment string
	// Conditions contains the results of individual condition evaluations.
	Conditions []ConditionResult
}

// ConditionResult represents the outcome of evaluating a single condition.
type ConditionResult struct {
	// RuleID identifies which rule this condition belongs to.
	RuleID string
	// ConditionType is the type of diff section that was checked.
	ConditionType string
	// Matched is true if the condition's pattern was found.
	Matched bool
	// Impact is the impact level of this condition.
	Impact string
	// Comment provides context about this condition.
	Comment string
	// MatchedText is the actual text that matched the pattern.
	MatchedText string
	// SupportingDoc is an optional URL to documentation for this condition.
	SupportingDoc string
}

// CountRule defines a rule that checks the number of matching CRs.
// Useful for enforcing policies like "only one CatalogSource allowed".
type CountRule struct {
	// ID is a unique identifier for the count rule.
	ID string `yaml:"id"`
	// Description explains what this count rule validates.
	Description string `yaml:"description"`
	// Match defines which CRs to count.
	Match Match `yaml:"match"`
	// Limits are the conditions based on count thresholds.
	Limits []CountLimit `yaml:"limits"`
}

// CountLimit defines a condition based on the count of matching CRs.
type CountLimit struct {
	// Condition is an expression like "count > 1" or "count == 0".
	Condition string `yaml:"condition"`
	// Impact is the severity when this limit is violated.
	Impact VersionedImpact `yaml:"impact"`
	// Comment explains the violation. Supports {count} placeholder.
	Comment string `yaml:"comment"`
	// SupportingDoc is an optional URL to documentation explaining this limit.
	SupportingDoc string `yaml:"supporting_doc,omitempty"`
}

// CountRuleResult represents the outcome of evaluating a count rule.
type CountRuleResult struct {
	// RuleID identifies the count rule.
	RuleID string
	// Description explains what was checked.
	Description string
	// Matched is true if a limit condition was triggered.
	Matched bool
	// Count is the number of CRs that matched the pattern.
	Count int
	// Impact is the impact level of the violated limit.
	Impact string
	// Comment provides context, with {count} replaced.
	Comment string
	// MatchedCRs lists the CR names that matched.
	MatchedCRs []string
	// SupportingDoc is an optional URL to documentation for this rule.
	SupportingDoc string
}

// MissingCRResult represents the evaluation result for a missing CR.
type MissingCRResult struct {
	// TemplatePath is the full path to the missing template.
	TemplatePath string
	// Basename is the template filename without path.
	Basename string
	// Impact indicates severity: "Impacting", "NotImpacting", or "NeedsReview".
	Impact string
	// GroupName is the validation group (e.g., "required-sriov").
	GroupName string
	// DeviationName is the specific deviation within the group.
	DeviationName string
	// IsOneOfRequired is true for "one of the following is required" groups.
	IsOneOfRequired bool
}

// LabelAnnotationResult represents the evaluation result for a label or annotation.
type LabelAnnotationResult struct {
	// Key is the label or annotation key.
	Key string
	// Value is the label or annotation value.
	Value string
	// Type is either "label" or "annotation".
	Type string
	// Impact is the evaluated impact level.
	Impact string
	// Comment provides context about the evaluation.
	Comment string
	// IsImpacting is true if this label/annotation is in the impacting list.
	IsImpacting bool
}

// VersionedImpact represents an impact value that can be either a simple string
// or a version-specific map. This allows rules to have different impacts for
// different OCP versions.
//
// Example YAML:
//
//	# Simple string (backward compatible)
//	impact: "NotImpacting"
//
//	# Versioned map
//	impact:
//	  4.19: Impacting
//	  4.20: NotImpacting
type VersionedImpact struct {
	// Simple is used when impact is a plain string.
	Simple string
	// VersionMap is used when impact varies by OCP version.
	VersionMap map[string]string
	// IsVersioned is true when VersionMap is used.
	IsVersioned bool
}

// UnmarshalYAML implements custom unmarshaling for VersionedImpact.
// It handles both simple string values and version-keyed maps.
func (v *VersionedImpact) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		v.Simple = value.Value
		v.IsVersioned = false
		return nil
	}

	if value.Kind == yaml.MappingNode {
		v.VersionMap = make(map[string]string)
		if err := value.Decode(&v.VersionMap); err != nil {
			return err
		}
		v.IsVersioned = true
		return nil
	}

	return nil
}

// ResolveImpact returns the appropriate impact string for a given target OCP version.
// For simple impacts, returns the simple value.
// For versioned impacts, uses smart inheritance:
//   - Exact version match uses that impact
//   - Otherwise, inherits from highest version <= target
//   - If target is below all versions, inherits from lowest defined version
func (v VersionedImpact) ResolveImpact(target OCPVersion) string {
	if !v.IsVersioned {
		return v.Simple
	}

	// Parse and sort all defined versions.
	var definedVersions []OCPVersion
	for versionStr := range v.VersionMap {
		parsed, err := ParseOCPVersion(versionStr)
		if err != nil {
			continue
		}
		definedVersions = append(definedVersions, parsed)
	}

	if len(definedVersions) == 0 {
		return v.Simple
	}

	sort.Slice(definedVersions, func(i, j int) bool {
		return definedVersions[i].Compare(definedVersions[j]) < 0
	})

	// Find the highest version <= target.
	for i := len(definedVersions) - 1; i >= 0; i-- {
		if definedVersions[i].Compare(target) <= 0 {
			return v.VersionMap[definedVersions[i].String()]
		}
	}

	// Target is below all defined versions - use lowest.
	return v.VersionMap[definedVersions[0].String()]
}

// GetHighestDefinedVersion returns the highest version in a versioned impact.
// Returns a zero OCPVersion if not versioned or no valid versions exist.
func (v VersionedImpact) GetHighestDefinedVersion() OCPVersion {
	if !v.IsVersioned {
		return OCPVersion{}
	}

	var highest OCPVersion
	for versionStr := range v.VersionMap {
		parsed, err := ParseOCPVersion(versionStr)
		if err != nil {
			continue
		}
		if parsed.Compare(highest) > 0 {
			highest = parsed
		}
	}
	return highest
}
