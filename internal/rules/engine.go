package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openshift-kni/rds-analyzer/internal/types"

	"gopkg.in/yaml.v3"
)

// Engine manages rule loading and evaluation against validation diffs.
// It supports version-specific impact resolution and maintains the loaded
// rule configuration for reuse across multiple evaluations.
type Engine struct {
	config        RulesConfig
	targetVersion OCPVersion
}

// NewEngine creates a new rule engine from a YAML file.
// When no target version is specified, it defaults to the highest version
// defined across all versioned impacts in the rules file.
func NewEngine(rulesFile string) (*Engine, error) {
	return NewEngineWithVersion(rulesFile, "")
}

// NewEngineWithVersion creates a new rule engine with a specific target OCP version.
// If version is empty, it defaults to the highest version defined in the rules.
func NewEngineWithVersion(rulesFile, version string) (*Engine, error) {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var config RulesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	engine := &Engine{config: config}

	if version != "" {
		parsed, err := ParseOCPVersion(version)
		if err != nil {
			return nil, fmt.Errorf("invalid OCP version %q: %w", version, err)
		}
		engine.targetVersion = parsed
	} else {
		engine.targetVersion = engine.findHighestDefinedVersion()
	}

	return engine, nil
}

// findHighestDefinedVersion scans all rules and returns the highest OCP version
// defined in any versioned impact.
func (e *Engine) findHighestDefinedVersion() OCPVersion {
	var highest OCPVersion

	for _, rule := range e.config.GlobalRules {
		for _, cond := range rule.Conditions {
			if v := cond.Impact.GetHighestDefinedVersion(); v.Compare(highest) > 0 {
				highest = v
			}
		}
	}

	for _, rule := range e.config.Rules {
		for _, cond := range rule.Conditions {
			if v := cond.Impact.GetHighestDefinedVersion(); v.Compare(highest) > 0 {
				highest = v
			}
		}
	}

	for _, rule := range e.config.CountRules {
		for _, limit := range rule.Limits {
			if v := limit.Impact.GetHighestDefinedVersion(); v.Compare(highest) > 0 {
				highest = v
			}
		}
	}

	return highest
}

// GetTargetVersion returns the target OCP version used for impact resolution.
func (e *Engine) GetTargetVersion() OCPVersion {
	return e.targetVersion
}

// Evaluate evaluates a DiffCheck against all applicable rules.
// It returns an EvaluationResult containing the overall impact and
// details about which conditions matched.
func (e *Engine) Evaluate(diffCheck types.DiffCheck) EvaluationResult {
	var allResults []EvaluationResult

	// Check specific rules that match this CR.
	for _, rule := range e.config.Rules {
		if e.matchesRule(rule, diffCheck) {
			result := e.evaluateRule(rule, diffCheck)
			if e.hasMatchedConditions(result) {
				allResults = append(allResults, result)
			}
		}
	}

	// Check global rules (apply to all CRs).
	for _, rule := range e.config.GlobalRules {
		result := e.evaluateRule(rule, diffCheck)
		if e.hasMatchedConditions(result) {
			allResults = append(allResults, result)
		}
	}

	// Evaluate labels and annotations if rules are configured.
	if e.HasLabelAnnotationRules() {
		labelResults := e.evaluateLabelsAndAnnotations(diffCheck)
		if e.hasMatchedConditions(labelResults) {
			allResults = append(allResults, labelResults)
		}
	}

	if len(allResults) > 0 {
		return e.mergeAllResults(allResults)
	}

	return EvaluationResult{
		Matched: false,
		Impact:  e.config.Settings.DefaultImpact,
		Comment: "No matching rule found",
	}
}

// evaluateLabelsAndAnnotations evaluates all label and annotation lines in a diff.
func (e *Engine) evaluateLabelsAndAnnotations(diffCheck types.DiffCheck) EvaluationResult {
	result := EvaluationResult{
		Matched:    false,
		RuleID:     "label-annotation-rules",
		Impact:     e.config.Settings.DefaultImpact,
		Conditions: []ConditionResult{},
	}

	// Use context-aware evaluation if available (includes section headers like labels:/annotations:).
	// Pass the target lines to filter which lines to actually match.
	// Fall back to plain lines if context is not available.

	// Evaluate FoundNotExpected (lines found but not in template).
	if len(diffCheck.FoundWithContext) > 0 {
		result.Conditions = append(result.Conditions,
			e.extractAndEvaluateLabelAnnotationsWithContext(
				diffCheck.FoundWithContext,
				diffCheck.FoundNotExpected,
				"FoundNotExpected")...)
	} else {
		result.Conditions = append(result.Conditions,
			e.extractAndEvaluateLabelAnnotations(diffCheck.FoundNotExpected, "FoundNotExpected")...)
	}

	// Evaluate ExpectedNotFound (lines in template but not found).
	if len(diffCheck.ExpectedWithContext) > 0 {
		result.Conditions = append(result.Conditions,
			e.extractAndEvaluateLabelAnnotationsWithContext(
				diffCheck.ExpectedWithContext,
				diffCheck.ExpectedNotFound,
				"ExpectedNotFound")...)
	} else {
		result.Conditions = append(result.Conditions,
			e.extractAndEvaluateLabelAnnotations(diffCheck.ExpectedNotFound, "ExpectedNotFound")...)
	}

	// Evaluate value differences (same key, different values).
	// Only evaluate FoundValue (actual cluster values), not ExpectedValue (template values).
	// For labels/annotations, we care about what's IN the cluster, not what's expected.
	if len(diffCheck.FoundValue) > 0 {
		if len(diffCheck.FoundWithContext) > 0 {
			result.Conditions = append(result.Conditions,
				e.extractAndEvaluateLabelAnnotationsWithContext(
					diffCheck.FoundWithContext,
					diffCheck.FoundValue,
					"ExpectedFound")...)
		} else {
			result.Conditions = append(result.Conditions,
				e.extractAndEvaluateLabelAnnotations(diffCheck.FoundValue, "ExpectedFound")...)
		}
	}

	result.Matched = e.hasAnyMatchedCondition(result.Conditions)

	if result.Matched {
		worstImpact, worstComment := e.findWorstImpact(result.Conditions)
		if worstImpact != "" {
			result.Impact = worstImpact
			result.Comment = worstComment
		}
	}

	return result
}

// extractAndEvaluateLabelAnnotationsWithContext processes lines with context to find and evaluate labels/annotations.
// It uses context lines to track section headers (labels:/annotations:) but only creates matches for lines
// that are both changed AND present in targetLines.
func (e *Engine) extractAndEvaluateLabelAnnotationsWithContext(contextLines []types.DiffLine, targetLines []string, conditionType string) []ConditionResult {
	var results []ConditionResult
	var currentType string
	var sectionIndent int = -1

	// Build a set of target line contents for fast lookup.
	targetSet := make(map[string]bool)
	for _, line := range targetLines {
		targetSet[strings.TrimSpace(line)] = true
	}

	defaultImpact, defaultComment := e.getLabelAnnotationDefaults()

	for _, diffLine := range contextLines {
		line := diffLine.Content
		trimmed := strings.TrimSpace(line)
		lineIndent := getIndentLevel(line)

		// Check for section headers in ALL lines (context and changed).
		if sectionType := e.detectSectionHeader(trimmed); sectionType != "" {
			currentType = sectionType
			sectionIndent = lineIndent
			// Only create a result for section headers that are in targetLines.
			if targetSet[trimmed] {
				results = append(results, e.createSectionHeaderResult(conditionType, defaultImpact, defaultComment, trimmed))
			}
			continue
		}

		// Check if we should exit the section based on indentation.
		if currentType != "" && lineIndent <= sectionIndent && trimmed != "" {
			currentType = ""
			sectionIndent = -1
		}

		// Only evaluate lines that are inside a labels/annotations section AND in targetLines.
		if currentType != "" && trimmed != "" && targetSet[trimmed] {
			if condResult := e.evaluateLabelAnnotationLine(trimmed, currentType, conditionType); condResult != nil {
				results = append(results, *condResult)
			}
		}
	}

	return results
}

// hasAnyMatchedCondition checks if any condition in the slice matched.
func (e *Engine) hasAnyMatchedCondition(conditions []ConditionResult) bool {
	for _, cond := range conditions {
		if cond.Matched {
			return true
		}
	}
	return false
}

// extractAndEvaluateLabelAnnotations processes lines to find and evaluate labels/annotations.
func (e *Engine) extractAndEvaluateLabelAnnotations(lines []string, conditionType string) []ConditionResult {
	var results []ConditionResult
	var currentType string
	var sectionIndent int = -1 // Indentation level of the section header (labels:/annotations:)

	defaultImpact, defaultComment := e.getLabelAnnotationDefaults()

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineIndent := getIndentLevel(line)

		if sectionType := e.detectSectionHeader(trimmed); sectionType != "" {
			currentType = sectionType
			sectionIndent = lineIndent
			results = append(results, e.createSectionHeaderResult(conditionType, defaultImpact, defaultComment, trimmed))
			continue
		}

		// If we're in a section, check if we should exit based on indentation.
		// Lines must be indented MORE than the section header to be part of it.
		if currentType != "" && lineIndent <= sectionIndent && trimmed != "" {
			currentType = ""
			sectionIndent = -1
		}

		if currentType != "" && trimmed != "" {
			if condResult := e.evaluateLabelAnnotationLine(trimmed, currentType, conditionType); condResult != nil {
				results = append(results, *condResult)
			}
		}
	}

	return results
}

// getIndentLevel returns the number of leading whitespace characters in a line.
func getIndentLevel(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' || ch == '\t' {
			count++
		} else {
			break
		}
	}
	return count
}

// getLabelAnnotationDefaults returns the default impact and comment settings.
func (e *Engine) getLabelAnnotationDefaults() (string, string) {
	defaultImpact := e.config.LabelAnnotationRules.DefaultImpact
	if defaultImpact == "" {
		defaultImpact = "NotADeviation"
	}

	defaultComment := e.config.LabelAnnotationRules.DefaultComment
	if defaultComment == "" {
		defaultComment = "Labels and annotations are acceptable"
	}

	return defaultImpact, defaultComment
}

// detectSectionHeader detects if a line is a section header and returns its type.
func (e *Engine) detectSectionHeader(trimmed string) string {
	if trimmed == "labels:" {
		return "label"
	}
	if trimmed == "annotations:" {
		return "annotation"
	}
	return ""
}

// createSectionHeaderResult creates a condition result for a section header.
func (e *Engine) createSectionHeaderResult(conditionType, defaultImpact, defaultComment, trimmed string) ConditionResult {
	return ConditionResult{
		RuleID:        "label-annotation-rules",
		ConditionType: conditionType,
		Matched:       true,
		Impact:        defaultImpact,
		Comment:       defaultComment,
		MatchedText:   trimmed,
	}
}

// evaluateLabelAnnotationLine evaluates a single label or annotation line.
func (e *Engine) evaluateLabelAnnotationLine(trimmed, currentType, conditionType string) *ConditionResult {
	key, value := parseSimpleKey(trimmed)
	if key == "" {
		return nil
	}

	laResult := e.EvaluateLabelOrAnnotation(key, value, currentType)
	return &ConditionResult{
		RuleID:        "label-annotation-rules",
		ConditionType: conditionType,
		Matched:       true,
		Impact:        laResult.Impact,
		Comment:       laResult.Comment,
		MatchedText:   trimmed,
	}
}

// parseSimpleKey extracts a key from a YAML-like line (key: value or key:).
// It strips surrounding quotes from values for easier rule matching.
func parseSimpleKey(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", ""
	}

	// Handle key: value format
	if idx := strings.Index(trimmed, ":"); idx > 0 {
		key := strings.TrimSpace(trimmed[:idx])
		value := ""
		if idx+1 < len(trimmed) {
			value = strings.TrimSpace(trimmed[idx+1:])
			// Strip surrounding quotes from value for easier matching
			if len(value) >= 2 {
				if (value[0] == '"' && value[len(value)-1] == '"') ||
					(value[0] == '\'' && value[len(value)-1] == '\'') {
					value = value[1 : len(value)-1]
				}
			}
		}
		return key, value
	}

	return "", ""
}

// mergeAllResults combines multiple rule evaluation results.
// The final impact is the worst (most critical) among all matches.
func (e *Engine) mergeAllResults(results []EvaluationResult) EvaluationResult {
	if len(results) == 0 {
		return EvaluationResult{
			Matched: false,
			Impact:  e.config.Settings.DefaultImpact,
			Comment: "No matching rule found",
		}
	}

	merged := EvaluationResult{
		Matched:    true,
		RuleID:     results[0].RuleID,
		Impact:     e.config.Settings.DefaultImpact,
		Conditions: []ConditionResult{},
	}

	var allConditions []ConditionResult
	for _, result := range results {
		for _, cond := range result.Conditions {
			if cond.Matched {
				allConditions = append(allConditions, cond)
			}
		}
	}

	merged.Conditions = e.deduplicateConditions(allConditions)

	worstImpact, worstComment := e.findWorstImpact(merged.Conditions)
	if worstImpact != "" {
		merged.Impact = worstImpact
		merged.Comment = worstComment
	}

	return merged
}

// findWorstImpact returns the most critical impact and its comment.
func (e *Engine) findWorstImpact(conditions []ConditionResult) (string, string) {
	worstImpact := ""
	worstComment := ""
	for _, cond := range conditions {
		if worstImpact == "" || e.isWorse(cond.Impact, worstImpact) {
			worstImpact = cond.Impact
			worstComment = cond.Comment
		}
	}
	return worstImpact, worstComment
}

// deduplicateConditions removes duplicate conditions, keeping the most critical.
func (e *Engine) deduplicateConditions(conditions []ConditionResult) []ConditionResult {
	conditionMap := make(map[string][]ConditionResult)

	for _, cond := range conditions {
		key := cond.ConditionType + ":" + strings.TrimSpace(cond.MatchedText)
		conditionMap[key] = append(conditionMap[key], cond)
	}

	var result []ConditionResult
	for _, group := range conditionMap {
		if len(group) == 1 {
			result = append(result, group[0])
		} else {
			worst := group[0]
			for _, cond := range group[1:] {
				if e.isWorse(cond.Impact, worst.Impact) {
					worst = cond
				}
			}
			result = append(result, worst)
		}
	}

	return result
}

// hasMatchedConditions checks if any conditions in the result matched.
func (e *Engine) hasMatchedConditions(result EvaluationResult) bool {
	for _, cond := range result.Conditions {
		if cond.Matched {
			return true
		}
	}
	return false
}

// matchesRule checks if a rule applies to the given diff.
func (e *Engine) matchesRule(rule Rule, diffCheck types.DiffCheck) bool {
	// Global rules (empty match) always apply.
	if rule.Match.TemplateFileName == "" && rule.Match.CRName == "" {
		return true
	}

	if rule.Match.TemplateFileName != "" {
		if !e.matchesPattern(rule.Match.TemplateFileName, diffCheck.TemplateFileName) {
			return false
		}
	}

	if rule.Match.CRName != "" {
		if !e.matchesPattern(rule.Match.CRName, diffCheck.CRName) {
			return false
		}
	}

	return true
}

// matchesPattern checks if a value matches a pattern with glob wildcards (*).
func (e *Engine) matchesPattern(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	// Convert glob to regex.
	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `.*`)
	regexPattern = "^" + regexPattern + "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// evaluateRule evaluates all conditions in a rule against a diff.
func (e *Engine) evaluateRule(rule Rule, diffCheck types.DiffCheck) EvaluationResult {
	result := EvaluationResult{
		Matched:    true,
		RuleID:     rule.ID,
		Impact:     e.config.Settings.DefaultImpact,
		Conditions: []ConditionResult{},
	}

	for _, condition := range rule.Conditions {
		condResults := e.evaluateCondition(condition, diffCheck, rule.ID)
		result.Conditions = append(result.Conditions, condResults...)
	}

	worstImpact, worstComment := e.findWorstImpact(result.Conditions)
	if worstImpact != "" {
		result.Impact = worstImpact
		result.Comment = worstComment
	}

	return result
}

// evaluateCondition evaluates a single condition against a diff.
// Returns a slice of ConditionResults, one for each matching line.
func (e *Engine) evaluateCondition(condition Condition, diffCheck types.DiffCheck, ruleID string) []ConditionResult {
	baseResult := ConditionResult{
		RuleID:        ruleID,
		ConditionType: condition.Type,
		Matched:       false,
		Impact:        condition.Impact.ResolveImpact(e.targetVersion),
		Comment:       condition.Comment,
		SupportingDoc: condition.SupportingDoc,
	}

	var results []ConditionResult

	switch condition.Type {
	case "Any":
		results = e.checkAnyCondition(baseResult, condition, diffCheck)
	case "FoundNotExpected":
		results = e.buildResultsFromMatches(baseResult, condition.Type, e.checkMatchAll(condition, diffCheck.FoundNotExpected))
	case "ExpectedNotFound":
		results = e.buildResultsFromMatches(baseResult, condition.Type, e.checkMatchAll(condition, diffCheck.ExpectedNotFound))
	case "ExpectedFound":
		results = e.buildResultsFromMatches(baseResult, condition.Type, e.checkMatchAll(condition, diffCheck.FoundValue))
	}

	// If no matches, return empty slice (not a single unmatched result)
	return results
}

// buildResultsFromMatches creates a ConditionResult for each matched text.
func (e *Engine) buildResultsFromMatches(base ConditionResult, condType string, matches []string) []ConditionResult {
	if len(matches) == 0 {
		return nil
	}

	results := make([]ConditionResult, len(matches))
	for i, match := range matches {
		results[i] = ConditionResult{
			RuleID:        base.RuleID,
			ConditionType: condType,
			Matched:       true,
			Impact:        base.Impact,
			Comment:       base.Comment,
			MatchedText:   match,
			SupportingDoc: base.SupportingDoc,
		}
	}
	return results
}

// checkAnyCondition checks all diff sections for the "Any" condition type.
// Returns a ConditionResult for each matching line across all sections.
func (e *Engine) checkAnyCondition(base ConditionResult, condition Condition, diffCheck types.DiffCheck) []ConditionResult {
	checks := []struct {
		lines []string
		typ   string
	}{
		{diffCheck.FoundNotExpected, "FoundNotExpected"},
		{diffCheck.ExpectedNotFound, "ExpectedNotFound"},
		{diffCheck.FoundValue, "ExpectedFound"},
	}

	var results []ConditionResult
	for _, check := range checks {
		matches := e.checkMatchAll(condition, check.lines)
		for _, match := range matches {
			results = append(results, ConditionResult{
				RuleID:        base.RuleID,
				ConditionType: check.typ,
				Matched:       true,
				Impact:        base.Impact,
				Comment:       base.Comment,
				MatchedText:   match,
				SupportingDoc: base.SupportingDoc,
			})
		}
	}
	return results
}

// checkMatch checks if a condition matches using regex or contains.
func (e *Engine) checkMatch(condition Condition, lines []string) (bool, string) {
	// Regex takes precedence.
	if condition.Regex != "" {
		return e.checkRegex(condition.Regex, lines)
	}

	if condition.Contains != "" {
		return e.checkContains(condition.Contains, lines)
	}

	return false, ""
}

// checkMatchAll returns all matching lines for a condition.
func (e *Engine) checkMatchAll(condition Condition, lines []string) []string {
	// Regex takes precedence.
	if condition.Regex != "" {
		return e.checkRegexAll(condition.Regex, lines)
	}

	if condition.Contains != "" {
		return e.checkContainsAll(condition.Contains, lines)
	}

	return nil
}

// checkContains checks if the search text is in any of the lines.
func (e *Engine) checkContains(searchText string, lines []string) (bool, string) {
	matches := e.checkContainsAll(searchText, lines)
	if len(matches) > 0 {
		return true, matches[0]
	}
	return false, ""
}

// checkContainsAll returns all lines containing the search text.
func (e *Engine) checkContainsAll(searchText string, lines []string) []string {
	if searchText == "" {
		return nil
	}

	// Multi-line matching - returns single match if found.
	if strings.Contains(searchText, "\n") {
		allText := strings.Join(lines, "\n")
		if strings.Contains(allText, searchText) {
			return []string{searchText}
		}

		searchLines := strings.Split(searchText, "\n")
		if e.containsMultilinePattern(lines, searchLines) {
			return []string{searchText}
		}

		return nil
	}

	// Single-line matching - collect all matching lines.
	searchText = strings.TrimSpace(searchText)
	var matches []string

	for _, line := range lines {
		if strings.Contains(strings.TrimSpace(line), searchText) {
			matches = append(matches, line)
		}
	}

	return matches
}

// checkRegex checks if any line matches the given regular expression.
func (e *Engine) checkRegex(pattern string, lines []string) (bool, string) {
	matches := e.checkRegexAll(pattern, lines)
	if len(matches) > 0 {
		return true, matches[0]
	}
	return false, ""
}

// checkRegexAll returns all lines matching the given regular expression.
func (e *Engine) checkRegexAll(pattern string, lines []string) []string {
	if pattern == "" {
		return nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var matches []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if match := re.FindString(trimmed); match != "" {
			// Return the full line for context, not just the match
			matches = append(matches, trimmed)
		}
	}

	return matches
}

// containsMultilinePattern checks if pattern lines exist in sequence.
func (e *Engine) containsMultilinePattern(textLines, patternLines []string) bool {
	cleanPattern := make([]string, 0, len(patternLines))
	for _, line := range patternLines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			cleanPattern = append(cleanPattern, trimmed)
		}
	}

	if len(cleanPattern) == 0 {
		return false
	}

	patternIdx := 0
	for _, textLine := range textLines {
		trimmedText := strings.TrimSpace(textLine)
		if trimmedText != "" && strings.Contains(trimmedText, cleanPattern[patternIdx]) {
			patternIdx++
			if patternIdx == len(cleanPattern) {
				return true
			}
		}
	}

	return false
}

// isWorse returns true if impact1 is more critical than impact2.
func (e *Engine) isWorse(impact1, impact2 string) bool {
	priority := map[string]int{
		"Impacting":     4,
		"NeedsReview":   3,
		"NotImpacting":  2,
		"NotADeviation": 1,
	}

	return priority[impact1] > priority[impact2]
}

// GetRules returns all loaded specific rules.
func (e *Engine) GetRules() []Rule {
	return e.config.Rules
}

// GetSettings returns the global settings.
func (e *Engine) GetSettings() Settings {
	return e.config.Settings
}

// GetCountRules returns all count rules.
func (e *Engine) GetCountRules() []CountRule {
	return e.config.CountRules
}

// EvaluateCountRules evaluates all count rules against a collection of DiffChecks.
func (e *Engine) EvaluateCountRules(diffChecks []types.DiffCheck) []CountRuleResult {
	var results []CountRuleResult

	for _, rule := range e.config.CountRules {
		result := e.evaluateCountRule(rule, diffChecks)
		if result.Matched {
			results = append(results, result)
		}
	}

	return results
}

// evaluateCountRule evaluates a single count rule.
func (e *Engine) evaluateCountRule(rule CountRule, diffChecks []types.DiffCheck) CountRuleResult {
	var matchedCRs []string
	for _, dc := range diffChecks {
		if e.matchesCountRule(rule, dc) {
			matchedCRs = append(matchedCRs, dc.CRName)
		}
	}

	count := len(matchedCRs)

	for _, limit := range rule.Limits {
		if e.evaluateCountCondition(limit.Condition, count) {
			comment := strings.ReplaceAll(limit.Comment, "{count}", fmt.Sprintf("%d", count))
			resolvedImpact := limit.Impact.ResolveImpact(e.targetVersion)

			return CountRuleResult{
				RuleID:        rule.ID,
				Description:   rule.Description,
				Matched:       true,
				Count:         count,
				Impact:        resolvedImpact,
				Comment:       comment,
				MatchedCRs:    matchedCRs,
				SupportingDoc: limit.SupportingDoc,
			}
		}
	}

	return CountRuleResult{
		RuleID:      rule.ID,
		Description: rule.Description,
		Matched:     false,
		Count:       count,
		MatchedCRs:  matchedCRs,
	}
}

// matchesCountRule checks if a DiffCheck matches the count rule's criteria.
func (e *Engine) matchesCountRule(rule CountRule, diffCheck types.DiffCheck) bool {
	if rule.Match.TemplateFileName != "" {
		if !e.matchesPattern(rule.Match.TemplateFileName, diffCheck.TemplateFileName) {
			return false
		}
	}

	if rule.Match.CRName != "" {
		if !e.matchesPattern(rule.Match.CRName, diffCheck.CRName) {
			return false
		}
	}

	return true
}

// evaluateCountCondition parses and evaluates count condition expressions.
// Supports: "count > N", "count >= N", "count < N", "count <= N", "count == N", "count != N"
func (e *Engine) evaluateCountCondition(condition string, count int) bool {
	condition = strings.TrimSpace(condition)

	patterns := []struct {
		op     string
		prefix string
	}{
		{">=", "count >="},
		{"<=", "count <="},
		{"!=", "count !="},
		{"==", "count =="},
		{">", "count >"},
		{"<", "count <"},
	}

	for _, p := range patterns {
		if strings.HasPrefix(condition, p.prefix) {
			valueStr := strings.TrimSpace(strings.TrimPrefix(condition, p.prefix))
			var value int
			if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
				return false
			}
			return e.compareValues(count, value, p.op)
		}
	}

	return false
}

// compareValues performs numeric comparison.
func (e *Engine) compareValues(count, value int, operator string) bool {
	switch operator {
	case ">":
		return count > value
	case ">=":
		return count >= value
	case "<":
		return count < value
	case "<=":
		return count <= value
	case "==":
		return count == value
	case "!=":
		return count != value
	default:
		return false
	}
}

// EvaluateMissingCRs evaluates all missing CRs from validation issues.
// Impact is derived from the JSON structure:
//   - Group names starting with "required-" -> Impacting
//   - Group names starting with "optional-" -> NotImpacting
//   - Other groups -> NeedsReview
func (e *Engine) EvaluateMissingCRs(issues types.ValidationIssues) map[string]MissingCRResult {
	results := make(map[string]MissingCRResult)

	for groupName, deviations := range issues {
		baseImpact := e.determineBaseImpact(groupName)

		for deviationName, deviation := range deviations {
			isOneOfRequired := strings.Contains(deviation.Msg, "One of the following is required")

			for _, crPath := range deviation.CRs {
				results[crPath] = MissingCRResult{
					TemplatePath:    crPath,
					Basename:        filepath.Base(crPath),
					Impact:          baseImpact,
					GroupName:       groupName,
					DeviationName:   deviationName,
					IsOneOfRequired: isOneOfRequired,
				}
			}
		}
	}

	return results
}

// determineBaseImpact determines impact from a group name prefix.
func (e *Engine) determineBaseImpact(groupName string) string {
	if strings.HasPrefix(groupName, "required-") {
		return "Impacting"
	}
	if strings.HasPrefix(groupName, "optional-") {
		return "NotImpacting"
	}
	return "NeedsReview"
}

// EvaluateLabelOrAnnotation evaluates a label or annotation against configured rules.
// It finds the most specific matching rule and returns its impact and description.
// If no rule matches, it returns the default impact and comment.
func (e *Engine) EvaluateLabelOrAnnotation(key, value, laType string) LabelAnnotationResult {
	rules := e.config.LabelAnnotationRules

	// Default values if not configured
	defaultImpact := rules.DefaultImpact
	if defaultImpact == "" {
		defaultImpact = "NotADeviation"
	}
	defaultComment := rules.DefaultComment
	if defaultComment == "" {
		defaultComment = "Labels and annotations are acceptable"
	}

	// Select the appropriate rule list based on type
	var ruleList []LabelAnnotationRule
	if laType == "label" {
		ruleList = rules.Labels
	} else if laType == "annotation" {
		ruleList = rules.Annotations
	}

	// Find all matching rules and track the most specific one
	var bestMatch *LabelAnnotationRule
	bestSpecificity := -1

	for i := range ruleList {
		rule := &ruleList[i]
		if !e.matchesLabelAnnotationPattern(rule.Key, key) {
			continue
		}

		// Check value matching: ValueRegex takes precedence over Value
		if rule.ValueRegex != "" {
			// Use regex matching for value
			if !e.matchesLabelAnnotationRegex(rule.ValueRegex, value) {
				continue
			}
		} else if rule.Value != "" {
			// Use glob pattern matching for value
			if !e.matchesLabelAnnotationPattern(rule.Value, value) {
				continue
			}
		}

		// Calculate specificity for this match
		specificity := e.calculateRuleSpecificity(rule, key, value)
		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestMatch = rule
		}
	}

	// If we found a matching rule, use its impact and description
	if bestMatch != nil {
		impact := bestMatch.Impact.ResolveImpact(e.targetVersion)
		return LabelAnnotationResult{
			Key:         key,
			Value:       value,
			Type:        laType,
			Impact:      impact,
			Comment:     bestMatch.Description,
			IsImpacting: impact == "Impacting" || impact == "NeedsReview",
		}
	}

	// No matching rule - use default
	return LabelAnnotationResult{
		Key:         key,
		Value:       value,
		Type:        laType,
		Impact:      defaultImpact,
		Comment:     defaultComment,
		IsImpacting: false,
	}
}

// calculateRuleSpecificity calculates a specificity score for a matching rule.
// Higher scores indicate more specific matches.
// Ranking (most to least specific):
//   - Exact key + exact value: 600 + bonus
//   - Exact key + regex value: 550 + bonus
//   - Exact key + glob value:  500 + bonus
//   - Exact key + any value:   400
//   - Glob key + exact value:  300 + bonus
//   - Glob key + regex value:  250 + bonus
//   - Glob key + glob value:   200 + bonus
//   - Glob key + any value:    100 + bonus
//
// Bonus points are added based on pattern length (fewer wildcards = higher score).
func (e *Engine) calculateRuleSpecificity(rule *LabelAnnotationRule, key, value string) int {
	isExactKey := !strings.Contains(rule.Key, "*")
	hasValue := rule.Value != ""
	hasValueRegex := rule.ValueRegex != ""
	isExactValue := hasValue && !strings.Contains(rule.Value, "*")

	var baseScore int
	if isExactKey {
		if isExactValue {
			baseScore = 600
		} else if hasValueRegex {
			baseScore = 550
		} else if hasValue {
			baseScore = 500
		} else {
			baseScore = 400
		}
	} else {
		if isExactValue {
			baseScore = 300
		} else if hasValueRegex {
			baseScore = 250
		} else if hasValue {
			baseScore = 200
		} else {
			baseScore = 100
		}
	}

	// Add bonus for longer literal prefixes (fewer wildcards = more specific)
	// Count non-wildcard characters as a tiebreaker
	keyLiteralLen := len(strings.ReplaceAll(rule.Key, "*", ""))
	valueLiteralLen := 0
	if hasValue {
		valueLiteralLen = len(strings.ReplaceAll(rule.Value, "*", ""))
	} else if hasValueRegex {
		// For regex, use the regex pattern length as a rough specificity indicator
		valueLiteralLen = len(rule.ValueRegex)
	}

	return baseScore + keyLiteralLen + valueLiteralLen
}

// matchesLabelAnnotationPattern checks if a key matches a pattern.
// Supports exact match and glob-style wildcards (*).
func (e *Engine) matchesLabelAnnotationPattern(pattern, key string) bool {
	// Exact match
	if pattern == key {
		return true
	}

	// Glob pattern matching
	if strings.Contains(pattern, "*") {
		regexPattern := regexp.QuoteMeta(pattern)
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, `.*`)
		regexPattern = "^" + regexPattern + "$"

		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(key)
	}

	return false
}

// matchesLabelAnnotationRegex checks if a value matches a regular expression pattern.
func (e *Engine) matchesLabelAnnotationRegex(pattern, value string) bool {
	if pattern == "" {
		return true
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// IsLabelAnnotationLine checks if a line is a label or annotation and returns its type.
// Returns the type ("label" or "annotation") and whether it's a label/annotation line.
func (e *Engine) IsLabelAnnotationLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)

	// Section headers
	if trimmed == "labels:" {
		return "label", true
	}
	if trimmed == "annotations:" {
		return "annotation", true
	}

	return "", false
}

// GetLabelAnnotationRules returns the label/annotation rules configuration.
func (e *Engine) GetLabelAnnotationRules() LabelAnnotationRules {
	return e.config.LabelAnnotationRules
}

// HasLabelAnnotationRules returns true if label/annotation rules are configured.
func (e *Engine) HasLabelAnnotationRules() bool {
	rules := e.config.LabelAnnotationRules
	return len(rules.Labels) > 0 || len(rules.Annotations) > 0 || rules.DefaultImpact != ""
}
