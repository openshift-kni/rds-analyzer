// Package report provides output generation for RDS analysis results.
// It supports multiple output formats including text (terminal) and HTML.
package report

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/openshift-kni/rds-analyzer/pkg/parser"
	"github.com/openshift-kni/rds-analyzer/pkg/rules"
	"github.com/openshift-kni/rds-analyzer/pkg/types"
)

// ANSI color codes for terminal output formatting.
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

// ansiRegex matches ANSI escape sequences for stripping from output.
var ansiRegex = regexp.MustCompile(`\033\[[0-9;]*m`)

// stripANSI removes all ANSI escape sequences from a string.
func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// TextGenerator produces text-based output suitable for terminal display.
// It includes ANSI color codes for enhanced readability.
type TextGenerator struct {
	ruleEngine *rules.Engine
	writer     io.Writer
}

// NewTextGenerator creates a new text report generator.
func NewTextGenerator(ruleEngine *rules.Engine) *TextGenerator {
	return &TextGenerator{
		ruleEngine: ruleEngine,
	}
}

// Generate writes the complete analysis report to the given writer.
func (g *TextGenerator) Generate(w io.Writer, report types.ValidationReport) error {
	g.writer = w

	// Show RDS variant and/or target version if set.
	variant := g.ruleEngine.GetRDSVariant()
	targetVersion := g.ruleEngine.GetTargetVersion()
	if variant != "" && !targetVersion.IsZero() {
		fmt.Fprintf(w, "Analyzing using %q RDS rules and target OCP version: %s\n\n", variant, targetVersion)
	} else if variant != "" {
		fmt.Fprintf(w, "Analyzing using %q RDS rules\n\n", variant)
	} else if !targetVersion.IsZero() {
		fmt.Fprintf(w, "Analyzing using target OCP version: %s\n\n", targetVersion)
	}

	g.printSummary(report.Summary)
	g.printMissingCRs(report.Summary.ValidationIssues, report.Diffs)
	g.printDiffs(report.Diffs)

	return nil
}

// printSummary outputs the high-level validation statistics.
func (g *TextGenerator) printSummary(summary types.Summary) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "               VALIDATION SUMMARY")
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintf(g.writer, "Total Missing CRs: %d - (CRs that were expected in the cluster but were not found)\n", summary.NumMissing)
	fmt.Fprintf(g.writer, "CRs with Differences: %d - (CRs that have differences between the expected and found configuration)\n", summary.NumDiffCRs)
	fmt.Fprintf(g.writer, "Total CRs Scanned: %d - (Total number of CRs that were scanned)\n", summary.TotalCRs)
	fmt.Fprintf(g.writer, "Unmatched CRs: %d - (CRs that were found in the cluster but do not match any RDS template)\n", len(summary.UnmatchedCRS))
	fmt.Fprintln(g.writer)
}

// printMissingCRs outputs the missing CRs section with impact evaluation.
func (g *TextGenerator) printMissingCRs(issues types.ValidationIssues, diffs []types.Diff) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "             MISSING CUSTOM RESOURCES")
	fmt.Fprintln(g.writer, "==================================================")

	if len(issues) == 0 {
		fmt.Fprintln(g.writer, "No missing CRs found.")
		fmt.Fprintln(g.writer)
		return
	}

	// Extract correlated templates and pre-evaluate all missing CRs.
	correlatedTemplates := rules.ExtractCorrelatedTemplates(diffs)
	missingCRResults := g.ruleEngine.EvaluateMissingCRs(issues, correlatedTemplates)

	// Track impact statistics.
	missingStats := map[string]int{
		"Impacting":    0,
		"NotImpacting": 0,
	}

	// Sort groups for consistent output.
	groupKeys := make([]string, 0, len(issues))
	for k := range issues {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)

	for _, groupName := range groupKeys {
		fmt.Fprintf(g.writer, "Group: %s\n", groupName)
		deviations := issues[groupName]

		// Sort deviations within group.
		deviationKeys := make([]string, 0, len(deviations))
		for k := range deviations {
			deviationKeys = append(deviationKeys, k)
		}
		sort.Strings(deviationKeys)

		for _, deviationName := range deviationKeys {
			deviation := deviations[deviationName]
			isOneOfRequired := strings.Contains(deviation.Msg, "One of the following is required")

			// Check if any CR in this deviation is satisfied.
			hasSatisfied := false
			if isOneOfRequired {
				for _, cr := range deviation.CRs {
					if missingCRResults[cr].IsSatisfied {
						hasSatisfied = true
						break
					}
				}
			}

			fmt.Fprintf(g.writer, "  - %s: %s\n", deviationName, deviation.Msg)

			// Show "🔴 None found" header when none of the alternatives are satisfied.
			if isOneOfRequired && !hasSatisfied {
				fmt.Fprintf(g.writer, "    🔴 None found\n")
			}

			for _, cr := range deviation.CRs {
				result := missingCRResults[cr]
				missingStats[result.Impact]++

				// Use extra indentation when showing "None found" header.
				indent := "    "
				if isOneOfRequired && !hasSatisfied {
					indent = "      "
				}

				if result.IsSatisfied {
					fmt.Fprintf(g.writer, "%s🟢 %s (satisfied)\n", indent, cr)
				} else {
					impactSymbol := getImpactSymbol(result.Impact)
					fmt.Fprintf(g.writer, "%s%s %s\n", indent, impactSymbol, cr)
				}
			}
		}
		fmt.Fprintln(g.writer)
	}

	// Print impact summary.
	fmt.Fprintln(g.writer, "--------------------------------------------------")
	fmt.Fprintln(g.writer, "Missing CRs Impact Summary:")
	fmt.Fprintf(g.writer, "  Impacting:     %d\n", missingStats["Impacting"])
	fmt.Fprintf(g.writer, "  Not Impacting: %d\n", missingStats["NotImpacting"])
	fmt.Fprintln(g.writer)
}

// evaluatedDiff holds a diff with its evaluation results for sorting.
type evaluatedDiff struct {
	diff        types.Diff
	diffCheck   types.DiffCheck
	ruleResult  rules.EvaluationResult
	finalImpact string
}

// printDiffs outputs the configuration differences section.
func (g *TextGenerator) printDiffs(diffs []types.Diff) {
	if len(diffs) == 0 {
		fmt.Fprintln(g.writer, "No differences detected.")
		return
	}

	// Track impact statistics.
	impactStats := map[string]int{
		"Impacting":     0,
		"NotImpacting":  0,
		"NotADeviation": 0,
		"NeedsReview":   0,
	}

	// Collect diffs for count rule evaluation.
	var allDiffChecks []types.DiffCheck

	// Pre-evaluate all diffs to determine their impact for sorting.
	var evaluatedDiffs []evaluatedDiff
	for _, d := range diffs {
		// Handle empty diffs - add minimal DiffCheck for count rules only.
		if d.DiffOutput == "" {
			allDiffChecks = append(allDiffChecks, minimalDiffCheck(d))
			continue
		}

		ed := evaluatedDiff{diff: d}
		formattedDiff := parser.ParseExpectedAndFound(d.DiffOutput, d.CRName, filepath.Base(d.CorrelatedTemplate))
		ed.diffCheck = formattedDiff
		ed.ruleResult = g.ruleEngine.Evaluate(formattedDiff)
		allDiffChecks = append(allDiffChecks, formattedDiff)

		// Determine final impact.
		hasNeedsReview := hasUnmatchedLines(formattedDiff, ed.ruleResult)
		ed.finalImpact = determineImpact(ed.ruleResult, hasNeedsReview)
		evaluatedDiffs = append(evaluatedDiffs, ed)
	}

	// Sort diffs by impact priority.
	sort.SliceStable(evaluatedDiffs, func(i, j int) bool {
		return getImpactPriority(evaluatedDiffs[i].finalImpact) < getImpactPriority(evaluatedDiffs[j].finalImpact)
	})

	// Evaluate and print count rule violations.
	countResults := g.ruleEngine.EvaluateCountRules(allDiffChecks)
	if len(countResults) > 0 {
		g.printCountRuleResults(countResults, impactStats)
	}

	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "              DETECTED DIFFERENCES")
	fmt.Fprintln(g.writer, "==================================================")

	// Print sorted diffs.
	for diffIndex, ed := range evaluatedDiffs {
		fmt.Fprintf(g.writer, "--- Diff %d of %d ---\n", diffIndex+1, len(evaluatedDiffs))
		fmt.Fprintf(g.writer, "CR Name: %s\n", ed.diff.CRName)
		fmt.Fprintf(g.writer, "Template: %s\n", ed.diff.CorrelatedTemplate)
		fmt.Fprintf(g.writer, "Description: %s\n", ed.diff.Description)
		fmt.Fprintln(g.writer, "---")

		g.printDiffCheck(ed.diffCheck, ed.ruleResult)
		impactStats[ed.finalImpact]++
		fmt.Fprintln(g.writer)
	}

	// Print summary statistics.
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "              IMPACT SUMMARY")
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintf(g.writer, "Impacting:      %d\n", impactStats["Impacting"])
	fmt.Fprintf(g.writer, "Not Impacting:  %d\n", impactStats["NotImpacting"])
	fmt.Fprintf(g.writer, "Needs Review:   %d\n", impactStats["NeedsReview"])
	fmt.Fprintf(g.writer, "Not a Deviation: %d\n", impactStats["NotADeviation"])
	fmt.Fprintln(g.writer)
}

// printCountRuleResults outputs count rule violations.
func (g *TextGenerator) printCountRuleResults(results []rules.CountRuleResult, impactStats map[string]int) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "              COUNT RULE VIOLATIONS")
	fmt.Fprintln(g.writer, "==================================================")

	for _, result := range results {
		impactColor := getImpactColor(result.Impact)
		impactSymbol := getImpactSymbol(result.Impact)

		fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", ColorBold, ColorReset)
		fmt.Fprintf(g.writer, "Rule: %s\n", result.RuleID)
		fmt.Fprintf(g.writer, "Description: %s\n", result.Description)
		fmt.Fprintf(g.writer, "Count: %d CRs matched\n", result.Count)
		fmt.Fprintf(g.writer, "Impact: %s%s %s%s\n", impactColor, impactSymbol, result.Impact, ColorReset)
		fmt.Fprintf(g.writer, "Comment: %s\n", result.Comment)

		if len(result.MatchedCRs) > 0 {
			fmt.Fprintln(g.writer, "Matched CRs:")
			for _, cr := range result.MatchedCRs {
				fmt.Fprintf(g.writer, "  - %s\n", cr)
			}
		}
		fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", ColorBold, ColorReset)
		fmt.Fprintln(g.writer)

		impactStats[result.Impact]++
	}
}

// printDiffCheck outputs a single diff with rule evaluation and returns the final impact.
func (g *TextGenerator) printDiffCheck(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) string {
	hasNeedsReview := false

	hasNeedsReview = g.printExpectedNotFoundLines(diffCheck, ruleResult) || hasNeedsReview
	hasNeedsReview = g.printFoundNotExpectedLines(diffCheck, ruleResult) || hasNeedsReview
	hasNeedsReview = g.printValueDifferences(diffCheck, ruleResult) || hasNeedsReview

	finalImpact := determineImpact(ruleResult, hasNeedsReview)
	fmt.Fprintln(g.writer)
	g.printOverallRuleResult(ruleResult, hasNeedsReview)

	return finalImpact
}

// printExpectedNotFoundLines outputs lines that were expected but not found.
func (g *TextGenerator) printExpectedNotFoundLines(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	if len(diffCheck.ExpectedNotFound) == 0 {
		return false
	}

	hasNeedsReview := false
	fmt.Fprintln(g.writer, "expected but not found:")
	for _, line := range diffCheck.ExpectedNotFound {
		ruleIDs := g.getMatchingRuleIDs(line, "ExpectedNotFound", ruleResult)
		if len(ruleIDs) == 0 {
			hasNeedsReview = true
		}
		fmt.Fprint(g.writer, ColorGreen+line+ColorReset)
		g.printRuleIDsSuffix(ruleIDs)
	}
	return hasNeedsReview
}

// printFoundNotExpectedLines outputs lines that were found but not expected.
func (g *TextGenerator) printFoundNotExpectedLines(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	if len(diffCheck.FoundNotExpected) == 0 {
		return false
	}

	hasNeedsReview := false
	fmt.Fprintln(g.writer, "found but not expected:")
	for _, line := range diffCheck.FoundNotExpected {
		ruleIDs := g.getMatchingRuleIDs(line, "FoundNotExpected", ruleResult)
		if len(ruleIDs) == 0 {
			hasNeedsReview = true
		}
		fmt.Fprint(g.writer, ColorRed+line+ColorReset)
		g.printRuleIDsSuffix(ruleIDs)
	}
	return hasNeedsReview
}

// printValueDifferences outputs value differences between expected and found.
func (g *TextGenerator) printValueDifferences(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	if len(diffCheck.ExpectedValue) == 0 || len(diffCheck.FoundValue) == 0 {
		return false
	}

	if len(diffCheck.ExpectedWithContext) > 0 {
		return g.printContextualValueDifferences(diffCheck, ruleResult)
	}
	return g.printPlainValueDifferences(diffCheck, ruleResult)
}

// printContextualValueDifferences outputs value differences with surrounding context.
func (g *TextGenerator) printContextualValueDifferences(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	hasNeedsReview := false

	// Only ExpectedNotFound needs rule checks - ExpectedValue is just reference context
	// (consistent with printPlainValueDifferences which doesn't check rules for ExpectedValue)
	expectedTargets := diffCheck.ExpectedNotFound

	fmt.Fprintln(g.writer, "expected:")
	if needsReview := g.printContextualDiffViewWithRules(diffCheck.ExpectedWithContext, expectedTargets, ColorGreen, ruleResult); needsReview {
		hasNeedsReview = true
	}

	// Combine FoundValue and FoundNotExpected for the found section.
	foundTargets := append([]string{}, diffCheck.FoundValue...)
	foundTargets = append(foundTargets, diffCheck.FoundNotExpected...)

	fmt.Fprintln(g.writer, "found:")
	if needsReview := g.printContextualDiffViewWithRules(diffCheck.FoundWithContext, foundTargets, ColorRed, ruleResult); needsReview {
		hasNeedsReview = true
	}

	return hasNeedsReview
}

// printPlainValueDifferences outputs value differences without context.
func (g *TextGenerator) printPlainValueDifferences(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	hasNeedsReview := false

	fmt.Fprintln(g.writer, "expected:")
	for _, line := range diffCheck.ExpectedValue {
		fmt.Fprintln(g.writer, ColorGreen+line+ColorReset)
	}

	fmt.Fprintln(g.writer, "found:")
	for _, line := range diffCheck.FoundValue {
		ruleIDs := g.getMatchingRuleIDs(line, "ExpectedFound", ruleResult)
		if len(ruleIDs) == 0 {
			hasNeedsReview = true
		}
		fmt.Fprint(g.writer, ColorRed+line+ColorReset)
		g.printRuleIDsSuffix(ruleIDs)
	}
	return hasNeedsReview
}

// printContextualDiffViewColored outputs diff lines with context in dim color
// and changed lines in the specified color.
func (g *TextGenerator) printContextualDiffViewColored(diffLines []types.DiffLine, changedColor string) {
	for _, dl := range diffLines {
		if dl.IsChanged {
			fmt.Fprintln(g.writer, changedColor+dl.Content+ColorReset)
		} else {
			fmt.Fprintln(g.writer, ColorDim+dl.Content+ColorReset)
		}
	}
}

// printContextualDiffViewWithRules outputs diff lines with context and rule markers.
// It shows rule match markers for lines that are in targetLines.
func (g *TextGenerator) printContextualDiffViewWithRules(diffLines []types.DiffLine, targetLines []string, changedColor string, ruleResult rules.EvaluationResult) bool {
	// Build a set of target line contents for matching.
	targetSet := make(map[string]bool)
	for _, line := range targetLines {
		targetSet[strings.TrimSpace(line)] = true
	}

	hasNeedsReview := false

	for _, dl := range diffLines {
		trimmed := strings.TrimSpace(dl.Content)

		if dl.IsChanged && targetSet[trimmed] {
			// This is a target line - check for rule matches across all condition types.
			ruleIDs := g.getMatchingRuleIDsAnyType(dl.Content, ruleResult)
			if len(ruleIDs) == 0 {
				hasNeedsReview = true
			}
			fmt.Fprint(g.writer, changedColor+dl.Content+ColorReset)
			g.printRuleIDsSuffix(ruleIDs)
		} else if dl.IsChanged {
			// Changed line but not in target set - just print colored.
			fmt.Fprintln(g.writer, changedColor+dl.Content+ColorReset)
		} else {
			// Context line - print dim.
			fmt.Fprintln(g.writer, ColorDim+dl.Content+ColorReset)
		}
	}

	return hasNeedsReview
}

// getMatchingRuleIDsAnyType returns rule IDs that match a line across any condition type.
func (g *TextGenerator) getMatchingRuleIDsAnyType(line string, ruleResult rules.EvaluationResult) []string {
	conditionTypes := []string{"ExpectedFound", "FoundNotExpected", "ExpectedNotFound"}
	seenRules := make(map[string]bool)
	var ruleIDs []string

	for _, condType := range conditionTypes {
		ids := g.getMatchingRuleIDs(line, condType, ruleResult)
		for _, id := range ids {
			if !seenRules[id] {
				seenRules[id] = true
				ruleIDs = append(ruleIDs, id)
			}
		}
	}

	return ruleIDs
}

// minimalDiffCheck creates a DiffCheck with only identity fields, for empty diffs.
func minimalDiffCheck(d types.Diff) types.DiffCheck {
	return types.DiffCheck{
		CRName:           d.CRName,
		TemplateFileName: filepath.Base(d.CorrelatedTemplate),
	}
}

// matchingRuleIDs returns rule IDs whose conditions matched a specific line.
// This is the shared implementation used by all report generators.
func matchingRuleIDs(line, diffType string, ruleResult rules.EvaluationResult) []string {
	trimmedLine := strings.TrimSpace(line)
	var ruleIDs []string
	seen := make(map[string]bool)

	for _, condResult := range ruleResult.Conditions {
		if condResult.ConditionType == diffType && condResult.Matched {
			trimmedMatched := strings.TrimSpace(condResult.MatchedText)
			if trimmedMatched == "" {
				continue
			}
			if strings.Contains(trimmedLine, trimmedMatched) || strings.Contains(trimmedMatched, trimmedLine) {
				if !seen[condResult.RuleID] {
					seen[condResult.RuleID] = true
					ruleIDs = append(ruleIDs, condResult.RuleID)
				}
			}
		}
	}
	return ruleIDs
}

// determineImpact calculates the final impact considering unmatched lines.
func determineImpact(ruleResult rules.EvaluationResult, hasNeedsReview bool) string {
	if !ruleResult.Matched {
		return "NeedsReview"
	}
	if hasNeedsReview && ruleResult.Impact != "Impacting" {
		return "NeedsReview"
	}
	return ruleResult.Impact
}

// hasUnmatchedLines checks if a diff has lines that aren't matched by any rule.
func hasUnmatchedLines(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	// Check ExpectedNotFound lines.
	for _, line := range diffCheck.ExpectedNotFound {
		if !lineHasMatchingRule(line, "ExpectedNotFound", ruleResult) {
			return true
		}
	}

	// Check FoundNotExpected lines.
	for _, line := range diffCheck.FoundNotExpected {
		if !lineHasMatchingRule(line, "FoundNotExpected", ruleResult) {
			return true
		}
	}

	// Check FoundValue lines.
	for _, line := range diffCheck.FoundValue {
		if !lineHasMatchingRule(line, "ExpectedFound", ruleResult) {
			return true
		}
	}

	return false
}

// lineHasMatchingRule checks if a line has at least one matching rule.
func lineHasMatchingRule(line, diffType string, ruleResult rules.EvaluationResult) bool {
	return len(matchingRuleIDs(line, diffType, ruleResult)) > 0
}

// getMatchingRuleIDs returns rule IDs that matched a specific line.
func (g *TextGenerator) getMatchingRuleIDs(line, diffType string, ruleResult rules.EvaluationResult) []string {
	return matchingRuleIDs(line, diffType, ruleResult)
}

// printRuleIDsSuffix outputs the rule IDs that matched a line.
func (g *TextGenerator) printRuleIDsSuffix(ruleIDs []string) {
	if len(ruleIDs) > 0 {
		fmt.Fprintf(g.writer, "  \u26A0\uFE0F  Matched by rule: [%s]\n", strings.Join(ruleIDs, ", "))
	} else {
		fmt.Fprintln(g.writer)
	}
}

// printOverallRuleResult outputs the overall evaluation result.
func (g *TextGenerator) printOverallRuleResult(ruleResult rules.EvaluationResult, hasNeedsReview bool) {
	fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", ColorBold, ColorReset)

	if !ruleResult.Matched {
		fmt.Fprintf(g.writer, "%s OVERALL IMPACT: %sNeedsReview%s%s\n", ColorBold, ColorCyan, ColorReset, ColorBold+ColorReset)
		fmt.Fprintln(g.writer)
		fmt.Fprintln(g.writer, "Rules:")
		fmt.Fprintf(g.writer, "  - None: \u26AA %s\n", ruleResult.Comment)
		fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", ColorBold, ColorReset)
		return
	}

	finalImpact := ruleResult.Impact
	if hasNeedsReview && finalImpact != "Impacting" {
		finalImpact = "NeedsReview"
	}

	impactColor := getImpactColor(finalImpact)
	fmt.Fprintf(g.writer, "%s OVERALL IMPACT: %s%s%s%s\n", ColorBold, impactColor, finalImpact, ColorReset, ColorBold+ColorReset)
	fmt.Fprintln(g.writer)
	fmt.Fprintln(g.writer, "Rules:")

	for _, condResult := range ruleResult.Conditions {
		if condResult.Matched {
			condImpactSymbol := getImpactSymbol(condResult.Impact)
			fmt.Fprintf(g.writer, "  - %s: %s %s\n", condResult.RuleID, condImpactSymbol, condResult.Comment)
		}
	}

	if hasNeedsReview {
		fmt.Fprintf(g.writer, "  - \U0001F50D Some lines need review by the telco team\n")
	}

	fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", ColorBold, ColorReset)
}

// getImpactSymbol returns an emoji symbol for the impact level.
func getImpactSymbol(impact string) string {
	switch impact {
	case "Impacting":
		return "\U0001F534" // Red circle
	case "NotImpacting":
		return "\U0001F7E1" // Yellow circle
	case "NotADeviation":
		return "\U0001F7E2" // Green circle
	default:
		return "\u26AA" // White circle
	}
}

// getImpactColor returns the ANSI color code for the impact level.
func getImpactColor(impact string) string {
	switch impact {
	case "Impacting":
		return ColorRed + ColorBold
	case "NotImpacting":
		return ColorYellow
	case "NotADeviation":
		return ColorGreen
	default:
		return ColorCyan
	}
}
