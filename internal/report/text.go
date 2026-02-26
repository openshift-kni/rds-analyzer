// Package report provides output generation for RDS analysis results.
// It supports multiple output formats including text (terminal) and HTML.
package report

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openshift-kni/rds-analyzer/internal/parser"
	"github.com/openshift-kni/rds-analyzer/internal/rules"
	"github.com/openshift-kni/rds-analyzer/internal/types"
)

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

	// Show target version if set.
	if targetVersion := g.ruleEngine.GetTargetVersion(); !targetVersion.IsZero() {
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

// ColorOrange is the ANSI color code for orange text.
const ColorOrange = "\033[38;5;208m"

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

// printDiffs outputs the configuration differences section.
func (g *TextGenerator) printDiffs(diffs []types.Diff) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "              DETECTED DIFFERENCES")
	fmt.Fprintln(g.writer, "==================================================")

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

	// Count non-empty diffs for display numbering.
	nonEmptyDiffs := parser.RemoveEmptyDiffs(diffs)
	diffIndex := 0

	for _, d := range diffs {
		// Handle empty diffs - add minimal DiffCheck for count rules only.
		if d.DiffOutput == "" {
			allDiffChecks = append(allDiffChecks, types.DiffCheck{
				CRName:           d.CRName,
				TemplateFileName: filepath.Base(d.CorrelatedTemplate),
			})
			continue
		}

		diffIndex++
		fmt.Fprintf(g.writer, "--- Diff %d of %d ---\n", diffIndex, len(nonEmptyDiffs))
		fmt.Fprintf(g.writer, "CR Name: %s\n", d.CRName)
		fmt.Fprintf(g.writer, "Template: %s\n", d.CorrelatedTemplate)
		fmt.Fprintf(g.writer, "Description: %s\n", d.Description)
		fmt.Fprintln(g.writer, "---")

		formattedDiff, err := parser.ParseExpectedAndFound(d.DiffOutput, d.CRName, filepath.Base(d.CorrelatedTemplate))
		if err != nil {
			fmt.Fprintf(g.writer, "Error parsing diff: %v\n", err)
			fmt.Fprintln(g.writer, d.DiffOutput)
		} else {
			allDiffChecks = append(allDiffChecks, formattedDiff)

			ruleResult := g.ruleEngine.Evaluate(formattedDiff)
			finalImpact := g.printDiffCheck(formattedDiff, ruleResult)
			impactStats[finalImpact]++
		}
		fmt.Fprintln(g.writer)
	}

	// Evaluate and print count rule violations.
	countResults := g.ruleEngine.EvaluateCountRules(allDiffChecks)
	if len(countResults) > 0 {
		g.printCountRuleResults(countResults, impactStats)
	}

	// Print summary statistics.
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "              IMPACT SUMMARY")
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintf(g.writer, "Impacting:      %d\n", impactStats["Impacting"])
	fmt.Fprintf(g.writer, "Not Impacting:  %d\n", impactStats["NotImpacting"])
	fmt.Fprintf(g.writer, "Not a Deviation: %d\n", impactStats["NotADeviation"])
	fmt.Fprintf(g.writer, "Needs Review:   %d\n", impactStats["NeedsReview"])
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

		fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", parser.ColorBold, parser.ColorReset)
		fmt.Fprintf(g.writer, "Rule: %s\n", result.RuleID)
		fmt.Fprintf(g.writer, "Description: %s\n", result.Description)
		fmt.Fprintf(g.writer, "Count: %d CRs matched\n", result.Count)
		fmt.Fprintf(g.writer, "Impact: %s%s %s%s\n", impactColor, impactSymbol, result.Impact, parser.ColorReset)
		fmt.Fprintf(g.writer, "Comment: %s\n", result.Comment)

		if len(result.MatchedCRs) > 0 {
			fmt.Fprintln(g.writer, "Matched CRs:")
			for _, cr := range result.MatchedCRs {
				fmt.Fprintf(g.writer, "  - %s\n", cr)
			}
		}
		fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", parser.ColorBold, parser.ColorReset)
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
		fmt.Fprint(g.writer, parser.ColorGreen+line+parser.ColorReset)
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
		fmt.Fprint(g.writer, parser.ColorRed+line+parser.ColorReset)
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
	if needsReview := g.printContextualDiffViewWithRules(diffCheck.ExpectedWithContext, expectedTargets, parser.ColorGreen, ruleResult); needsReview {
		hasNeedsReview = true
	}

	// Combine FoundValue and FoundNotExpected for the found section.
	foundTargets := append([]string{}, diffCheck.FoundValue...)
	foundTargets = append(foundTargets, diffCheck.FoundNotExpected...)

	fmt.Fprintln(g.writer, "found:")
	if needsReview := g.printContextualDiffViewWithRules(diffCheck.FoundWithContext, foundTargets, parser.ColorRed, ruleResult); needsReview {
		hasNeedsReview = true
	}

	return hasNeedsReview
}

// printPlainValueDifferences outputs value differences without context.
func (g *TextGenerator) printPlainValueDifferences(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	hasNeedsReview := false

	fmt.Fprintln(g.writer, "expected:")
	for _, line := range diffCheck.ExpectedValue {
		fmt.Fprintln(g.writer, parser.ColorGreen+line+parser.ColorReset)
	}

	fmt.Fprintln(g.writer, "found:")
	for _, line := range diffCheck.FoundValue {
		ruleIDs := g.getMatchingRuleIDs(line, "ExpectedFound", ruleResult)
		if len(ruleIDs) == 0 {
			hasNeedsReview = true
		}
		fmt.Fprint(g.writer, parser.ColorRed+line+parser.ColorReset)
		g.printRuleIDsSuffix(ruleIDs)
	}
	return hasNeedsReview
}

// printContextualDiffViewColored outputs diff lines with context in dim color
// and changed lines in the specified color.
func (g *TextGenerator) printContextualDiffViewColored(diffLines []types.DiffLine, changedColor string) {
	for _, dl := range diffLines {
		if dl.IsChanged {
			fmt.Fprintln(g.writer, changedColor+dl.Content+parser.ColorReset)
		} else {
			fmt.Fprintln(g.writer, parser.ColorDim+dl.Content+parser.ColorReset)
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
			fmt.Fprint(g.writer, changedColor+dl.Content+parser.ColorReset)
			g.printRuleIDsSuffix(ruleIDs)
		} else if dl.IsChanged {
			// Changed line but not in target set - just print colored.
			fmt.Fprintln(g.writer, changedColor+dl.Content+parser.ColorReset)
		} else {
			// Context line - print dim.
			fmt.Fprintln(g.writer, parser.ColorDim+dl.Content+parser.ColorReset)
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

// getMatchingRuleIDs returns rule IDs that matched a specific line.
func (g *TextGenerator) getMatchingRuleIDs(line, diffType string, ruleResult rules.EvaluationResult) []string {
	trimmedLine := strings.TrimSpace(line)
	var ruleIDs []string
	seen := make(map[string]bool)

	for _, condResult := range ruleResult.Conditions {
		if condResult.ConditionType == diffType && condResult.Matched {
			trimmedMatched := strings.TrimSpace(condResult.MatchedText)
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
	fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", parser.ColorBold, parser.ColorReset)

	if !ruleResult.Matched {
		fmt.Fprintf(g.writer, "%s OVERALL IMPACT: %sNeedsReview%s%s\n", parser.ColorBold, parser.ColorCyan, parser.ColorReset, parser.ColorBold+parser.ColorReset)
		fmt.Fprintln(g.writer)
		fmt.Fprintln(g.writer, "Rules:")
		fmt.Fprintf(g.writer, "  - None: \u26AA %s\n", ruleResult.Comment)
		fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", parser.ColorBold, parser.ColorReset)
		return
	}

	finalImpact := ruleResult.Impact
	if hasNeedsReview && finalImpact != "Impacting" {
		finalImpact = "NeedsReview"
	}

	impactColor := getImpactColor(finalImpact)
	fmt.Fprintf(g.writer, "%s OVERALL IMPACT: %s%s%s%s\n", parser.ColorBold, impactColor, finalImpact, parser.ColorReset, parser.ColorBold+parser.ColorReset)
	fmt.Fprintln(g.writer)
	fmt.Fprintln(g.writer, "Rules:")

	for _, condResult := range ruleResult.Conditions {
		if condResult.Matched {
			condImpactSymbol := getImpactSymbol(condResult.Impact)
			fmt.Fprintf(g.writer, "  - %s: %s %s\n", condResult.RuleID, condImpactSymbol, condResult.Comment)
		}
	}

	if hasNeedsReview {
		fmt.Fprintf(g.writer, "  - \U0001F535 Some diffs from this deviation need to be reviewed by the telco team\n")
	}

	fmt.Fprintf(g.writer, "%s═══════════════════════════════════════════════════%s\n", parser.ColorBold, parser.ColorReset)
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
		return parser.ColorRed + parser.ColorBold
	case "NotImpacting":
		return parser.ColorYellow
	case "NotADeviation":
		return parser.ColorGreen
	default:
		return parser.ColorCyan
	}
}
