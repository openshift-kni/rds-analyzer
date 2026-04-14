// Package report provides output generation for RDS analysis results.
package report

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openshift-kni/rds-analyzer/internal/parser"
	"github.com/openshift-kni/rds-analyzer/internal/rules"
	"github.com/openshift-kni/rds-analyzer/internal/types"
)

// ReportingGenerator produces a plain text report.
// It divides output into two sections: items requiring action and items requiring guidance.
type ReportingGenerator struct {
	ruleEngine *rules.Engine
	writer     io.Writer
}

// NewReportingGenerator creates a new reporting generator.
func NewReportingGenerator(ruleEngine *rules.Engine) *ReportingGenerator {
	return &ReportingGenerator{
		ruleEngine: ruleEngine,
	}
}

// reportingDiffResult holds the evaluation result for a single diff.
type reportingDiffResult struct {
	diff           types.Diff
	diffCheck      types.DiffCheck
	ruleResult     rules.EvaluationResult
	finalImpact    string
	impactingRules []rules.ConditionResult // Only impacting rules
	resolvedRules  []rules.ConditionResult // Non-impacting matched rules
	unresolvedDiff unresolvedDiffLines     // Lines not matched by any rule
}

// unresolvedDiffLines holds diff lines that were not matched by rules.
type unresolvedDiffLines struct {
	expectedNotFound []string
	foundNotExpected []string
	expectedValue    []string
	foundValue       []string
}

// Generate writes the complete reporting-mode output to the given writer.
func (g *ReportingGenerator) Generate(w io.Writer, report types.ValidationReport) error {
	g.writer = w

	// Extract correlated templates and evaluate all data.
	correlatedTemplates := rules.ExtractCorrelatedTemplates(report.Diffs)
	missingCRResults := g.ruleEngine.EvaluateMissingCRs(report.Summary.ValidationIssues, correlatedTemplates)
	diffResults, allDiffChecks := g.evaluateAllDiffs(report.Diffs)
	// Use allDiffChecks for count rules to include NotADeviation CRs in the count.
	countResults := g.ruleEngine.EvaluateCountRules(allDiffChecks)

	// Calculate statistics.
	stats := g.calculateStats(missingCRResults, diffResults, countResults, report.Summary.UnmatchedCRS)

	// Print header.
	g.printHeader()

	// Print section 1: Deviations that must be addressed.
	g.printSection1(report.Summary.ValidationIssues, missingCRResults, diffResults, countResults, report.Summary.UnmatchedCRS)

	// Print section 2: Deviations that require guidance.
	g.printSection2(report.Summary.ValidationIssues, missingCRResults, diffResults)

	// Print summary.
	g.printSummary(stats)

	return nil
}

// printHeader outputs the report header.
func (g *ReportingGenerator) printHeader() {
	fmt.Fprintln(g.writer, "RDS Analyzer Report")

	targetVersion := g.ruleEngine.GetTargetVersion()
	if !targetVersion.IsZero() {
		fmt.Fprintf(g.writer, "Used target OCP version: %s\n", targetVersion)
	}

	if variant := g.ruleEngine.GetRDSVariant(); variant != "" {
		fmt.Fprintf(g.writer, "Used RDS Variant: %s\n", variant)
	}

	fmt.Fprintf(g.writer, "Generated: %s\n", time.Now().Format("2006-01-02"))
	fmt.Fprintln(g.writer)
}

// printSection1 outputs deviations that must be addressed.
func (g *ReportingGenerator) printSection1(
	issues types.ValidationIssues,
	missingCRResults map[string]rules.MissingCRResult,
	diffResults []reportingDiffResult,
	countResults []rules.CountRuleResult,
	unmatchedCRs []string,
) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "The following deviations must be addressed:")
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer)

	subsectionNum := 1

	// 1.1 Missing required CRs (Impacting).
	if g.hasImpactingMissingCRs(missingCRResults) {
		fmt.Fprintf(g.writer, "%d. Missing required CRs:\n\n", subsectionNum)
		fmt.Fprintln(g.writer, "  These CRs are required by the reference configuration.")
		fmt.Fprintln(g.writer, "  Make sure they are present in the cluster.")
		fmt.Fprintln(g.writer)
		g.printMissingCRsByImpact(issues, missingCRResults, "Impacting")
		subsectionNum++
	}

	// 1.2 Impacting diffs.
	impactingDiffs := g.filterDiffsByImpact(diffResults, "Impacting")
	if len(impactingDiffs) > 0 {
		fmt.Fprintf(g.writer, "%d. Impacting diffs:\n\n", subsectionNum)
		g.printImpactingDiffs(impactingDiffs)
		subsectionNum++
	}

	// 1.3 Count rule violations (Impacting).
	impactingCountRules := g.filterCountRulesByImpact(countResults, "Impacting")
	if len(impactingCountRules) > 0 {
		fmt.Fprintf(g.writer, "%d. Count rule violations:\n\n", subsectionNum)
		g.printCountRuleViolations(impactingCountRules)
		subsectionNum++
	}

	// 1.4 Unmatched CRs.
	if len(unmatchedCRs) > 0 {
		fmt.Fprintf(g.writer, "%d. Unmatched CRs:\n\n", subsectionNum)
		g.printUnmatchedCRs(unmatchedCRs)
	}
}

// printSection2 outputs deviations that require guidance.
func (g *ReportingGenerator) printSection2(
	issues types.ValidationIssues,
	missingCRResults map[string]rules.MissingCRResult,
	diffResults []reportingDiffResult,
) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "The following deviations require guidance from the telco team:")
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer)

	subsectionNum := 1

	// 2.1 Missing CRs (NotImpacting/NeedsReview).
	if g.hasGuidanceMissingCRs(missingCRResults) {
		fmt.Fprintf(g.writer, "%d. Missing CRs:\n\n", subsectionNum)
		fmt.Fprintln(g.writer, "  While marked as optional, these CRs are expected in most clusters.")
		fmt.Fprintln(g.writer, "  Please clarify why they are not being used.")
		fmt.Fprintln(g.writer)
		g.printMissingCRsByImpact(issues, missingCRResults, "NotImpacting", "NeedsReview")
		subsectionNum++
	}

	// 2.2 Diffs requiring review (NotImpacting/NeedsReview).
	guidanceDiffs := g.filterDiffsByImpact(diffResults, "NotImpacting", "NeedsReview")
	if len(guidanceDiffs) > 0 {
		fmt.Fprintf(g.writer, "%d. Diffs requiring review:\n\n", subsectionNum)
		g.printGuidanceDiffs(guidanceDiffs)
	}
}

// printSummary outputs the final summary statistics.
func (g *ReportingGenerator) printSummary(stats reportStats) {
	fmt.Fprintln(g.writer, "==================================================")
	fmt.Fprintln(g.writer, "Summary:")
	fmt.Fprintf(g.writer, "  Items requiring action: %d\n", stats.actionItems)
	fmt.Fprintf(g.writer, "  Items requiring guidance: %d\n", stats.guidanceItems)
	fmt.Fprintln(g.writer, "==================================================")
}

// reportStats holds summary statistics.
type reportStats struct {
	actionItems   int
	guidanceItems int
}

// calculateStats computes summary statistics.
func (g *ReportingGenerator) calculateStats(
	missingCRResults map[string]rules.MissingCRResult,
	diffResults []reportingDiffResult,
	countResults []rules.CountRuleResult,
	unmatchedCRs []string,
) reportStats {
	var stats reportStats

	// Count missing CRs.
	for _, result := range missingCRResults {
		switch result.Impact {
		case "Impacting":
			stats.actionItems++
		case "NotImpacting", "NeedsReview":
			stats.guidanceItems++
		}
	}

	// Count diffs.
	for _, result := range diffResults {
		switch result.finalImpact {
		case "Impacting":
			stats.actionItems++
		case "NotImpacting", "NeedsReview":
			stats.guidanceItems++
		}
	}

	// Count impacting count rules.
	for _, result := range countResults {
		if result.Impact == "Impacting" {
			stats.actionItems++
		}
	}

	// Count unmatched CRs.
	stats.actionItems += len(unmatchedCRs)

	return stats
}

// evaluateAllDiffs processes all diffs and returns their evaluation results.
// Returns two values:
//   - filtered results (excluding NotADeviation) for display
//   - all DiffChecks (including NotADeviation) for count rule evaluation
func (g *ReportingGenerator) evaluateAllDiffs(diffs []types.Diff) ([]reportingDiffResult, []types.DiffCheck) {
	results := make([]reportingDiffResult, 0, len(diffs))
	allDiffChecks := make([]types.DiffCheck, 0, len(diffs))

	for _, d := range diffs {
		// Handle empty diffs - add minimal DiffCheck for count rules only.
		if d.DiffOutput == "" {
			allDiffChecks = append(allDiffChecks, types.DiffCheck{
				CRName:           d.CRName,
				TemplateFileName: filepath.Base(d.CorrelatedTemplate),
			})
			continue
		}

		diffCheck, err := parser.ParseExpectedAndFound(d.DiffOutput, d.CRName, filepath.Base(d.CorrelatedTemplate))
		if err != nil {
			continue
		}

		// Collect all DiffChecks for count rule evaluation.
		allDiffChecks = append(allDiffChecks, diffCheck)

		ruleResult := g.ruleEngine.Evaluate(diffCheck)
		hasNeedsReview := g.hasUnmatchedLines(diffCheck, ruleResult)
		finalImpact := determineImpact(ruleResult, hasNeedsReview)

		// Skip NotADeviation diffs for display purposes only.
		if finalImpact == "NotADeviation" {
			continue
		}

		result := reportingDiffResult{
			diff:           d,
			diffCheck:      diffCheck,
			ruleResult:     ruleResult,
			finalImpact:    finalImpact,
			impactingRules: g.extractImpactingRules(ruleResult),
			resolvedRules:  g.extractResolvedRules(ruleResult),
			unresolvedDiff: g.extractUnresolvedLines(diffCheck, ruleResult),
		}

		results = append(results, result)
	}

	return results, allDiffChecks
}

// hasUnmatchedLines checks if any diff lines are not matched by rules.
func (g *ReportingGenerator) hasUnmatchedLines(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) bool {
	for _, line := range diffCheck.ExpectedNotFound {
		if len(g.getMatchingRuleIDs(line, "ExpectedNotFound", ruleResult)) == 0 {
			return true
		}
	}
	for _, line := range diffCheck.FoundNotExpected {
		if len(g.getMatchingRuleIDs(line, "FoundNotExpected", ruleResult)) == 0 {
			return true
		}
	}
	for _, line := range diffCheck.FoundValue {
		if len(g.getMatchingRuleIDs(line, "ExpectedFound", ruleResult)) == 0 {
			return true
		}
	}
	return false
}

// getMatchingRuleIDs returns rule IDs that matched a specific line.
func (g *ReportingGenerator) getMatchingRuleIDs(line, diffType string, ruleResult rules.EvaluationResult) []string {
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

// extractImpactingRules returns only the rules with Impacting impact.
func (g *ReportingGenerator) extractImpactingRules(ruleResult rules.EvaluationResult) []rules.ConditionResult {
	var impacting []rules.ConditionResult
	seen := make(map[string]bool)

	for _, cond := range ruleResult.Conditions {
		if cond.Matched && cond.Impact == "Impacting" {
			key := cond.RuleID + ":" + cond.Comment
			if !seen[key] {
				seen[key] = true
				impacting = append(impacting, cond)
			}
		}
	}
	return impacting
}

// extractResolvedRules returns matched rules with non-Impacting impact.
func (g *ReportingGenerator) extractResolvedRules(ruleResult rules.EvaluationResult) []rules.ConditionResult {
	var resolved []rules.ConditionResult
	seen := make(map[string]bool)

	for _, cond := range ruleResult.Conditions {
		if cond.Matched && cond.Impact != "Impacting" && cond.Impact != "" {
			key := cond.RuleID + ":" + cond.Comment
			if !seen[key] {
				seen[key] = true
				resolved = append(resolved, cond)
			}
		}
	}
	return resolved
}

// extractUnresolvedLines returns diff lines not matched by any rule.
func (g *ReportingGenerator) extractUnresolvedLines(diffCheck types.DiffCheck, ruleResult rules.EvaluationResult) unresolvedDiffLines {
	var unresolved unresolvedDiffLines

	for _, line := range diffCheck.ExpectedNotFound {
		if len(g.getMatchingRuleIDs(line, "ExpectedNotFound", ruleResult)) == 0 {
			unresolved.expectedNotFound = append(unresolved.expectedNotFound, g.stripANSI(line))
		}
	}

	for _, line := range diffCheck.FoundNotExpected {
		if len(g.getMatchingRuleIDs(line, "FoundNotExpected", ruleResult)) == 0 {
			unresolved.foundNotExpected = append(unresolved.foundNotExpected, g.stripANSI(line))
		}
	}

	// For ExpectedFound (value differences), include both expected and found if unmatched.
	for i, line := range diffCheck.FoundValue {
		if len(g.getMatchingRuleIDs(line, "ExpectedFound", ruleResult)) == 0 {
			unresolved.foundValue = append(unresolved.foundValue, g.stripANSI(line))
			if i < len(diffCheck.ExpectedValue) {
				unresolved.expectedValue = append(unresolved.expectedValue, g.stripANSI(diffCheck.ExpectedValue[i]))
			}
		}
	}

	return unresolved
}

// stripANSI removes ANSI color codes from a string.
func (g *ReportingGenerator) stripANSI(s string) string {
	s = strings.ReplaceAll(s, parser.ColorReset, "")
	s = strings.ReplaceAll(s, parser.ColorRed, "")
	s = strings.ReplaceAll(s, parser.ColorGreen, "")
	s = strings.ReplaceAll(s, parser.ColorYellow, "")
	s = strings.ReplaceAll(s, parser.ColorBlue, "")
	s = strings.ReplaceAll(s, parser.ColorCyan, "")
	s = strings.ReplaceAll(s, parser.ColorBold, "")
	return s
}

// printIndentedLines prints lines preserving their relative YAML indentation.
func (g *ReportingGenerator) printIndentedLines(lines []string, baseIndent string) {
	if len(lines) == 0 {
		return
	}

	// Find the minimum indentation across all non-empty lines.
	minIndent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if minIndent == -1 || indent < minIndent {
			minIndent = indent
		}
	}

	if minIndent < 0 {
		minIndent = 0
	}

	// Print each line with the base indent plus relative indentation.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Calculate relative indent from minimum.
		currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		relativeIndent := currentIndent - minIndent
		if relativeIndent < 0 {
			relativeIndent = 0
		}
		fmt.Fprintf(g.writer, "%s%s%s\n", baseIndent, strings.Repeat(" ", relativeIndent), trimmed)
	}
}

// printContextualDiffView prints a diff view with >> markers for changed lines.
// Context lines are printed without markers, changed lines get >> prefix.
func (g *ReportingGenerator) printContextualDiffView(diffLines []types.DiffLine, baseIndent string) {
	if len(diffLines) == 0 {
		return
	}

	// Find minimum indentation across all lines.
	minIndent := -1
	for _, dl := range diffLines {
		if strings.TrimSpace(dl.Content) == "" {
			continue
		}
		indent := len(dl.Content) - len(strings.TrimLeft(dl.Content, " \t"))
		if minIndent == -1 || indent < minIndent {
			minIndent = indent
		}
	}
	if minIndent < 0 {
		minIndent = 0
	}

	// Print with >> markers for changed lines.
	// Use 4-char gutter: ">>" + 2 spaces for changed, 4 spaces for context.
	for _, dl := range diffLines {
		trimmed := strings.TrimSpace(dl.Content)
		if trimmed == "" {
			continue
		}

		currentIndent := len(dl.Content) - len(strings.TrimLeft(dl.Content, " \t"))
		relativeIndent := currentIndent - minIndent
		if relativeIndent < 0 {
			relativeIndent = 0
		}

		var gutter string
		if dl.IsChanged {
			gutter = ">>" + strings.Repeat(" ", 2)
		} else {
			gutter = strings.Repeat(" ", 4)
		}

		fmt.Fprintf(g.writer, "%s%s%s%s\n", baseIndent, gutter, strings.Repeat(" ", relativeIndent), trimmed)
	}
}

// extractDiffChecks extracts DiffCheck objects from results.
func (g *ReportingGenerator) extractDiffChecks(results []reportingDiffResult) []types.DiffCheck {
	checks := make([]types.DiffCheck, len(results))
	for i, r := range results {
		checks[i] = r.diffCheck
	}
	return checks
}

// hasImpactingMissingCRs checks if there are any impacting missing CRs.
func (g *ReportingGenerator) hasImpactingMissingCRs(results map[string]rules.MissingCRResult) bool {
	for _, r := range results {
		if r.Impact == "Impacting" {
			return true
		}
	}
	return false
}

// hasGuidanceMissingCRs checks if there are any NotImpacting/NeedsReview missing CRs.
func (g *ReportingGenerator) hasGuidanceMissingCRs(results map[string]rules.MissingCRResult) bool {
	for _, r := range results {
		if r.Impact == "NotImpacting" || r.Impact == "NeedsReview" {
			return true
		}
	}
	return false
}

// printMissingCRsByImpact outputs missing CRs filtered by impact levels.
func (g *ReportingGenerator) printMissingCRsByImpact(
	issues types.ValidationIssues,
	results map[string]rules.MissingCRResult,
	impacts ...string,
) {
	impactSet := make(map[string]bool)
	for _, imp := range impacts {
		impactSet[imp] = true
	}

	// Build a map of group -> deviation -> CRs for the specified impacts.
	type deviationData struct {
		msg             string
		crs             []string
		isOneOfRequired bool
		hasSatisfiedCR  bool
	}
	groupData := make(map[string]map[string]*deviationData)

	for crPath, result := range results {
		if !impactSet[result.Impact] {
			continue
		}

		if groupData[result.GroupName] == nil {
			groupData[result.GroupName] = make(map[string]*deviationData)
		}

		if groupData[result.GroupName][result.DeviationName] == nil {
			// Get the message from the original issues.
			msg := "Missing CRs"
			if devGroup, ok := issues[result.GroupName]; ok {
				if dev, ok := devGroup[result.DeviationName]; ok {
					msg = dev.Msg
				}
			}
			groupData[result.GroupName][result.DeviationName] = &deviationData{
				msg:             msg,
				isOneOfRequired: result.IsOneOfRequired,
			}
		}

		// Track if any CR is satisfied (for "one of the following" groups).
		if result.IsSatisfied {
			groupData[result.GroupName][result.DeviationName].hasSatisfiedCR = true
		}

		groupData[result.GroupName][result.DeviationName].crs = append(
			groupData[result.GroupName][result.DeviationName].crs,
			crPath,
		)
	}

	// Sort and print.
	groupNames := make([]string, 0, len(groupData))
	for name := range groupData {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)

	for _, groupName := range groupNames {
		fmt.Fprintf(g.writer, "  Group: %s\n", groupName)

		deviations := groupData[groupName]
		devNames := make([]string, 0, len(deviations))
		for name := range deviations {
			devNames = append(devNames, name)
		}
		sort.Strings(devNames)

		for _, devName := range devNames {
			data := deviations[devName]
			fmt.Fprintf(g.writer, "    - %s: %s\n", devName, data.msg)

			// Show "NONE FOUND" header for unsatisfied "one of the following" groups.
			if data.isOneOfRequired && !data.hasSatisfiedCR {
				fmt.Fprintf(g.writer, "      [NONE FOUND]\n")
			}

			sort.Strings(data.crs)
			for _, cr := range data.crs {
				result := results[cr]

				// Determine indentation based on whether we have a "NONE FOUND" header.
				indent := "      "
				if data.isOneOfRequired && !data.hasSatisfiedCR {
					indent = "        "
				}

				// Print with satisfaction or impact indicator.
				if result.IsSatisfied {
					fmt.Fprintf(g.writer, "%s[SATISFIED] %s\n", indent, cr)
				} else {
					fmt.Fprintf(g.writer, "%s[%s] %s\n", indent, result.Impact, cr)
				}
			}
		}
		fmt.Fprintln(g.writer)
	}
}

// filterDiffsByImpact returns diffs matching any of the specified impacts.
func (g *ReportingGenerator) filterDiffsByImpact(results []reportingDiffResult, impacts ...string) []reportingDiffResult {
	impactSet := make(map[string]bool)
	for _, imp := range impacts {
		impactSet[imp] = true
	}

	var filtered []reportingDiffResult
	for _, r := range results {
		if impactSet[r.finalImpact] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// filterCountRulesByImpact returns count rules matching any of the specified impacts.
func (g *ReportingGenerator) filterCountRulesByImpact(results []rules.CountRuleResult, impacts ...string) []rules.CountRuleResult {
	impactSet := make(map[string]bool)
	for _, imp := range impacts {
		impactSet[imp] = true
	}

	var filtered []rules.CountRuleResult
	for _, r := range results {
		if r.Matched && impactSet[r.Impact] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// printImpactingDiffs outputs diffs with impacting rules.
func (g *ReportingGenerator) printImpactingDiffs(results []reportingDiffResult) {
	for _, r := range results {
		fmt.Fprintf(g.writer, "  CR Name: %s\n", r.diff.CRName)
		fmt.Fprintf(g.writer, "  Template: %s\n", r.diff.CorrelatedTemplate)
		fmt.Fprintln(g.writer, "  What must be changed:")

		// Print impacting rule comments (deduplicated).
		seen := make(map[string]bool)
		for _, cond := range r.impactingRules {
			if !seen[cond.Comment] {
				seen[cond.Comment] = true
				fmt.Fprintf(g.writer, "    - %s\n", cond.Comment)
				if cond.SupportingDoc != "" {
					fmt.Fprintf(g.writer, "      See: %s\n", cond.SupportingDoc)
				}
			}
		}
		fmt.Fprintln(g.writer)
	}
}

// printGuidanceDiffs outputs diffs requiring review, grouped by template.
func (g *ReportingGenerator) printGuidanceDiffs(results []reportingDiffResult) {
	templateGroups, templateOrder := g.groupResultsByTemplate(results)

	for i, template := range templateOrder {
		if i > 0 {
			g.printTemplateSeparator()
		}

		g.printTemplateHeader(template)
		g.printTemplateResults(templateGroups[template])
	}
}

// groupResultsByTemplate groups results by template and maintains insertion order.
func (g *ReportingGenerator) groupResultsByTemplate(results []reportingDiffResult) (map[string][]reportingDiffResult, []string) {
	templateGroups := make(map[string][]reportingDiffResult)
	var templateOrder []string

	for _, r := range results {
		template := r.diff.CorrelatedTemplate
		if _, exists := templateGroups[template]; !exists {
			templateOrder = append(templateOrder, template)
		}
		templateGroups[template] = append(templateGroups[template], r)
	}

	return templateGroups, templateOrder
}

// printTemplateSeparator prints a separator between template sections.
func (g *ReportingGenerator) printTemplateSeparator() {
	fmt.Fprintln(g.writer, "--------------------------------------------------")
	fmt.Fprintln(g.writer)
}

// printTemplateHeader prints the template name header.
func (g *ReportingGenerator) printTemplateHeader(template string) {
	fmt.Fprintf(g.writer, "  Template: %s\n", template)
	fmt.Fprintln(g.writer)
}

// printTemplateResults prints all results for a given template.
func (g *ReportingGenerator) printTemplateResults(results []reportingDiffResult) {
	for _, r := range results {
		fmt.Fprintf(g.writer, "  CR Name: %s\n", r.diff.CRName)

		if g.hasUnresolvedDifferences(r) {
			g.printUnresolvedDifferences(r)
		} else if len(r.resolvedRules) > 0 {
			g.printResolvedRuleEvaluations(r.resolvedRules)
		}

		fmt.Fprintln(g.writer)
	}
}

// hasUnresolvedDifferences checks if a result has any unresolved differences.
func (g *ReportingGenerator) hasUnresolvedDifferences(r reportingDiffResult) bool {
	return len(r.unresolvedDiff.expectedNotFound) > 0 ||
		len(r.unresolvedDiff.foundNotExpected) > 0 ||
		len(r.unresolvedDiff.expectedValue) > 0
}

// printUnresolvedDifferences outputs all unresolved differences for a result.
func (g *ReportingGenerator) printUnresolvedDifferences(r reportingDiffResult) {
	fmt.Fprintln(g.writer, "  Unresolved differences:")

	if len(r.unresolvedDiff.expectedNotFound) > 0 {
		fmt.Fprintln(g.writer, "    expected but not found:")
		g.printIndentedLines(r.unresolvedDiff.expectedNotFound, "      ")
	}

	if len(r.unresolvedDiff.foundNotExpected) > 0 {
		fmt.Fprintln(g.writer, "    found but not expected:")
		g.printIndentedLines(r.unresolvedDiff.foundNotExpected, "      ")
	}

	if len(r.unresolvedDiff.expectedValue) > 0 {
		g.printUnresolvedValueDifferences(r)
	}
}

// printUnresolvedValueDifferences outputs unresolved value differences.
func (g *ReportingGenerator) printUnresolvedValueDifferences(r reportingDiffResult) {
	if len(r.diffCheck.ExpectedWithContext) > 0 {
		fmt.Fprintln(g.writer, "    expected:")
		g.printContextualDiffView(r.diffCheck.ExpectedWithContext, "      ")
		fmt.Fprintln(g.writer, "    found:")
		g.printContextualDiffView(r.diffCheck.FoundWithContext, "      ")
	} else {
		fmt.Fprintln(g.writer, "    expected:")
		g.printIndentedLines(r.unresolvedDiff.expectedValue, "      ")
		fmt.Fprintln(g.writer, "    found:")
		g.printIndentedLines(r.unresolvedDiff.foundValue, "      ")
	}
}

// printResolvedRuleEvaluations outputs the rule evaluations for resolved differences.
func (g *ReportingGenerator) printResolvedRuleEvaluations(resolvedRules []rules.ConditionResult) {
	fmt.Fprintln(g.writer, "  Evaluation:")
	seen := make(map[string]bool)
	for _, cond := range resolvedRules {
		if !seen[cond.Comment] {
			seen[cond.Comment] = true
			fmt.Fprintf(g.writer, "    - [%s] %s\n", cond.Impact, cond.Comment)
			if cond.SupportingDoc != "" {
				fmt.Fprintf(g.writer, "      See: %s\n", cond.SupportingDoc)
			}
		}
	}
}

// printCountRuleViolations outputs impacting count rule violations.
func (g *ReportingGenerator) printCountRuleViolations(results []rules.CountRuleResult) {
	for _, r := range results {
		fmt.Fprintf(g.writer, "  %s: %s\n", r.RuleID, r.Comment)
		if r.SupportingDoc != "" {
			fmt.Fprintf(g.writer, "  See: %s\n", r.SupportingDoc)
		}
		if len(r.MatchedCRs) > 0 {
			fmt.Fprintln(g.writer, "  Affected CRs:")
			for _, cr := range r.MatchedCRs {
				fmt.Fprintf(g.writer, "    - %s\n", cr)
			}
		}
		fmt.Fprintln(g.writer)
	}
}

// printUnmatchedCRs outputs CRs in the cluster that don't match any template.
func (g *ReportingGenerator) printUnmatchedCRs(crs []string) {
	for _, cr := range crs {
		fmt.Fprintf(g.writer, "  - %s\n", cr)
	}
	fmt.Fprintln(g.writer)
}
