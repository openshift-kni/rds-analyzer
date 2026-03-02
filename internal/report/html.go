package report

import (
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openshift-kni/rds-analyzer/internal/parser"
	"github.com/openshift-kni/rds-analyzer/internal/rules"
	"github.com/openshift-kni/rds-analyzer/internal/types"
)

// escapeHTML escapes characters that could break HTML structure.
// Returns template.HTML to prevent double-escaping by the template engine.
func escapeHTML(s string) template.HTML {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return template.HTML(s)
}

// HTMLReport contains all data needed to render the HTML report.
type HTMLReport struct {
	GeneratedAt     string
	OCPVersion      string
	Summary         SummaryData
	MissingCRs      []MissingCRGroup
	Diffs           []DiffData
	CountViolations []CountViolationData
	ImpactStats     ImpactStats
}

// SummaryData contains validation summary statistics.
type SummaryData struct {
	TotalMissing int
	DiffCRs      int
	TotalCRs     int
	UnmatchedCRs int
	PatchedCRs   int
	MetadataHash string
}

// MissingCRGroup represents a group of missing CRs.
type MissingCRGroup struct {
	GroupName  string
	IsRequired bool
	Deviations []DeviationData
}

// DeviationData represents a deviation within a group.
type DeviationData struct {
	Name            string
	Message         string
	CRs             []MissingCRData
	IsOneOfRequired bool // True for "one of the following is required" deviations
	HasSatisfiedCR  bool // True if at least one CR in this deviation is satisfied
}

// MissingCRData represents a single missing CR.
type MissingCRData struct {
	Path        string
	Impact      string
	ImpactCSS   string
	IsSatisfied bool // True if this CR was found in correlated templates
}

// DiffData represents a single difference with rule evaluation.
type DiffData struct {
	Index            int
	Total            int
	CRName           string
	Template         string
	Description      string
	ExpectedNotFound []DiffLineData
	FoundNotExpected []DiffLineData
	ExpectedValues   []template.HTML
	FoundValues      []DiffLineData
	OverallImpact    string
	OverallImpactCSS string
	MatchedRules     []RuleMatchData
	HasNeedsReview   bool
	NoRulesMatched   bool
	NoMatchComment   string
}

// DiffLineData represents a single diff line with optional rule match.
type DiffLineData struct {
	Line     template.HTML
	Rules    []RuleTagData
	HasRules bool
}

// RuleTagData represents a rule tag with tooltip info.
type RuleTagData struct {
	ID        string
	Comment   string
	Impact    string
	ImpactCSS string
}

// RuleMatchData represents a matched rule.
type RuleMatchData struct {
	RuleID    string
	Impact    string
	ImpactCSS string
	Comment   string
}

// CountViolationData represents a count rule violation.
type CountViolationData struct {
	RuleID      string
	Description string
	Count       int
	Impact      string
	ImpactCSS   string
	Comment     string
	MatchedCRs  []string
}

// ImpactStats contains impact statistics.
type ImpactStats struct {
	Impacting           int
	NotImpacting        int
	NotADeviation       int
	NeedsReview         int
	MissingImpacting    int
	MissingNotImpacting int
	MissingNeedsReview  int
	RequiredCRCount     int
	OptionalCRCount     int
}

// HTMLGenerator generates HTML reports.
type HTMLGenerator struct {
	ruleEngine *rules.Engine
	tmpl       *template.Template
}

// NewHTMLGenerator creates a new HTML report generator.
func NewHTMLGenerator(ruleEngine *rules.Engine) *HTMLGenerator {
	tmpl := template.Must(template.New("report").Parse(htmlTemplate))
	return &HTMLGenerator{
		ruleEngine: ruleEngine,
		tmpl:       tmpl,
	}
}

// Generate creates an HTML report from the validation report.
func (g *HTMLGenerator) Generate(w io.Writer, report types.ValidationReport) error {
	htmlReport := g.buildHTMLReport(report)
	return g.tmpl.Execute(w, htmlReport)
}

func (g *HTMLGenerator) buildHTMLReport(report types.ValidationReport) HTMLReport {
	htmlReport := HTMLReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		Summary: SummaryData{
			TotalMissing: report.Summary.NumMissing,
			DiffCRs:      report.Summary.NumDiffCRs,
			TotalCRs:     report.Summary.TotalCRs,
			UnmatchedCRs: len(report.Summary.UnmatchedCRS),
			PatchedCRs:   report.Summary.PatchedCRs,
			MetadataHash: report.Summary.MetadataHash,
		},
	}

	if targetVersion := g.ruleEngine.GetTargetVersion(); !targetVersion.IsZero() {
		htmlReport.OCPVersion = targetVersion.String()
	}

	htmlReport.MissingCRs, htmlReport.ImpactStats = g.processMissingCRs(report.Summary.ValidationIssues, report.Diffs)
	htmlReport.Summary.TotalMissing = htmlReport.ImpactStats.RequiredCRCount + htmlReport.ImpactStats.OptionalCRCount
	htmlReport.Diffs, htmlReport.CountViolations = g.processDiffs(report.Diffs, &htmlReport.ImpactStats)

	return htmlReport
}

func (g *HTMLGenerator) processMissingCRs(issues types.ValidationIssues, diffs []types.Diff) ([]MissingCRGroup, ImpactStats) {
	stats := ImpactStats{}
	var groups []MissingCRGroup

	if len(issues) == 0 {
		return groups, stats
	}

	// Extract correlated templates from diffs to determine satisfied CRs.
	correlatedTemplates := rules.ExtractCorrelatedTemplates(diffs)
	missingCRResults := g.ruleEngine.EvaluateMissingCRs(issues, correlatedTemplates)

	groupKeys := make([]string, 0, len(issues))
	for k := range issues {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)

	for _, groupName := range groupKeys {
		group := MissingCRGroup{
			GroupName:  groupName,
			IsRequired: false, // Will be set based on CR impacts below.
		}

		deviations := issues[groupName]
		deviationKeys := make([]string, 0, len(deviations))
		for k := range deviations {
			deviationKeys = append(deviationKeys, k)
		}
		sort.Strings(deviationKeys)

		// Track if any CR in this group is impacting.
		hasImpactingCR := false

		for _, deviationName := range deviationKeys {
			deviation := deviations[deviationName]
			devData := DeviationData{
				Name:            deviationName,
				Message:         deviation.Msg,
				IsOneOfRequired: strings.Contains(deviation.Msg, "One of the following is required"),
				HasSatisfiedCR:  false,
			}

			for _, cr := range deviation.CRs {
				result := missingCRResults[cr]

				// Determine impact CSS - override to green for satisfied CRs.
				impactCSS := getImpactCSS(result.Impact)
				if result.IsSatisfied {
					impactCSS = "impact-satisfied"
					devData.HasSatisfiedCR = true
				}

				crData := MissingCRData{
					Path:        cr,
					Impact:      result.Impact,
					ImpactCSS:   impactCSS,
					IsSatisfied: result.IsSatisfied,
				}
				devData.CRs = append(devData.CRs, crData)

				if !result.IsSatisfied {
					switch result.Impact {
					case "Impacting":
						stats.MissingImpacting++
						hasImpactingCR = true
					case "NotImpacting":
						stats.MissingNotImpacting++
					default:
						stats.MissingNeedsReview++
					}
				}
			}

			group.Deviations = append(group.Deviations, devData)
		}

		// Group is required if any unsatisfied CR in it has Impacting impact.
		group.IsRequired = hasImpactingCR
		if hasImpactingCR {
			stats.RequiredCRCount += countUnsatisfiedGroupCRs(group)
		} else {
			stats.OptionalCRCount += countUnsatisfiedGroupCRs(group)
		}

		groups = append(groups, group)
	}

	return groups, stats
}

// countUnsatisfiedGroupCRs counts the number of unsatisfied CRs in a MissingCRGroup.
func countUnsatisfiedGroupCRs(group MissingCRGroup) int {
	count := 0
	for _, dev := range group.Deviations {
		for _, cr := range dev.CRs {
			if !cr.IsSatisfied {
				count++
			}
		}
	}
	return count
}

// getImpactPriority returns the sort priority for an impact (lower = first).
func getImpactPriority(impact string) int {
	switch impact {
	case "Impacting":
		return 0
	case "NotImpacting":
		return 1
	case "NeedsReview":
		return 2
	case "NotADeviation":
		return 3
	default:
		return 4
	}
}

func (g *HTMLGenerator) processDiffs(diffs []types.Diff, stats *ImpactStats) ([]DiffData, []CountViolationData) {
	var diffDataList []DiffData
	var allDiffChecks []types.DiffCheck

	for _, d := range diffs {
		// Handle empty diffs - add minimal DiffCheck for count rules only.
		if d.DiffOutput == "" {
			allDiffChecks = append(allDiffChecks, types.DiffCheck{
				CRName:           d.CRName,
				TemplateFileName: filepath.Base(d.CorrelatedTemplate),
			})
			continue
		}

		diffData := DiffData{
			CRName:      d.CRName,
			Template:    d.CorrelatedTemplate,
			Description: d.Description,
		}

		formattedDiff, err := parser.ParseExpectedAndFound(d.DiffOutput, d.CRName, filepath.Base(d.CorrelatedTemplate))
		if err != nil {
			continue
		}

		allDiffChecks = append(allDiffChecks, formattedDiff)
		ruleResult := g.ruleEngine.Evaluate(formattedDiff)

		for _, line := range formattedDiff.ExpectedNotFound {
			rules := getMatchingRulesHTML(line, "ExpectedNotFound", ruleResult)
			diffData.ExpectedNotFound = append(diffData.ExpectedNotFound, DiffLineData{
				Line:     escapeHTML(line),
				Rules:    rules,
				HasRules: len(rules) > 0,
			})
			if len(rules) == 0 {
				diffData.HasNeedsReview = true
			}
		}

		for _, line := range formattedDiff.FoundNotExpected {
			rules := getMatchingRulesHTML(line, "FoundNotExpected", ruleResult)
			diffData.FoundNotExpected = append(diffData.FoundNotExpected, DiffLineData{
				Line:     escapeHTML(line),
				Rules:    rules,
				HasRules: len(rules) > 0,
			})
			if len(rules) == 0 {
				diffData.HasNeedsReview = true
			}
		}

		for _, line := range formattedDiff.ExpectedValue {
			diffData.ExpectedValues = append(diffData.ExpectedValues, escapeHTML(line))
		}
		for _, line := range formattedDiff.FoundValue {
			rules := getMatchingRulesHTML(line, "ExpectedFound", ruleResult)
			diffData.FoundValues = append(diffData.FoundValues, DiffLineData{
				Line:     escapeHTML(line),
				Rules:    rules,
				HasRules: len(rules) > 0,
			})
			if len(rules) == 0 {
				diffData.HasNeedsReview = true
			}
		}

		finalImpact := ruleResult.Impact
		if !ruleResult.Matched {
			finalImpact = "NeedsReview"
			diffData.NoRulesMatched = true
			diffData.NoMatchComment = ruleResult.Comment
		} else if diffData.HasNeedsReview && finalImpact != "Impacting" {
			finalImpact = "NeedsReview"
		}

		diffData.OverallImpact = finalImpact
		diffData.OverallImpactCSS = getImpactCSS(finalImpact)

		for _, condResult := range ruleResult.Conditions {
			if condResult.Matched {
				diffData.MatchedRules = append(diffData.MatchedRules, RuleMatchData{
					RuleID:    condResult.RuleID,
					Impact:    condResult.Impact,
					ImpactCSS: getImpactCSS(condResult.Impact),
					Comment:   condResult.Comment,
				})
			}
		}

		switch finalImpact {
		case "Impacting":
			stats.Impacting++
		case "NotImpacting":
			stats.NotImpacting++
		case "NotADeviation":
			stats.NotADeviation++
		default:
			stats.NeedsReview++
		}

		diffDataList = append(diffDataList, diffData)
	}

	// Sort diffs by impact priority: Impacting -> NotImpacting -> NeedsReview -> NotADeviation.
	sort.SliceStable(diffDataList, func(i, j int) bool {
		return getImpactPriority(diffDataList[i].OverallImpact) < getImpactPriority(diffDataList[j].OverallImpact)
	})

	// Update Index and Total after sorting.
	for i := range diffDataList {
		diffDataList[i].Index = i + 1
		diffDataList[i].Total = len(diffDataList)
	}

	var countViolations []CountViolationData
	countResults := g.ruleEngine.EvaluateCountRules(allDiffChecks)
	for _, result := range countResults {
		countViolations = append(countViolations, CountViolationData{
			RuleID:      result.RuleID,
			Description: result.Description,
			Count:       result.Count,
			Impact:      result.Impact,
			ImpactCSS:   getImpactCSS(result.Impact),
			Comment:     result.Comment,
			MatchedCRs:  result.MatchedCRs,
		})

		switch result.Impact {
		case "Impacting":
			stats.Impacting++
		case "NotImpacting":
			stats.NotImpacting++
		case "NotADeviation":
			stats.NotADeviation++
		default:
			stats.NeedsReview++
		}
	}

	return diffDataList, countViolations
}

func getMatchingRulesHTML(line, diffType string, ruleResult rules.EvaluationResult) []RuleTagData {
	trimmedLine := strings.TrimSpace(line)
	var ruleTags []RuleTagData
	seen := make(map[string]bool)

	for _, condResult := range ruleResult.Conditions {
		if condResult.ConditionType == diffType && condResult.Matched {
			trimmedMatched := strings.TrimSpace(condResult.MatchedText)
			if strings.Contains(trimmedLine, trimmedMatched) || strings.Contains(trimmedMatched, trimmedLine) {
				if !seen[condResult.RuleID] {
					seen[condResult.RuleID] = true
					ruleTags = append(ruleTags, RuleTagData{
						ID:        condResult.RuleID,
						Comment:   condResult.Comment,
						Impact:    condResult.Impact,
						ImpactCSS: getImpactCSS(condResult.Impact),
					})
				}
			}
		}
	}
	return ruleTags
}

func getImpactCSS(impact string) string {
	switch impact {
	case "Impacting":
		return "impact-impacting"
	case "NotImpacting":
		return "impact-not-impacting"
	case "NotADeviation":
		return "impact-not-deviation"
	default:
		return "impact-needs-review"
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RDS Validation Report</title>
    <style>
        :root {
            --color-impacting: #dc3545;
            --color-not-impacting: #e6a817;
            --color-not-deviation: #28a745;
            --color-needs-review: #6c757d;
            --color-bg: #f5f5f5;
            --color-card-bg: #ffffff;
            --color-border: #dee2e6;
            --color-text: #212529;
            --color-text-muted: #6c757d;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            background: #343a40;
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }

        header h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }

        header .meta {
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .section {
            background: var(--color-card-bg);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            border: 1px solid var(--color-border);
        }

        .section h2 {
            font-size: 1.4rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--color-border);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section h2 .badge {
            font-size: 0.8rem;
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: normal;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }

        .stat-card {
            background: #5b7188;
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }

        .stat-card .value {
            font-size: 2.5rem;
            font-weight: bold;
        }

        .stat-card .label {
            font-size: 0.9rem;
            opacity: 0.9;
            margin-top: 5px;
        }

        .tooltip-container {
            position: relative;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .tooltip-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            font-size: 0.75rem;
            font-weight: bold;
            cursor: help;
        }

        .tooltip-icon:hover + .tooltip-text,
        .tooltip-text:hover {
            visibility: visible;
            opacity: 1;
        }

        .tooltip-text {
            visibility: hidden;
            opacity: 0;
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            background: #212529;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            white-space: nowrap;
            z-index: 100;
            transition: opacity 0.2s;
        }

        .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #212529 transparent transparent transparent;
        }

        .impact-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .impact-impacting {
            background-color: rgba(220, 53, 69, 0.15);
            color: var(--color-impacting);
            border: 1px solid var(--color-impacting);
        }

        .impact-not-impacting {
            background-color: rgba(230, 168, 23, 0.15);
            color: #a37c00;
            border: 1px solid var(--color-not-impacting);
        }

        .impact-not-deviation {
            background-color: rgba(40, 167, 69, 0.15);
            color: var(--color-not-deviation);
            border: 1px solid var(--color-not-deviation);
        }

        .impact-needs-review {
            background-color: rgba(108, 117, 125, 0.15);
            color: var(--color-needs-review);
            border: 1px solid var(--color-needs-review);
        }

        .impact-satisfied {
            background-color: rgba(40, 167, 69, 0.15);
            color: var(--color-not-deviation);
            border: 1px solid var(--color-not-deviation);
        }

        .none-found-box {
            border: 2px solid #fd7e14;
            background-color: rgba(253, 126, 20, 0.1);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }

        .none-found-header {
            color: #d63300;
            font-weight: 600;
            margin-bottom: 10px;
        }

        .group-card {
            border: 1px solid var(--color-border);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }

        .group-header {
            background: #f1f3f4;
            padding: 12px 15px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .deviation-item {
            padding: 12px 15px;
            border-bottom: 1px solid var(--color-border);
        }

        .deviation-item:last-child {
            border-bottom: none;
        }

        .deviation-name {
            font-weight: 500;
            color: #495057;
        }

        .deviation-msg {
            font-size: 0.9rem;
            color: var(--color-text-muted);
            margin-bottom: 8px;
        }

        .cr-list {
            list-style: none;
            margin-top: 10px;
        }

        .cr-list li {
            padding: 6px 0;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .diff-card {
            border: 1px solid var(--color-border);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .diff-header {
            background: #f1f3f4;
            padding: 15px;
            border-bottom: 1px solid var(--color-border);
        }

        .diff-header h3 {
            font-size: 1.1rem;
            margin-bottom: 8px;
        }

        .diff-meta {
            font-size: 0.85rem;
            color: var(--color-text-muted);
        }

        .diff-meta span {
            display: block;
            margin-bottom: 3px;
        }

        .diff-content {
            padding: 15px;
        }

        .diff-section {
            margin-bottom: 15px;
        }

        .diff-section h4 {
            font-size: 0.9rem;
            color: var(--color-text-muted);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .diff-lines {
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 0.85rem;
            background: #f8f9fa;
            border-radius: 4px;
            padding: 10px;
            overflow: visible;
        }

        .diff-line {
            padding: 3px 5px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            position: relative;
        }

        .diff-line.expected {
            background-color: rgba(40, 167, 69, 0.15);
            color: #155724;
            border-left: 3px solid var(--color-not-deviation);
        }

        .diff-line.found {
            background-color: rgba(220, 53, 69, 0.15);
            color: #721c24;
            border-left: 3px solid var(--color-impacting);
        }

        .diff-line span {
            white-space: pre-wrap;
            word-break: break-word;
        }

        .rule-tags-container {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
            margin-left: 10px;
            flex-shrink: 0;
        }

        .rule-tag {
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 3px;
            white-space: nowrap;
            cursor: help;
            position: relative;
            display: inline-block;
            border: 1px solid;
        }

        .rule-tag.impact-impacting {
            background: rgba(220, 53, 69, 0.1);
            border-color: var(--color-impacting);
            color: var(--color-impacting);
        }

        .rule-tag.impact-not-impacting {
            background: rgba(230, 168, 23, 0.1);
            border-color: var(--color-not-impacting);
            color: #a37c00;
        }

        .rule-tag.impact-not-deviation {
            background: rgba(40, 167, 69, 0.1);
            border-color: var(--color-not-deviation);
            color: var(--color-not-deviation);
        }

        .rule-tag.impact-needs-review {
            background: rgba(108, 117, 125, 0.1);
            border-color: var(--color-needs-review);
            color: var(--color-needs-review);
        }

        .rule-tag .tooltip {
            visibility: hidden;
            opacity: 0;
            position: fixed;
            background-color: #333;
            color: white;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 0.85rem;
            white-space: normal;
            width: max-content;
            max-width: 350px;
            z-index: 10000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            text-align: left;
            line-height: 1.5;
            pointer-events: none;
        }

        .rule-tag:hover .tooltip {
            visibility: visible;
            opacity: 1;
        }

        .diff-result {
            background: #f8f9fa;
            padding: 15px;
            border-top: 1px solid var(--color-border);
        }

        .diff-result h4 {
            margin-bottom: 10px;
        }

        .rules-list {
            list-style: none;
        }

        .rules-list li {
            padding: 5px 0;
            font-size: 0.9rem;
        }

        .violation-card {
            border: 1px solid var(--color-border);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }

        .violation-card.impact-impacting {
            border-color: var(--color-impacting);
        }

        .violation-card.impact-impacting .violation-header {
            background: rgba(220, 53, 69, 0.12);
            border-left: 4px solid var(--color-impacting);
        }

        .violation-card.impact-not-impacting {
            border-color: var(--color-not-impacting);
        }

        .violation-card.impact-not-impacting .violation-header {
            background: rgba(230, 168, 23, 0.12);
            border-left: 4px solid var(--color-not-impacting);
        }

        .violation-card.impact-not-deviation {
            border-color: var(--color-not-deviation);
        }

        .violation-card.impact-not-deviation .violation-header {
            background: rgba(40, 167, 69, 0.12);
            border-left: 4px solid var(--color-not-deviation);
        }

        .violation-card.impact-needs-review {
            border-color: var(--color-needs-review);
        }

        .violation-card.impact-needs-review .violation-header {
            background: rgba(108, 117, 125, 0.12);
            border-left: 4px solid var(--color-needs-review);
        }

        .violation-header {
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--color-border);
        }

        .violation-body {
            padding: 15px;
        }

        .matched-crs {
            margin-top: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .matched-crs h5 {
            font-size: 0.85rem;
            margin-bottom: 8px;
        }

        .matched-crs ul {
            list-style: none;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 0.8rem;
        }

        .impact-summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
        }

        .impact-stat {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            border: 2px solid;
        }

        .impact-stat.impacting {
            border-color: var(--color-impacting);
            background: rgba(220, 53, 69, 0.4);
        }

        .impact-stat.not-impacting {
            border-color: var(--color-not-impacting);
            background: rgba(230, 168, 23, 0.4);
        }

        .impact-stat.not-deviation {
            border-color: var(--color-not-deviation);
            background: rgba(40, 167, 69, 0.05);
        }

        .impact-stat.needs-review {
            border-color: var(--color-needs-review);
            background: rgba(108, 117, 125, 0.05);
        }

        .impact-stat .count {
            font-size: 2.5rem;
            font-weight: bold;
        }

        .impact-stat .label {
            font-size: 0.9rem;
            color: var(--color-text-muted);
        }

        details.collapsible {
            margin-bottom: 15px;
            border: 1px solid var(--color-border);
            border-radius: 8px;
            overflow: visible;
        }

        details.collapsible summary {
            cursor: pointer;
            padding: 15px;
            background: #f8f9fa;
            font-weight: 500;
            display: flex;
            justify-content: space-between;
            align-items: center;
            list-style: none;
        }

        details.collapsible summary::-webkit-details-marker {
            display: none;
        }

        details.collapsible summary::after {
            content: "+";
            font-size: 1.2rem;
            font-weight: bold;
            color: #6c757d;
            transition: transform 0.2s;
        }

        details.collapsible[open] summary::after {
            content: "-";
        }

        details.collapsible summary:hover {
            opacity: 0.9;
        }

        details.collapsible[open] summary {
            border-bottom: 1px solid var(--color-border);
        }

        details.collapsible .collapsible-content {
            padding: 15px;
            overflow: visible;
        }

        details.collapsible.impact-impacting {
            border-color: var(--color-impacting);
        }

        details.collapsible.impact-impacting summary {
            background: rgba(220, 53, 69, 0.12);
            border-left: 4px solid var(--color-impacting);
        }

        details.collapsible.impact-not-impacting {
            border-color: var(--color-not-impacting);
        }

        details.collapsible.impact-not-impacting summary {
            background: rgba(230, 168, 23, 0.12);
            border-left: 4px solid var(--color-not-impacting);
        }

        details.collapsible.impact-not-deviation {
            border-color: var(--color-not-deviation);
        }

        details.collapsible.impact-not-deviation summary {
            background: rgba(40, 167, 69, 0.12);
            border-left: 4px solid var(--color-not-deviation);
        }

        details.collapsible.impact-needs-review {
            border-color: var(--color-needs-review);
        }

        details.collapsible.impact-needs-review summary {
            background: rgba(108, 117, 125, 0.12);
            border-left: 4px solid var(--color-needs-review);
        }

        details.category-collapsible {
            margin-bottom: 20px;
            border: 1px solid var(--color-border);
            border-radius: 8px;
            overflow: visible;
        }

        details.category-collapsible summary {
            cursor: pointer;
            padding: 15px 20px;
            background: #e9ecef;
            font-weight: 600;
            font-size: 1.1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            list-style: none;
        }

        details.category-collapsible summary::-webkit-details-marker {
            display: none;
        }

        details.category-collapsible summary::after {
            content: "+";
            font-size: 1.3rem;
            font-weight: bold;
            color: #6c757d;
        }

        details.category-collapsible[open] summary::after {
            content: "-";
        }

        details.category-collapsible summary:hover {
            opacity: 0.9;
        }

        details.category-collapsible[open] summary {
            border-bottom: 1px solid var(--color-border);
        }

        details.category-collapsible .category-content {
            padding: 15px;
        }

        details.category-collapsible.required {
            border-color: var(--color-impacting);
        }

        details.category-collapsible.required summary {
            background: rgba(220, 53, 69, 0.4);
            border-left: 4px solid var(--color-impacting);
        }

        details.category-collapsible.optional {
            border-color: var(--color-not-impacting);
        }

        details.category-collapsible.optional summary {
            background: rgba(230, 168, 23, 0.4);
            border-left: 4px solid var(--color-not-impacting);
        }

        .category-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .category-count {
            font-size: 0.85rem;
            font-weight: normal;
            color: var(--color-text-muted);
            background: #fff;
            padding: 2px 10px;
            border-radius: 12px;
            border: 1px solid var(--color-border);
        }

        details.group-collapsible {
            margin-bottom: 10px;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            overflow: visible;
        }

        details.group-collapsible summary {
            cursor: pointer;
            padding: 12px 15px;
            background: #f8f9fa;
            font-weight: 500;
            display: flex;
            justify-content: space-between;
            align-items: center;
            list-style: none;
        }

        details.group-collapsible summary::-webkit-details-marker {
            display: none;
        }

        details.group-collapsible summary::after {
            content: "+";
            font-size: 1.2rem;
            font-weight: bold;
            color: #6c757d;
        }

        details.group-collapsible[open] > summary::after {
            content: "-";
        }

        details.group-collapsible summary:hover {
            background: #e0e0e0;
        }

        details.group-collapsible[open] > summary {
            border-bottom: 1px solid #e9ecef;
        }

        details.group-collapsible .group-content {
            padding: 10px 15px;
        }

        .category-collapsible.required .group-collapsible summary {
            background: rgba(220, 53, 69, 0.08);
        }

        .category-collapsible.required .group-collapsible summary:hover {
            background: rgba(220, 53, 69, 0.25);
        }

        .category-collapsible.required .group-collapsible summary::after {
            content: "+";
            color: var(--color-impacting);
        }

        .category-collapsible.required .group-collapsible[open] > summary::after {
            content: "-";
            color: var(--color-impacting);
        }

        .category-collapsible.optional .group-collapsible summary {
            background: rgba(230, 168, 23, 0.08);
        }

        .category-collapsible.optional .group-collapsible summary:hover {
            background: rgba(230, 168, 23, 0.30);
        }

        .category-collapsible.optional .group-collapsible summary::after {
            content: "+";
            color: var(--color-not-impacting);
        }

        .category-collapsible.optional .group-collapsible[open] > summary::after {
            content: "-";
            color: var(--color-not-impacting);
        }

        .summary-info {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .summary-title {
            font-weight: 600;
        }

        .summary-count {
            font-size: 0.85rem;
            color: var(--color-text-muted);
        }

        .no-data {
            text-align: center;
            padding: 40px;
            color: var(--color-text-muted);
            font-style: italic;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }

            .section {
                box-shadow: none;
                border: 1px solid #ddd;
                break-inside: avoid;
            }

            header {
                background: #343a40 !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }

        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .diff-line {
                flex-direction: column;
            }

            .rule-tags-container {
                margin-left: 0;
                margin-top: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>RDS Validation Report</h1>
            <div class="meta">
                <span>Generated at {{.GeneratedAt}}{{if .OCPVersion}}. Using target OCP Version: {{.OCPVersion}}{{end}} </span>
            </div>
        </header>

        <section class="section">
            <h2>Validation Summary</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="value">{{.Summary.TotalCRs}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            CRs Scanned
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">Total number of CRs that were scanned</span>
                        </span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="value">{{.Summary.TotalMissing}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Missing CRs
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">CRs that were expected in the cluster but were not found</span>
                        </span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="value">{{.Summary.DiffCRs}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            CRs with Differences
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">CRs that have differences between the expected and found configuration</span>
                        </span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="value">{{.Summary.UnmatchedCRs}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Unmatched CRs
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">CRs that were found in the cluster but do not match any RDS template</span>
                        </span>
                    </div>
                </div>
            </div>
        </section>

        <section class="section">
            <h2>Impact Summary</h2>
            <h4 style="margin-bottom: 15px; color: #6c757d;">Missing CRs</h4>
            <div class="impact-summary-grid">
                <div class="impact-stat impacting">
                    <div class="count">{{.ImpactStats.MissingImpacting}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Impacting
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">Must be addressed. No need to involve the telco team.</span>
                        </span>
                    </div>
                </div>
                <div class="impact-stat not-impacting">
                    <div class="count">{{.ImpactStats.MissingNotImpacting}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Not Impacting
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">Engage with the telco team. Might require RDS expansion or support exception.</span>
                        </span>
                    </div>
                </div>
            </div>
            <h4 style="margin: 20px 0 15px 0; color: #6c757d;">Detected Differences</h4>
            <div class="impact-summary-grid">
                <div class="impact-stat impacting">
                    <div class="count">{{.ImpactStats.Impacting}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Impacting
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">Must be addressed. No need to involve the telco team.</span>
                        </span>
                    </div>
                </div>
                <div class="impact-stat not-impacting">
                    <div class="count">{{.ImpactStats.NotImpacting}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Not Impacting
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">Engage with the telco team. Might require RDS expansion or support exception.</span>
                        </span>
                    </div>
                </div>
                <div class="impact-stat needs-review">
                    <div class="count">{{.ImpactStats.NeedsReview}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Needs Review
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">The tool couldn't identify the impact. Engage with the telco team to assess impact.</span>
                        </span>
                    </div>
                </div>
                <div class="impact-stat not-deviation">
                    <div class="count">{{.ImpactStats.NotADeviation}}</div>
                    <div class="label">
                        <span class="tooltip-container">
                            Not a Deviation
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">No action required, you can keep these.</span>
                        </span>
                    </div>
                </div>
            </div>

        </section>

        <section class="section">
            <h2>Missing Custom Resources <span class="badge" style="background: #6c757d; color: white;">{{.Summary.TotalMissing}}</span></h2>
            {{if .MissingCRs}}
            <details class="category-collapsible required" open>
                <summary>
                    <div class="category-title">
                        <span class="tooltip-container">
                            Required
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">These CRs are required by the reference configuration and must be present in the cluster.</span>
                        </span>
                        <span class="category-count">{{.ImpactStats.RequiredCRCount}} CRs</span>
                    </div>
                </summary>
                <div class="category-content">
                    {{range .MissingCRs}}{{if .IsRequired}}
                    <details class="group-collapsible">
                        <summary>
                            <div class="summary-info">
                                <span class="summary-title">{{.GroupName}}</span>
                            </div>
                        </summary>
                        <div class="group-content">
                            {{range .Deviations}}
                            <div class="deviation-item" style="padding: 10px 0; border-bottom: 1px solid #eee;">
                                <div class="deviation-name" style="font-weight: 500; margin-bottom: 5px;">{{.Name}}</div>
                                <div class="deviation-msg" style="font-size: 0.9rem; color: #6c757d; margin-bottom: 10px;">{{.Message}}</div>
                                {{if and .IsOneOfRequired (not .HasSatisfiedCR)}}
                                <div style="color: #dc3545; font-weight: 600; margin-bottom: 8px;">🔴 None found</div>
                                {{end}}
                                <ul class="cr-list" style="list-style: none; margin: 0; padding: 0;{{if and .IsOneOfRequired (not .HasSatisfiedCR)}} margin-left: 20px;{{end}}">
                                    {{range .CRs}}
                                    <li style="padding: 4px 0; display: flex; align-items: center; gap: 8px;">
                                        {{if .IsSatisfied}}
                                        <span class="impact-badge impact-satisfied">✓ Satisfied</span>
                                        {{else}}
                                        <span class="impact-badge {{.ImpactCSS}}">{{.Impact}}</span>
                                        {{end}}
                                        <span style="font-family: monospace; font-size: 0.85rem;">{{.Path}}</span>
                                    </li>
                                    {{end}}
                                </ul>
                            </div>
                            {{end}}
                        </div>
                    </details>
                    {{end}}{{end}}
                </div>
            </details>

            <details class="category-collapsible optional">
                <summary>
                    <div class="category-title">
                        <span class="tooltip-container">
                            Optional
                            <span class="tooltip-icon">?</span>
                            <span class="tooltip-text">These CRs, although optional, are expected. Engage with the telco team to explain why these are missing from the cluster.</span>
                        </span>
                        <span class="category-count">{{.ImpactStats.OptionalCRCount}} CRs</span>
                    </div>
                </summary>
                <div class="category-content">
                    {{range .MissingCRs}}{{if not .IsRequired}}
                    <details class="group-collapsible">
                        <summary>
                            <div class="summary-info">
                                <span class="summary-title">{{.GroupName}}</span>
                            </div>
                        </summary>
                        <div class="group-content">
                            {{range .Deviations}}
                            <div class="deviation-item" style="padding: 10px 0; border-bottom: 1px solid #eee;">
                                <div class="deviation-name" style="font-weight: 500; margin-bottom: 5px;">{{.Name}}</div>
                                <div class="deviation-msg" style="font-size: 0.9rem; color: #6c757d; margin-bottom: 10px;">{{.Message}}</div>
                                {{if and .IsOneOfRequired (not .HasSatisfiedCR)}}
                                <div style="color: #dc3545; font-weight: 600; margin-bottom: 8px;">🔴 None found</div>
                                {{end}}
                                <ul class="cr-list" style="list-style: none; margin: 0; padding: 0;{{if and .IsOneOfRequired (not .HasSatisfiedCR)}} margin-left: 20px;{{end}}">
                                    {{range .CRs}}
                                    <li style="padding: 4px 0; display: flex; align-items: center; gap: 8px;">
                                        {{if .IsSatisfied}}
                                        <span class="impact-badge impact-satisfied">✓ Satisfied</span>
                                        {{else}}
                                        <span class="impact-badge {{.ImpactCSS}}">{{.Impact}}</span>
                                        {{end}}
                                        <span style="font-family: monospace; font-size: 0.85rem;">{{.Path}}</span>
                                    </li>
                                    {{end}}
                                </ul>
                            </div>
                            {{end}}
                        </div>
                    </details>
                    {{end}}{{end}}
                </div>
            </details>
            {{else}}
            <div class="no-data">No missing CRs found.</div>
            {{end}}
        </section>

        <section class="section">
            <h2>Detected Differences <span class="badge" style="background: #6c757d; color: white;">{{len .Diffs}}</span></h2>
            {{if .Diffs}}
            {{range .Diffs}}
            <details class="collapsible {{.OverallImpactCSS}}">
                <summary>
                    <div class="summary-info">
                        <span class="summary-title">{{.CRName}}</span>
                        <span class="impact-badge {{.OverallImpactCSS}}">{{.OverallImpact}}</span>
                        <span class="summary-count">{{.Index}}/{{.Total}}</span>
                    </div>
                </summary>
                <div class="collapsible-content">
                    <div class="diff-meta" style="margin-bottom: 15px; font-size: 0.9rem; color: #6c757d;">
                        <div><strong>Template:</strong> {{.Template}}</div>
                        {{if .Description}}<div><strong>Description:</strong> {{.Description}}</div>{{end}}
                    </div>

                    {{if .ExpectedNotFound}}
                    <div class="diff-section">
                        <h4>Expected but not found</h4>
                        <div class="diff-lines">
                            {{range .ExpectedNotFound}}
                            <div class="diff-line expected">
                                <span>{{.Line}}</span>
                                {{if .HasRules}}{{range .Rules}}<span class="rule-tag {{.ImpactCSS}}">{{.ID}}<span class="tooltip">{{.Comment}}</span></span>{{end}}{{end}}
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}

                    {{if .FoundNotExpected}}
                    <div class="diff-section">
                        <h4>Found but not expected</h4>
                        <div class="diff-lines">
                            {{range .FoundNotExpected}}
                            <div class="diff-line found">
                                <span>{{.Line}}</span>
                                {{if .HasRules}}{{range .Rules}}<span class="rule-tag {{.ImpactCSS}}">{{.ID}}<span class="tooltip">{{.Comment}}</span></span>{{end}}{{end}}
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}

                    {{if .ExpectedValues}}
                    <div class="diff-section">
                        <h4>Value Differences</h4>
                        <div class="diff-lines">
                            <div style="margin-bottom: 10px;">
                                <strong style="color: #155724;">Expected:</strong>
                                {{range .ExpectedValues}}
                                <div class="diff-line expected"><span>{{.}}</span></div>
                                {{end}}
                            </div>
                            <div>
                                <strong style="color: #721c24;">Found:</strong>
                                {{range .FoundValues}}
                                <div class="diff-line found">
                                    <span>{{.Line}}</span>
                                    {{if .HasRules}}{{range .Rules}}<span class="rule-tag {{.ImpactCSS}}">{{.ID}}<span class="tooltip">{{.Comment}}</span></span>{{end}}{{end}}
                                </div>
                                {{end}}
                            </div>
                        </div>
                    </div>
                    {{end}}

                    {{if .MatchedRules}}
                    <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee; display: flex; gap: 5px; flex-wrap: wrap; align-items: center;">
                        <span style="font-size: 0.9rem; color: #6c757d;">Rules:</span>
                        {{range .MatchedRules}}<span class="rule-tag {{.ImpactCSS}}">{{.RuleID}}<span class="tooltip">{{.Comment}}</span></span>{{end}}
                    </div>
                    {{end}}

                    {{if .HasNeedsReview}}
                    <p style="margin-top: 10px; font-size: 0.9rem; color: #6c757d;">
                        &#x1F50D; Some lines need review by the telco team
                    </p>
                    {{end}}
                    {{if .NoRulesMatched}}
                    <p style="margin-top: 10px; font-size: 0.9rem; color: #6c757d;">
                        &#x26AA; {{.NoMatchComment}}
                    </p>
                    {{end}}
                </div>
            </details>
            {{end}}
            {{else}}
            <div class="no-data">No differences detected.</div>
            {{end}}
        </section>

        {{if .CountViolations}}
        <section class="section">
            <h2>Count Rule Violations <span class="badge" style="background: #6c757d; color: white;">{{len .CountViolations}}</span></h2>
            {{range .CountViolations}}
            <div class="violation-card {{.ImpactCSS}}">
                <div class="violation-header">
                    <div>
                        <strong>{{.RuleID}}</strong>
                        <span style="margin-left: 10px; color: #6c757d;">{{.Description}}</span>
                    </div>
                    <span class="impact-badge {{.ImpactCSS}}">{{.Impact}}</span>
                </div>
                <div class="violation-body">
                    <p><strong>Count:</strong> {{.Count}} CRs matched</p>
                    <p><strong>Comment:</strong> {{.Comment}}</p>
                    {{if .MatchedCRs}}
                    <div class="matched-crs">
                        <h5>Matched CRs:</h5>
                        <ul>
                            {{range .MatchedCRs}}
                            <li>{{.}}</li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </section>
        {{end}}

        <footer style="text-align: center; padding: 20px; color: #6c757d; font-size: 0.85rem;">
            Generated using <a href="https://github.com/openshift-kni/rds-analyzer">RDS Analyzer</a>
        </footer>
    </div>

    <script>
        document.querySelectorAll('.rule-tag').forEach(tag => {
            const tooltip = tag.querySelector('.tooltip');
            if (!tooltip) return;

            tag.addEventListener('mouseenter', (e) => {
                const rect = tag.getBoundingClientRect();
                const tooltipRect = tooltip.getBoundingClientRect();

                let top = rect.top - 10;
                let left = rect.left + (rect.width / 2);

                const tooltipWidth = Math.min(350, tooltip.scrollWidth);
                if (left - tooltipWidth/2 < 10) {
                    left = tooltipWidth/2 + 10;
                } else if (left + tooltipWidth/2 > window.innerWidth - 10) {
                    left = window.innerWidth - tooltipWidth/2 - 10;
                }

                if (top - tooltip.offsetHeight < 10) {
                    top = rect.bottom + 10 + tooltip.offsetHeight;
                }

                tooltip.style.left = left + 'px';
                tooltip.style.top = (top - tooltip.offsetHeight) + 'px';
                tooltip.style.transform = 'translateX(-50%)';
            });
        });
    </script>
</body>
</html>`
