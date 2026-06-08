package report

import (
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openshift-kni/rds-analyzer/pkg/parser"
	"github.com/openshift-kni/rds-analyzer/pkg/rules"
	"github.com/openshift-kni/rds-analyzer/pkg/types"
)

// JSONReport contains all data for the JSON output.
type JSONReport struct {
	Metadata        JSONMetadata         `json:"Metadata"`
	Summary         JSONSummary          `json:"Summary"`
	ImpactSummary   JSONImpactSummary    `json:"ImpactSummary"`
	MissingCRs      []JSONMissingGroup   `json:"MissingCRs"`
	Diffs           []JSONDiffEntry      `json:"Diffs"`
	CountViolations []JSONCountViolation `json:"CountViolations"`
	UnmatchedCRs    []string             `json:"UnmatchedCRs"`
}

// JSONMetadata contains report metadata.
type JSONMetadata struct {
	GeneratedAt string `json:"GeneratedAt"`
	OCPVersion  string `json:"OCPVersion"`
	RDSVariant  string `json:"RDSVariant"`
	RulesFile   string `json:"RulesFile"`
}

// JSONSummary contains validation summary statistics.
type JSONSummary struct {
	TotalCRs     int    `json:"TotalCRs"`
	NumMissing   int    `json:"NumMissing"`
	NumDiffCRs   int    `json:"NumDiffCRs"`
	UnmatchedCRs int    `json:"UnmatchedCRs"`
	PatchedCRs   int    `json:"PatchedCRs"`
	MetadataHash string `json:"MetadataHash"`
}

// JSONImpactSummary contains impact statistics for diffs and missing CRs.
type JSONImpactSummary struct {
	Diffs      JSONDiffImpactStats    `json:"Diffs"`
	MissingCRs JSONMissingImpactStats `json:"MissingCRs"`
}

// JSONDiffImpactStats contains impact counts for detected differences.
type JSONDiffImpactStats struct {
	Impacting     int `json:"Impacting"`
	NotImpacting  int `json:"NotImpacting"`
	NeedsReview   int `json:"NeedsReview"`
	NotADeviation int `json:"NotADeviation"`
}

// JSONMissingImpactStats contains impact counts for missing CRs.
type JSONMissingImpactStats struct {
	Impacting      int `json:"Impacting"`
	NotImpacting   int `json:"NotImpacting"`
	NeedsReview    int `json:"NeedsReview"`
	RequiredGroups int `json:"RequiredGroups"`
	OptionalGroups int `json:"OptionalGroups"`
}

// JSONMissingGroup represents a group of missing CRs.
type JSONMissingGroup struct {
	GroupName  string              `json:"GroupName"`
	IsRequired bool                `json:"IsRequired"`
	Deviations []JSONDeviationData `json:"Deviations"`
}

// JSONDeviationData represents a deviation within a group.
type JSONDeviationData struct {
	Name            string          `json:"Name"`
	Message         string          `json:"Message"`
	IsOneOfRequired bool            `json:"IsOneOfRequired"`
	HasSatisfiedCR  bool            `json:"HasSatisfiedCR"`
	CRs             []JSONMissingCR `json:"CRs"`
}

// JSONMissingCR represents a single missing CR.
type JSONMissingCR struct {
	Path        string `json:"Path"`
	Impact      string `json:"Impact"`
	IsSatisfied bool   `json:"IsSatisfied"`
}

// JSONDiffEntry represents a single CR diff with rule evaluation.
type JSONDiffEntry struct {
	CRName           string           `json:"CRName"`
	TemplateFileName string           `json:"TemplateFileName"`
	Description      string           `json:"Description"`
	DiffOutput       string           `json:"DiffOutput"`
	OverallImpact    string           `json:"OverallImpact"`
	Sections         JSONDiffSections `json:"Sections"`
	MatchedRules     []JSONRuleMatch  `json:"MatchedRules"`
}

// JSONDiffSections contains the categorized diff lines.
type JSONDiffSections struct {
	ExpectedNotFound []JSONDiffLine          `json:"ExpectedNotFound"`
	FoundNotExpected []JSONDiffLine          `json:"FoundNotExpected"`
	ExpectedFound    []JSONExpectedFoundLine `json:"ExpectedFound"`
}

// JSONDiffLine represents a diff line with its matched rules.
type JSONDiffLine struct {
	Line         string          `json:"Line"`
	MatchedRules []JSONRuleMatch `json:"MatchedRules"`
}

// JSONExpectedFoundLine represents a paired expected/found value difference.
type JSONExpectedFoundLine struct {
	ExpectedLine string          `json:"ExpectedLine"`
	FoundLine    string          `json:"FoundLine"`
	MatchedRules []JSONRuleMatch `json:"MatchedRules"`
}

// JSONRuleMatch represents a matched rule condition.
type JSONRuleMatch struct {
	RuleID        string `json:"RuleID"`
	Impact        string `json:"Impact"`
	Comment       string `json:"Comment"`
	SupportingDoc string `json:"SupportingDoc"`
}

// JSONCountViolation represents a count rule violation.
type JSONCountViolation struct {
	RuleID        string   `json:"RuleID"`
	Description   string   `json:"Description"`
	Count         int      `json:"Count"`
	Impact        string   `json:"Impact"`
	Comment       string   `json:"Comment"`
	MatchedCRs    []string `json:"MatchedCRs"`
	SupportingDoc string   `json:"SupportingDoc"`
}

// JSONGenerator generates JSON reports.
type JSONGenerator struct {
	ruleEngine *rules.Engine
}

// NewJSONGenerator creates a new JSON report generator.
func NewJSONGenerator(ruleEngine *rules.Engine) *JSONGenerator {
	return &JSONGenerator{
		ruleEngine: ruleEngine,
	}
}

// Generate creates a JSON report from the validation report and writes it to the given writer.
func (g *JSONGenerator) Generate(w io.Writer, report types.ValidationReport) error {
	jsonReport := g.buildJSONReport(report)
	return json.NewEncoder(w).Encode(jsonReport)
}

func (g *JSONGenerator) buildJSONReport(report types.ValidationReport) JSONReport {
	jsonReport := JSONReport{
		Metadata: JSONMetadata{
			GeneratedAt: time.Now().Format(time.RFC3339),
			RulesFile:   g.ruleEngine.GetRulesFile(),
		},
		Summary: JSONSummary{
			TotalCRs:     report.Summary.TotalCRs,
			NumMissing:   report.Summary.NumMissing,
			NumDiffCRs:   report.Summary.NumDiffCRs,
			UnmatchedCRs: len(report.Summary.UnmatchedCRS),
			PatchedCRs:   report.Summary.PatchedCRs,
			MetadataHash: report.Summary.MetadataHash,
		},
		MissingCRs:      []JSONMissingGroup{},
		Diffs:           []JSONDiffEntry{},
		CountViolations: []JSONCountViolation{},
		UnmatchedCRs:    ensureStringSlice(report.Summary.UnmatchedCRS),
	}

	if targetVersion := g.ruleEngine.GetTargetVersion(); !targetVersion.IsZero() {
		jsonReport.Metadata.OCPVersion = targetVersion.String()
	}
	jsonReport.Metadata.RDSVariant = g.ruleEngine.GetRDSVariant()

	jsonReport.MissingCRs, jsonReport.ImpactSummary.MissingCRs = g.processMissingCRs(
		report.Summary.ValidationIssues, report.Diffs,
	)
	jsonReport.Summary.NumMissing = jsonReport.ImpactSummary.MissingCRs.RequiredGroups +
		jsonReport.ImpactSummary.MissingCRs.OptionalGroups

	var countViolations []JSONCountViolation
	jsonReport.Diffs, countViolations, jsonReport.ImpactSummary.Diffs = g.processDiffs(report.Diffs)
	jsonReport.CountViolations = countViolations

	return jsonReport
}

func (g *JSONGenerator) processMissingCRs(issues types.ValidationIssues, diffs []types.Diff) ([]JSONMissingGroup, JSONMissingImpactStats) {
	stats := JSONMissingImpactStats{}
	groups := []JSONMissingGroup{}

	if len(issues) == 0 {
		return groups, stats
	}

	correlatedTemplates := rules.ExtractCorrelatedTemplates(diffs)
	missingCRResults := g.ruleEngine.EvaluateMissingCRs(issues, correlatedTemplates)

	groupKeys := make([]string, 0, len(issues))
	for k := range issues {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)

	for _, groupName := range groupKeys {
		group := JSONMissingGroup{
			GroupName:  groupName,
			Deviations: []JSONDeviationData{},
		}

		deviations := issues[groupName]
		deviationKeys := make([]string, 0, len(deviations))
		for k := range deviations {
			deviationKeys = append(deviationKeys, k)
		}
		sort.Strings(deviationKeys)

		hasImpactingCR := false

		for _, deviationName := range deviationKeys {
			deviation := deviations[deviationName]
			devData := JSONDeviationData{
				Name:            deviationName,
				Message:         deviation.Msg,
				IsOneOfRequired: strings.Contains(deviation.Msg, "One of the following is required"),
				HasSatisfiedCR:  false,
				CRs:             []JSONMissingCR{},
			}

			for _, cr := range deviation.CRs {
				result := missingCRResults[cr]

				if result.IsSatisfied {
					devData.HasSatisfiedCR = true
				}

				devData.CRs = append(devData.CRs, JSONMissingCR{
					Path:        cr,
					Impact:      result.Impact,
					IsSatisfied: result.IsSatisfied,
				})

				if !result.IsSatisfied {
					switch result.Impact {
					case "Impacting":
						stats.Impacting++
						hasImpactingCR = true
					case "NotImpacting":
						stats.NotImpacting++
					default:
						stats.NeedsReview++
					}
				}
			}

			group.Deviations = append(group.Deviations, devData)
		}

		group.IsRequired = hasImpactingCR
		unsatisfied := countUnsatisfiedGroupCRsJSON(group)
		if hasImpactingCR {
			stats.RequiredGroups += unsatisfied
		} else {
			stats.OptionalGroups += unsatisfied
		}

		groups = append(groups, group)
	}

	return groups, stats
}

// countUnsatisfiedGroupCRsJSON counts the number of unsatisfied CRs in a JSONMissingGroup.
func countUnsatisfiedGroupCRsJSON(group JSONMissingGroup) int {
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

func (g *JSONGenerator) processDiffs(diffs []types.Diff) ([]JSONDiffEntry, []JSONCountViolation, JSONDiffImpactStats) {
	stats := JSONDiffImpactStats{}
	diffEntries := []JSONDiffEntry{}
	var allDiffChecks []types.DiffCheck

	for _, d := range diffs {
		if d.DiffOutput == "" {
			allDiffChecks = append(allDiffChecks, minimalDiffCheck(d))
			continue
		}

		formattedDiff := parser.ParseExpectedAndFound(d.DiffOutput, d.CRName, filepath.Base(d.CorrelatedTemplate))

		allDiffChecks = append(allDiffChecks, formattedDiff)
		ruleResult := g.ruleEngine.Evaluate(formattedDiff)

		entry := JSONDiffEntry{
			CRName:           d.CRName,
			TemplateFileName: d.CorrelatedTemplate,
			Description:      d.Description,
			DiffOutput:       d.DiffOutput,
			MatchedRules:     []JSONRuleMatch{},
			Sections: JSONDiffSections{
				ExpectedNotFound: []JSONDiffLine{},
				FoundNotExpected: []JSONDiffLine{},
				ExpectedFound:    []JSONExpectedFoundLine{},
			},
		}

		hasNeedsReview := false

		for _, line := range formattedDiff.ExpectedNotFound {
			rules := getMatchingRulesJSON(line, "ExpectedNotFound", ruleResult)
			entry.Sections.ExpectedNotFound = append(entry.Sections.ExpectedNotFound, JSONDiffLine{
				Line:         line,
				MatchedRules: rules,
			})
			if len(rules) == 0 {
				hasNeedsReview = true
			}
		}

		for _, line := range formattedDiff.FoundNotExpected {
			rules := getMatchingRulesJSON(line, "FoundNotExpected", ruleResult)
			entry.Sections.FoundNotExpected = append(entry.Sections.FoundNotExpected, JSONDiffLine{
				Line:         line,
				MatchedRules: rules,
			})
			if len(rules) == 0 {
				hasNeedsReview = true
			}
		}

		// Pair expected and found values.
		for i := range formattedDiff.FoundValue {
			paired := JSONExpectedFoundLine{
				MatchedRules: []JSONRuleMatch{},
			}
			if i < len(formattedDiff.ExpectedValue) {
				paired.ExpectedLine = formattedDiff.ExpectedValue[i]
			}
			paired.FoundLine = formattedDiff.FoundValue[i]
			paired.MatchedRules = getMatchingRulesJSON(formattedDiff.FoundValue[i], "ExpectedFound", ruleResult)
			if len(paired.MatchedRules) == 0 {
				hasNeedsReview = true
			}
			entry.Sections.ExpectedFound = append(entry.Sections.ExpectedFound, paired)
		}

		finalImpact := determineImpact(ruleResult, hasNeedsReview)
		entry.OverallImpact = finalImpact

		for _, condResult := range ruleResult.Conditions {
			if condResult.Matched {
				entry.MatchedRules = append(entry.MatchedRules, JSONRuleMatch{
					RuleID:        condResult.RuleID,
					Impact:        condResult.Impact,
					Comment:       condResult.Comment,
					SupportingDoc: condResult.SupportingDoc,
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

		diffEntries = append(diffEntries, entry)
	}

	countViolations := []JSONCountViolation{}
	countResults := g.ruleEngine.EvaluateCountRules(allDiffChecks)
	for _, result := range countResults {
		countViolations = append(countViolations, JSONCountViolation{
			RuleID:        result.RuleID,
			Description:   result.Description,
			Count:         result.Count,
			Impact:        result.Impact,
			Comment:       result.Comment,
			MatchedCRs:    ensureStringSlice(result.MatchedCRs),
			SupportingDoc: result.SupportingDoc,
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

	return diffEntries, countViolations, stats
}

// getMatchingRulesJSON returns rule matches for a specific line and diff type.
func getMatchingRulesJSON(line, diffType string, ruleResult rules.EvaluationResult) []JSONRuleMatch {
	trimmedLine := strings.TrimSpace(line)
	var matches []JSONRuleMatch
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
					matches = append(matches, JSONRuleMatch{
						RuleID:        condResult.RuleID,
						Impact:        condResult.Impact,
						Comment:       condResult.Comment,
						SupportingDoc: condResult.SupportingDoc,
					})
				}
			}
		}
	}

	if matches == nil {
		return []JSONRuleMatch{}
	}
	return matches
}

// ensureStringSlice returns an empty slice instead of nil.
func ensureStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
