package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openshift-kni/rds-analyzer/internal/rules"
	"github.com/openshift-kni/rds-analyzer/internal/types"
)

// testRulesYAML contains a minimal rules configuration for testing.
const testReportingRulesYAML = `
version: "1.0"
description: "Test Rules for Reporting"

settings:
  default_impact: "NeedsReview"
  default_severity: "MEDIUM"

label_annotation_rules:
  impacting_labels: []
  impacting_annotations: []
  default_impact: "NotADeviation"
  default_comment: "Labels and annotations are acceptable"

rules:
  - id: "R001-subscription"
    description: "Subscription configs"
    match:
      crName: "operators.coreos.com/v1alpha1_Subscription_*"
    conditions:
      - type: "ExpectedNotFound"
        contains: "channel:"
        impact: "Impacting"
        comment: "Subscriptions must be pinned to the validated channel."

  - id: "R002-image-registry"
    description: "Image Registry Configuration"
    match:
      templateFileName: "ImageRegistryConfig.yaml"
    conditions:
      - type: "FoundNotExpected"
        contains: "proxy"
        impact: "NotADeviation"
        comment: "Proxy configuration is allowed"
`

func createTestRulesFile(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulesFile, []byte(testReportingRulesYAML), 0644); err != nil {
		t.Fatalf("Failed to create test rules file: %v", err)
	}
	return rulesFile
}

func TestReportingGenerator_Generate(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{
				"required-test-group": {
					"test-deviation": types.Deviation{
						Msg: "Missing CRs",
						CRs: []string{
							"required/test/TestCR.yaml",
						},
					},
				},
				"optional-test-group": {
					"optional-deviation": types.Deviation{
						Msg: "Missing CRs",
						CRs: []string{
							"optional/test/OptionalCR.yaml",
						},
					},
				},
			},
			NumMissing:   2,
			UnmatchedCRS: []string{"v1_ConfigMap_default_unknown"},
			NumDiffCRs:   1,
			TotalCRs:     5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  channel: stable\n+  channel: unstable",
				CorrelatedTemplate: "required/test/Subscription.yaml",
				CRName:             "operators.coreos.com/v1alpha1_Subscription_test_mysubscription",
				Description:        "Test subscription",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Verify header.
	if !strings.Contains(output, "RDS Analyzer Report") {
		t.Error("Missing report header")
	}
	if !strings.Contains(output, "Used target OCP version: 4.20") {
		t.Error("Missing OCP version")
	}

	// Verify section 1 header.
	if !strings.Contains(output, "The following deviations must be addressed:") {
		t.Error("Missing section 1 header")
	}

	// Verify impacting missing CRs appear in section 1.
	if !strings.Contains(output, "required-test-group") {
		t.Error("Missing required-test-group in output")
	}

	// Verify unmatched CRs appear.
	if !strings.Contains(output, "v1_ConfigMap_default_unknown") {
		t.Error("Missing unmatched CR in output")
	}

	// Verify section 2 header.
	if !strings.Contains(output, "The following deviations require guidance from the telco team:") {
		t.Error("Missing section 2 header")
	}

	// Verify optional missing CRs appear in section 2.
	if !strings.Contains(output, "optional-test-group") {
		t.Error("Missing optional-test-group in output")
	}

	// Verify the explanatory message for optional CRs.
	if !strings.Contains(output, "While marked as optional, these CRs are expected in most clusters.") {
		t.Error("Missing explanatory message for optional CRs")
	}

	// Verify summary.
	if !strings.Contains(output, "Items requiring action:") {
		t.Error("Missing action items summary")
	}
	if !strings.Contains(output, "Items requiring guidance:") {
		t.Error("Missing guidance items summary")
	}
}

func TestReportingGenerator_EmptySections(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	// Report with only optional missing CRs (no impacting items).
	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{
				"optional-test-group": {
					"optional-deviation": types.Deviation{
						Msg: "Missing CRs",
						CRs: []string{
							"optional/test/OptionalCR.yaml",
						},
					},
				},
			},
			NumMissing: 1,
		},
		Diffs: []types.Diff{},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Section 1 should not have "Missing required CRs" subsection.
	// But section headers should still appear.
	if !strings.Contains(output, "The following deviations must be addressed:") {
		t.Error("Missing section 1 header")
	}

	// Section 2 should have the optional CRs.
	if !strings.Contains(output, "optional-test-group") {
		t.Error("Missing optional-test-group in section 2")
	}
}

func TestReportingGenerator_ImpactingDiffs(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{},
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  channel: stable",
				CorrelatedTemplate: "required/test/Subscription.yaml",
				CRName:             "operators.coreos.com/v1alpha1_Subscription_test_mysubscription",
				Description:        "Test subscription",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Verify impacting diff appears in section 1.
	if !strings.Contains(output, "Impacting diffs:") {
		t.Error("Missing impacting diffs subsection")
	}
	if !strings.Contains(output, "operators.coreos.com/v1alpha1_Subscription_test_mysubscription") {
		t.Error("Missing CR name in impacting diffs")
	}
	if !strings.Contains(output, "What must be changed:") {
		t.Error("Missing 'What must be changed' label")
	}
	if !strings.Contains(output, "Subscriptions must be pinned to the validated channel.") {
		t.Error("Missing rule comment in impacting diffs")
	}
}

func TestReportingGenerator_NeedsReviewDiffs(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	// Diff that doesn't match any rule -> NeedsReview.
	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{},
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  someField: expected\n+  someField: found",
				CorrelatedTemplate: "required/test/UnknownCR.yaml",
				CRName:             "v1_ConfigMap_default_unknown",
				Description:        "Unknown CR",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Verify NeedsReview diff appears in section 2.
	if !strings.Contains(output, "Diffs requiring review:") {
		t.Error("Missing diffs requiring review subsection")
	}
	if !strings.Contains(output, "v1_ConfigMap_default_unknown") {
		t.Error("Missing CR name in diffs requiring review")
	}
	if !strings.Contains(output, "Unresolved differences:") {
		t.Error("Missing 'Unresolved differences' label")
	}
}

func TestReportingGenerator_NotADeviationOmitted(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	// Diff that matches NotADeviation rule.
	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{},
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "+  proxy: {}",
				CorrelatedTemplate: "optional/image-registry/ImageRegistryConfig.yaml",
				CRName:             "imageregistry.operator.openshift.io/v1_Config_cluster",
				Description:        "Image registry config",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// NotADeviation diffs should not appear in either section.
	if strings.Contains(output, "imageregistry.operator.openshift.io") {
		t.Error("NotADeviation diff should be omitted from output")
	}

	// Summary should show 0 items.
	if !strings.Contains(output, "Items requiring action: 0") {
		t.Error("Expected 0 action items")
	}
	if !strings.Contains(output, "Items requiring guidance: 0") {
		t.Error("Expected 0 guidance items")
	}
}

func TestReportingGenerator_TemplateSeparator(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	// Multiple NeedsReview diffs with different templates.
	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{},
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  field1: value1",
				CorrelatedTemplate: "required/test/Template1.yaml",
				CRName:             "v1_ConfigMap_default_cr1",
				Description:        "CR 1",
			},
			{
				DiffOutput:         "-  field2: value2",
				CorrelatedTemplate: "required/test/Template2.yaml",
				CRName:             "v1_ConfigMap_default_cr2",
				Description:        "CR 2",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Verify separator between templates.
	if !strings.Contains(output, "--------------------------------------------------") {
		t.Error("Missing template separator")
	}

	// Verify both templates appear.
	if !strings.Contains(output, "Template: required/test/Template1.yaml") {
		t.Error("Missing Template1")
	}
	if !strings.Contains(output, "Template: required/test/Template2.yaml") {
		t.Error("Missing Template2")
	}
}

func TestReportingGenerator_StripANSI(t *testing.T) {
	generator := &ReportingGenerator{}

	tests := []struct {
		input    string
		expected string
	}{
		{"\033[31mred text\033[0m", "red text"},
		{"\033[32mgreen\033[0m", "green"},
		{"\033[1m\033[31mbold red\033[0m", "bold red"},
		{"no codes here", "no codes here"},
	}

	for _, tt := range tests {
		result := generator.stripANSI(tt.input)
		if result != tt.expected {
			t.Errorf("stripANSI(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestReportingGenerator_NoOCPVersion(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile) // No version specified.
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	report := types.ValidationReport{
		Summary: types.Summary{
			ValidationIssues: types.ValidationIssues{},
		},
		Diffs: []types.Diff{},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// When no version is set, the version line should be omitted entirely.
	if strings.Contains(output, "OCP version") || strings.Contains(output, "target OCP version") {
		t.Error("Expected no OCP version line when no version is set")
	}
}

func TestReportingGenerator_PrintCountRuleViolations(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)
	var buf bytes.Buffer
	generator.writer = &buf

	countResults := []rules.CountRuleResult{
		{
			RuleID:        "C001-test",
			Description:   "Test count rule",
			Matched:       true,
			Count:         3,
			Impact:        "Impacting",
			Comment:       "Found 3 CRs, expected only 1",
			SupportingDoc: "https://docs.example.com/count-rules",
			MatchedCRs: []string{
				"v1_ConfigMap_ns1_config1",
				"v1_ConfigMap_ns2_config2",
			},
		},
	}

	generator.printCountRuleViolations(countResults)

	output := buf.String()

	// Verify rule ID and comment
	if !strings.Contains(output, "C001-test") {
		t.Error("expected rule ID in output")
	}
	if !strings.Contains(output, "Found 3 CRs") {
		t.Error("expected comment in output")
	}

	// Verify supporting doc
	if !strings.Contains(output, "See: https://docs.example.com/count-rules") {
		t.Error("expected supporting doc URL in output")
	}

	// Verify affected CRs
	if !strings.Contains(output, "Affected CRs:") {
		t.Error("expected 'Affected CRs:' section")
	}
	if !strings.Contains(output, "v1_ConfigMap_ns1_config1") {
		t.Error("expected matched CR in output")
	}
}

func TestReportingGenerator_PrintCountRuleViolations_NoSupportingDoc(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)
	var buf bytes.Buffer
	generator.writer = &buf

	countResults := []rules.CountRuleResult{
		{
			RuleID:      "C002-no-doc",
			Description: "Rule without doc",
			Matched:     true,
			Count:       2,
			Impact:      "Impacting",
			Comment:     "Violation found",
			MatchedCRs:  []string{},
		},
	}

	generator.printCountRuleViolations(countResults)

	output := buf.String()

	// Verify rule ID
	if !strings.Contains(output, "C002-no-doc") {
		t.Error("expected rule ID in output")
	}

	// Should NOT contain "See:" since no supporting doc
	if strings.Contains(output, "See:") {
		t.Error("should not print 'See:' when no supporting doc")
	}

	// Should NOT contain "Affected CRs:" since list is empty
	if strings.Contains(output, "Affected CRs:") {
		t.Error("should not print 'Affected CRs:' when list is empty")
	}
}

func TestReportingGenerator_PrintCountRuleViolations_Empty(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)
	var buf bytes.Buffer
	generator.writer = &buf

	generator.printCountRuleViolations([]rules.CountRuleResult{})

	output := buf.String()

	// Should be empty when no violations
	if output != "" {
		t.Errorf("expected empty output for no violations, got: %q", output)
	}
}

func TestReportingGenerator_ExtractDiffChecks(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	// Create test data with reportingDiffResult
	results := []reportingDiffResult{
		{
			diffCheck: types.DiffCheck{
				CRName:           "v1_ConfigMap_ns1_config1",
				TemplateFileName: "Config1.yaml",
				ExpectedNotFound: []string{"key1: value1"},
			},
			finalImpact: "Impacting",
		},
		{
			diffCheck: types.DiffCheck{
				CRName:           "v1_ConfigMap_ns2_config2",
				TemplateFileName: "Config2.yaml",
				FoundNotExpected: []string{"extra: field"},
			},
			finalImpact: "NotImpacting",
		},
		{
			diffCheck: types.DiffCheck{
				CRName:           "v1_Secret_ns3_secret1",
				TemplateFileName: "Secret1.yaml",
				ExpectedValue:    []string{"password: old"},
				FoundValue:       []string{"password: new"},
			},
			finalImpact: "NeedsReview",
		},
	}

	checks := generator.extractDiffChecks(results)

	// Verify correct number of checks extracted
	if len(checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(checks))
	}

	// Verify first check
	if checks[0].CRName != "v1_ConfigMap_ns1_config1" {
		t.Errorf("check[0].CRName = %q, want %q", checks[0].CRName, "v1_ConfigMap_ns1_config1")
	}
	if checks[0].TemplateFileName != "Config1.yaml" {
		t.Errorf("check[0].TemplateFileName = %q, want %q", checks[0].TemplateFileName, "Config1.yaml")
	}
	if len(checks[0].ExpectedNotFound) != 1 {
		t.Errorf("check[0].ExpectedNotFound length = %d, want 1", len(checks[0].ExpectedNotFound))
	}

	// Verify second check
	if checks[1].CRName != "v1_ConfigMap_ns2_config2" {
		t.Errorf("check[1].CRName = %q, want %q", checks[1].CRName, "v1_ConfigMap_ns2_config2")
	}
	if len(checks[1].FoundNotExpected) != 1 {
		t.Errorf("check[1].FoundNotExpected length = %d, want 1", len(checks[1].FoundNotExpected))
	}

	// Verify third check
	if checks[2].CRName != "v1_Secret_ns3_secret1" {
		t.Errorf("check[2].CRName = %q, want %q", checks[2].CRName, "v1_Secret_ns3_secret1")
	}
	if len(checks[2].ExpectedValue) != 1 || len(checks[2].FoundValue) != 1 {
		t.Errorf("check[2] should have 1 ExpectedValue and 1 FoundValue")
	}
}

func TestReportingGenerator_ExtractDiffChecks_Empty(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	checks := generator.extractDiffChecks([]reportingDiffResult{})

	if len(checks) != 0 {
		t.Errorf("expected 0 checks for empty input, got %d", len(checks))
	}
}

func TestReportingGenerator_ExtractResolvedRules(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	tests := []struct {
		name       string
		ruleResult rules.EvaluationResult
		wantCount  int
	}{
		{
			name: "mixed impacts - only non-impacting returned",
			ruleResult: rules.EvaluationResult{
				Conditions: []rules.ConditionResult{
					{RuleID: "R001", Matched: true, Impact: "Impacting", Comment: "Bad"},
					{RuleID: "R002", Matched: true, Impact: "NotImpacting", Comment: "OK"},
					{RuleID: "R003", Matched: true, Impact: "NotADeviation", Comment: "Fine"},
				},
			},
			wantCount: 2, // NotImpacting and NotADeviation
		},
		{
			name: "duplicate rules deduplicated",
			ruleResult: rules.EvaluationResult{
				Conditions: []rules.ConditionResult{
					{RuleID: "R001", Matched: true, Impact: "NotImpacting", Comment: "Same"},
					{RuleID: "R001", Matched: true, Impact: "NotImpacting", Comment: "Same"},
					{RuleID: "R002", Matched: true, Impact: "NotImpacting", Comment: "Different"},
				},
			},
			wantCount: 2, // Deduplicated by RuleID:Comment
		},
		{
			name: "empty impact excluded",
			ruleResult: rules.EvaluationResult{
				Conditions: []rules.ConditionResult{
					{RuleID: "R001", Matched: true, Impact: "", Comment: "No impact"},
					{RuleID: "R002", Matched: true, Impact: "NotImpacting", Comment: "Has impact"},
				},
			},
			wantCount: 1, // Only the one with impact
		},
		{
			name: "unmatched conditions excluded",
			ruleResult: rules.EvaluationResult{
				Conditions: []rules.ConditionResult{
					{RuleID: "R001", Matched: false, Impact: "NotImpacting", Comment: "Not matched"},
					{RuleID: "R002", Matched: true, Impact: "NotImpacting", Comment: "Matched"},
				},
			},
			wantCount: 1,
		},
		{
			name:       "empty conditions",
			ruleResult: rules.EvaluationResult{Conditions: []rules.ConditionResult{}},
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generator.extractResolvedRules(tt.ruleResult)
			if len(result) != tt.wantCount {
				t.Errorf("extractResolvedRules() returned %d, want %d", len(result), tt.wantCount)
			}
		})
	}
}

func TestReportingGenerator_FilterCountRulesByImpact(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	countResults := []rules.CountRuleResult{
		{RuleID: "C001", Matched: true, Impact: "Impacting"},
		{RuleID: "C002", Matched: true, Impact: "NotImpacting"},
		{RuleID: "C003", Matched: true, Impact: "NeedsReview"},
		{RuleID: "C004", Matched: false, Impact: "Impacting"}, // Not matched
	}

	tests := []struct {
		name      string
		impacts   []string
		wantCount int
	}{
		{
			name:      "filter impacting only",
			impacts:   []string{"Impacting"},
			wantCount: 1, // C001 only (C004 not matched)
		},
		{
			name:      "filter multiple impacts",
			impacts:   []string{"Impacting", "NotImpacting"},
			wantCount: 2,
		},
		{
			name:      "filter non-existent impact",
			impacts:   []string{"Unknown"},
			wantCount: 0,
		},
		{
			name:      "filter all matched",
			impacts:   []string{"Impacting", "NotImpacting", "NeedsReview"},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generator.filterCountRulesByImpact(countResults, tt.impacts...)
			if len(result) != tt.wantCount {
				t.Errorf("filterCountRulesByImpact() returned %d, want %d", len(result), tt.wantCount)
			}
		})
	}
}

func TestReportingGenerator_FilterCountRulesByImpact_Empty(t *testing.T) {
	rulesFile := createTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewReportingGenerator(engine)

	// Empty input
	result := generator.filterCountRulesByImpact([]rules.CountRuleResult{}, "Impacting")
	if len(result) != 0 {
		t.Errorf("expected 0 for empty input, got %d", len(result))
	}
}
