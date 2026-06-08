package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift-kni/rds-analyzer/pkg/rules"
	"github.com/openshift-kni/rds-analyzer/pkg/types"
)

const testJSONRulesYAML = `
version: "1.0"
description: "Test Rules for JSON Generator"

settings:
  default_impact: "NeedsReview"
  default_severity: "MEDIUM"

label_annotation_rules:
  labels: []
  annotations: []
  default_impact: "NotADeviation"
  default_comment: "Labels and annotations are acceptable"

count_rules:
  - id: "C001-test"
    description: "Test count rule"
    match:
      templateFileName: "TestCR.yaml"
      crName: "*"
    limits:
      - condition: "count > 1"
        impact: "Impacting"
        comment: "Too many CRs"
        supporting_doc: "https://docs.example.com/count"

rules:
  - id: "R001-test"
    description: "Test rule"
    match:
      crName: "*"
    conditions:
      - type: "ExpectedFound"
        contains: "name:"
        impact: "NotImpacting"
        comment: "Name changes are acceptable"
        supporting_doc: "https://docs.example.com/names"
  - id: "R002-impacting"
    description: "Impacting test rule"
    match:
      crName: "*"
    conditions:
      - type: "FoundNotExpected"
        contains: "dangerous:"
        impact: "Impacting"
        comment: "Dangerous configuration found"
`

func createJSONTestRulesFile(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulesFile, []byte(testJSONRulesYAML), 0644); err != nil {
		t.Fatalf("Failed to create test rules file: %v", err)
	}
	return rulesFile
}

func TestNewJSONGenerator(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	if generator == nil {
		t.Fatal("expected generator, got nil")
	}
	if generator.ruleEngine != engine {
		t.Error("generator should have the rule engine set")
	}
}

func TestJSONGenerator_Generate_EmptyReport(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	// Metadata should be populated.
	if result.Metadata.GeneratedAt == "" {
		t.Error("expected GeneratedAt to be set")
	}

	// Empty slices should be present, not null.
	if result.MissingCRs == nil {
		t.Error("expected MissingCRs to be empty slice, got null")
	}
	if result.Diffs == nil {
		t.Error("expected Diffs to be empty slice, got null")
	}
	if result.CountViolations == nil {
		t.Error("expected CountViolations to be empty slice, got null")
	}
	if result.UnmatchedCRs == nil {
		t.Error("expected UnmatchedCRs to be empty slice, got null")
	}
}

func TestJSONGenerator_Generate_EmptySlicesNotNull(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify raw JSON uses [] not null for empty arrays.
	raw := buf.String()

	// Decode into generic map to check JSON structure.
	var generic map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	for _, field := range []string{"MissingCRs", "Diffs", "CountViolations", "UnmatchedCRs"} {
		val, ok := generic[field]
		if !ok {
			t.Errorf("expected field %q in JSON output", field)
			continue
		}
		arr, ok := val.([]interface{})
		if !ok {
			t.Errorf("expected %q to be an array, got %T", field, val)
			continue
		}
		if arr == nil {
			t.Errorf("expected %q to be [], got null", field)
		}
	}
}

func TestJSONGenerator_Generate_WithDiffs(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.20")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumMissing: 0,
			NumDiffCRs: 2,
			TotalCRs:   10,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  name: expected\n+  name: found",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_test",
				Description:        "Test ConfigMap",
			},
			{
				DiffOutput:         "+  dangerous: true",
				CorrelatedTemplate: "required/test/DangerCR.yaml",
				CRName:             "v1_ConfigMap_default_danger",
				Description:        "Dangerous ConfigMap",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	// Verify OCP version in metadata.
	if result.Metadata.OCPVersion != "4.20" {
		t.Errorf("expected OCPVersion 4.20, got %q", result.Metadata.OCPVersion)
	}

	// Verify diffs are present.
	if len(result.Diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d", len(result.Diffs))
	}

	// Verify input order is preserved (not sorted by impact).
	if result.Diffs[0].CRName != "v1_ConfigMap_default_test" {
		t.Errorf("expected first diff to be test, got %q", result.Diffs[0].CRName)
	}
	if result.Diffs[1].CRName != "v1_ConfigMap_default_danger" {
		t.Errorf("expected second diff to be danger, got %q", result.Diffs[1].CRName)
	}

	// Verify DiffOutput is included.
	if result.Diffs[0].DiffOutput == "" {
		t.Error("expected DiffOutput to be included")
	}
}

func TestJSONGenerator_Generate_PreservesInputOrder(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 3,
			TotalCRs:   10,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "+  extra: field",
				CorrelatedTemplate: "test/C.yaml",
				CRName:             "v1_ConfigMap_default_c",
			},
			{
				DiffOutput:         "-  name: expected\n+  name: found",
				CorrelatedTemplate: "test/A.yaml",
				CRName:             "v1_ConfigMap_default_a",
			},
			{
				DiffOutput:         "+  dangerous: true",
				CorrelatedTemplate: "test/B.yaml",
				CRName:             "v1_ConfigMap_default_b",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Diffs should be in the same order as input.
	expectedOrder := []string{
		"v1_ConfigMap_default_c",
		"v1_ConfigMap_default_a",
		"v1_ConfigMap_default_b",
	}
	for i, expected := range expectedOrder {
		if result.Diffs[i].CRName != expected {
			t.Errorf("diff[%d]: expected CRName %q, got %q", i, expected, result.Diffs[i].CRName)
		}
	}
}

func TestJSONGenerator_Generate_WithMissingCRs(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumMissing: 2,
			NumDiffCRs: 0,
			TotalCRs:   10,
			ValidationIssues: types.ValidationIssues{
				"required-config": {
					"missing-sriov": types.Deviation{
						Msg: "Missing required SRIOV configuration",
						CRs: []string{"required/sriov/SriovConfig.yaml"},
					},
				},
				"optional-ptp": {
					"missing-ptp": types.Deviation{
						Msg: "Missing optional PTP configuration",
						CRs: []string{"optional/ptp/PtpConfig.yaml"},
					},
				},
			},
		},
		Diffs: []types.Diff{},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	if len(result.MissingCRs) != 2 {
		t.Fatalf("expected 2 missing CR groups, got %d", len(result.MissingCRs))
	}

	// Check that required and optional groups are marked correctly.
	foundRequired := false
	foundOptional := false
	for _, g := range result.MissingCRs {
		if g.GroupName == "required-config" && g.IsRequired {
			foundRequired = true
		}
		if g.GroupName == "optional-ptp" && !g.IsRequired {
			foundOptional = true
		}
	}
	if !foundRequired {
		t.Error("expected required-config group to be marked as required")
	}
	if !foundOptional {
		t.Error("expected optional-ptp group to be marked as not required")
	}

	// Check impact stats.
	if result.ImpactSummary.MissingCRs.Impacting == 0 && result.ImpactSummary.MissingCRs.NotImpacting == 0 {
		t.Error("expected at least some missing CR impacts")
	}
}

func TestJSONGenerator_Generate_WithUnmatchedCRs(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	unmatchedList := []string{
		"v1_ConfigMap_default_unknown",
		"v1_Secret_default_mystery",
	}
	report := types.ValidationReport{
		Summary: types.Summary{
			TotalCRs:     5,
			UnmatchedCRS: unmatchedList,
		},
		Diffs: []types.Diff{},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	if len(result.UnmatchedCRs) != 2 {
		t.Fatalf("expected 2 unmatched CRs, got %d", len(result.UnmatchedCRs))
	}
	if result.Summary.UnmatchedCRs != 2 {
		t.Errorf("expected UnmatchedCRs count 2, got %d", result.Summary.UnmatchedCRs)
	}
}

func TestJSONGenerator_Generate_PairedExpectedFound(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 1,
			TotalCRs:   5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  name: expected-value\n+  name: found-value",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_test",
				Description:        "Test CR with value diff",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	if len(result.Diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(result.Diffs))
	}

	ef := result.Diffs[0].Sections.ExpectedFound
	if len(ef) == 0 {
		t.Fatal("expected at least one ExpectedFound pair")
	}

	// Verify pairing: each entry should have both expected and found lines.
	for i, pair := range ef {
		if pair.ExpectedLine == "" {
			t.Errorf("ExpectedFound[%d]: expected ExpectedLine to be set", i)
		}
		if pair.FoundLine == "" {
			t.Errorf("ExpectedFound[%d]: expected FoundLine to be set", i)
		}
	}
}

func TestJSONGenerator_Generate_RuleMatches(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 1,
			TotalCRs:   5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "+  dangerous: true",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_test",
				Description:        "Test with impacting rule",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(result.Diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(result.Diffs))
	}

	diff := result.Diffs[0]

	// The diff should have overall Impacting impact.
	if diff.OverallImpact != "Impacting" {
		t.Errorf("expected overall impact Impacting, got %q", diff.OverallImpact)
	}

	// Should have matched rules.
	if len(diff.MatchedRules) == 0 {
		t.Error("expected at least one matched rule")
	}

	// Check that FoundNotExpected section has a line with rule matches.
	if len(diff.Sections.FoundNotExpected) == 0 {
		t.Fatal("expected FoundNotExpected lines")
	}
	foundRuleMatch := false
	for _, line := range diff.Sections.FoundNotExpected {
		if len(line.MatchedRules) > 0 {
			foundRuleMatch = true
			if line.MatchedRules[0].RuleID != "R002-impacting" {
				t.Errorf("expected rule R002-impacting, got %q", line.MatchedRules[0].RuleID)
			}
		}
	}
	if !foundRuleMatch {
		t.Error("expected to find a line with matched rules in FoundNotExpected")
	}
}

func TestJSONGenerator_Generate_ImpactSummary(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 2,
			TotalCRs:   10,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "+  dangerous: true",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_danger",
			},
			{
				DiffOutput:         "-  name: expected\n+  name: found",
				CorrelatedTemplate: "required/test/TestCR2.yaml",
				CRName:             "v1_ConfigMap_default_test",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// At least one diff should be impacting.
	if result.ImpactSummary.Diffs.Impacting == 0 {
		t.Error("expected at least one impacting diff")
	}

	// Total diffs in impact summary should match number of diffs.
	totalDiffImpacts := result.ImpactSummary.Diffs.Impacting +
		result.ImpactSummary.Diffs.NotImpacting +
		result.ImpactSummary.Diffs.NeedsReview +
		result.ImpactSummary.Diffs.NotADeviation
	if totalDiffImpacts != len(result.Diffs) {
		t.Errorf("impact summary total (%d) should match diff count (%d)", totalDiffImpacts, len(result.Diffs))
	}
}

func TestJSONGenerator_Generate_CountViolations(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	// Create two diffs matching the count rule (templateFileName: "TestCR.yaml", crName: "*", count > 1).
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 2,
			TotalCRs:   5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "+  extra: one",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_first",
			},
			{
				DiffOutput:         "+  extra: two",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_second",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(result.CountViolations) == 0 {
		t.Fatal("expected count violations, got none")
	}

	cv := result.CountViolations[0]
	if cv.RuleID != "C001-test" {
		t.Errorf("expected rule ID C001-test, got %q", cv.RuleID)
	}
	if cv.Count != 2 {
		t.Errorf("expected count 2, got %d", cv.Count)
	}
	if cv.Impact != "Impacting" {
		t.Errorf("expected Impacting, got %q", cv.Impact)
	}
	if len(cv.MatchedCRs) != 2 {
		t.Errorf("expected 2 matched CRs, got %d", len(cv.MatchedCRs))
	}
}

func TestJSONGenerator_Generate_Metadata(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.19")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result.Metadata.OCPVersion != "4.19" {
		t.Errorf("expected OCPVersion 4.19, got %q", result.Metadata.OCPVersion)
	}
	if result.Metadata.GeneratedAt == "" {
		t.Error("expected GeneratedAt to be set")
	}
	if result.Metadata.RulesFile != rulesFile {
		t.Errorf("expected RulesFile %q, got %q", rulesFile, result.Metadata.RulesFile)
	}
}

func TestJSONGenerator_Generate_CompactOutput(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	// Compact JSON should be a single line (ending with \n from Encode).
	lines := 0
	for _, c := range output {
		if c == '\n' {
			lines++
		}
	}
	if lines != 1 {
		t.Errorf("expected compact single-line JSON (1 newline), got %d newlines", lines)
	}
}

func TestJSONGenerator_Generate_EmptyDiffsInSections(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	// A diff with only FoundNotExpected lines (no ExpectedNotFound or ExpectedFound).
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 1,
			TotalCRs:   5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "+  extra: field",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_test",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(result.Diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(result.Diffs))
	}

	sections := result.Diffs[0].Sections
	// Empty sections should be [], not null.
	if sections.ExpectedNotFound == nil {
		t.Error("expected ExpectedNotFound to be [], got null")
	}
	if sections.ExpectedFound == nil {
		t.Error("expected ExpectedFound to be [], got null")
	}
	// FoundNotExpected should have content.
	if len(sections.FoundNotExpected) == 0 {
		t.Error("expected FoundNotExpected to have entries")
	}
}

func TestJSONGenerator_Generate_FullReport(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngineWithVersion(rulesFile, "4.19")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumMissing:   1,
			NumDiffCRs:   2,
			TotalCRs:     15,
			MetadataHash: "abc123",
			PatchedCRs:   3,
			UnmatchedCRS: []string{"v1_ConfigMap_default_extra"},
			ValidationIssues: types.ValidationIssues{
				"required-config": {
					"missing-cr": types.Deviation{
						Msg: "Missing required CR",
						CRs: []string{"required/TestCR.yaml"},
					},
				},
			},
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  name: expected\n+  name: found",
				CorrelatedTemplate: "required/test/ConfigA.yaml",
				CRName:             "v1_ConfigMap_ns_configA",
				Description:        "Config A",
			},
			{
				DiffOutput:         "+  dangerous: true",
				CorrelatedTemplate: "optional/test/ConfigB.yaml",
				CRName:             "v1_ConfigMap_ns_configB",
				Description:        "Config B",
			},
		},
	}

	var buf bytes.Buffer
	err = generator.Generate(&buf, report)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify metadata.
	if result.Metadata.OCPVersion != "4.19" {
		t.Errorf("expected OCPVersion 4.19, got %q", result.Metadata.OCPVersion)
	}

	// Verify summary.
	if result.Summary.TotalCRs != 15 {
		t.Errorf("expected TotalCRs 15, got %d", result.Summary.TotalCRs)
	}
	if result.Summary.MetadataHash != "abc123" {
		t.Errorf("expected MetadataHash abc123, got %q", result.Summary.MetadataHash)
	}
	if result.Summary.PatchedCRs != 3 {
		t.Errorf("expected PatchedCRs 3, got %d", result.Summary.PatchedCRs)
	}

	// Verify all sections are populated.
	if len(result.MissingCRs) == 0 {
		t.Error("expected missing CRs to be populated")
	}
	if len(result.Diffs) != 2 {
		t.Errorf("expected 2 diffs, got %d", len(result.Diffs))
	}
	if len(result.UnmatchedCRs) != 1 {
		t.Errorf("expected 1 unmatched CR, got %d", len(result.UnmatchedCRs))
	}
}

func TestJSONGenerator_Generate_EmptyDiffOutput(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	// Diffs with empty DiffOutput should be skipped in output but used for count rules.
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 1,
			TotalCRs:   5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "",
				CorrelatedTemplate: "required/test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_empty",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var result JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Empty diffs should not appear in Diffs output.
	if len(result.Diffs) != 0 {
		t.Errorf("expected 0 diffs for empty DiffOutput, got %d", len(result.Diffs))
	}
}

func TestJSONGenerator_Generate_ValidJSON(t *testing.T) {
	rulesFile := createJSONTestRulesFile(t)
	engine, err := rules.NewEngine(rulesFile)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	generator := NewJSONGenerator(engine)
	report := types.ValidationReport{
		Summary: types.Summary{
			NumDiffCRs: 1,
			TotalCRs:   5,
		},
		Diffs: []types.Diff{
			{
				DiffOutput:         "-  key: \"value with \\\"quotes\\\"\"\n+  key: 'other'",
				CorrelatedTemplate: "test/TestCR.yaml",
				CRName:             "v1_ConfigMap_default_special",
				Description:        "CR with special chars: <>&",
			},
		},
	}

	var buf bytes.Buffer
	if err := generator.Generate(&buf, report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Ensure output is valid JSON.
	if !json.Valid(buf.Bytes()) {
		t.Error("output is not valid JSON")
	}
}

func TestEnsureStringSlice(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"nil input", nil, 0},
		{"empty input", []string{}, 0},
		{"with values", []string{"a", "b"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ensureStringSlice(tt.input)
			if result == nil {
				t.Error("expected non-nil slice")
			}
			if len(result) != tt.want {
				t.Errorf("expected length %d, got %d", tt.want, len(result))
			}
		})
	}
}
