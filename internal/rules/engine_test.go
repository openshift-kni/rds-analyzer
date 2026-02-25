package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift-kni/rds-analyzer/internal/types"
)

// testRulesYAML contains a minimal rules configuration for testing.
const testRulesYAML = `
version: "1.0"
description: "Test Rules"

settings:
  default_impact: "NeedsReview"
  default_severity: "MEDIUM"

label_annotation_rules:
  labels:
    - key: "problematic-label"
      description: "This label is problematic"
      impact: "Impacting"
    - key: "bad-prefix/*"
      description: "Labels with bad-prefix are not allowed"
      impact: "Impacting"
    - key: "specific-key"
      value: "specific-value"
      description: "Exact key+value match"
      impact: "NeedsReview"
    - key: "specific-key"
      description: "Key only match (any value)"
      impact: "NotImpacting"
  annotations:
    - key: "problematic-annotation"
      description: "This annotation is problematic"
      impact: "Impacting"
  default_impact: "NotADeviation"
  default_comment: "Labels and annotations are acceptable"

count_rules:
  - id: "C001-single-catalogsource"
    description: "Only one CatalogSource should be configured"
    match:
      templateFileName: "DefaultCatsrc.yaml"
      crName: "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_*"
    limits:
      - condition: "count > 1"
        impact: "Impacting"
        comment: "Found {count} CatalogSource CRs, expected only 1."
        supporting_doc: "https://docs.example.com/catalogsource"
      - condition: "count == 0"
        impact: "Impacting"
        comment: "No CatalogSource configured."

global_rules:
  - id: "G001-reference-label"
    description: "Reference configuration label handling"
    match: {}
    conditions:
      - type: "ExpectedNotFound"
        contains: "ran.openshift.io/reference-configuration"
        impact: "NotADeviation"
        comment: "Missing reference configuration label is not a deviation"

  - id: "G002-sysctls"
    description: "Detect sysctl diffs"
    match: {}
    conditions:
      - type: "Any"
        regex: 'net\..*\..*'
        impact: "NotImpacting"
        comment: "Sysctls beginning with net.* are network namespaced"
        supporting_doc: "https://docs.example.com/sysctls"

rules:
  - id: "R001-network-diagnostics"
    description: "Network diagnostics configuration"
    match:
      templateFileName: "DisableSnoNetworkDiag.yaml"
      crName: "operator.openshift.io/v1_Network_cluster"
    conditions:
      - type: "ExpectedFound"
        contains: "disableNetworkDiagnostics: false"
        impact: "Impacting"
        comment: "Network diagnostics should be disabled"

  - id: "R002-image-registry"
    description: "Image Registry Configuration"
    match:
      templateFileName: "ImageRegistryConfig.yaml"
      crName: "imageregistry.operator.openshift.io/v1_Config_cluster"
    conditions:
      - type: "FoundNotExpected"
        contains: "proxy"
        impact: "NotADeviation"
        comment: "Proxy configuration is allowed"
      - type: "ExpectedFound"
        contains: "managementState: Removed"
        impact: "NotADeviation"
        comment: "Image registry not deployed is not a deviation"
      - type: "ExpectedFound"
        contains: "rolloutStrategy"
        impact: "NotADeviation"
        comment: "Rollout strategy differences are acceptable"

  - id: "R003-subscription"
    description: "Subscription configs"
    match:
      crName: "operators.coreos.com/v1alpha1_Subscription_*"
    conditions:
      - type: "Any"
        contains: "channel:"
        impact: "Impacting"
        comment: "Subscriptions must be pinned to the validated channel"
      - type: "ExpectedFound"
        contains: "installPlanApproval: Automatic"
        impact: "NotADeviation"
        comment: "Automatic install plan approval is acceptable"

  - id: "R004-olm-pprof"
    description: "OLM profiling configuration"
    match:
      templateFileName: "DisableOLMPprof.yaml"
      crName: "v1_ConfigMap_openshift-operator-lifecycle-manager_collect-profiles-config"
    conditions:
      - type: "ExpectedFound"
        contains: "disabled: False"
        impact: "Impacting"
        comment: "OLM profiling should be disabled"

  - id: "R005-glob-pattern"
    description: "Test glob pattern matching"
    match:
      templateFileName: "SriovNetworkNodePolicy*.yaml"
      crName: "sriovnetwork.openshift.io/v1_SriovNetworkNodePolicy_*"
    conditions:
      - type: "FoundNotExpected"
        contains: "mtu:"
        impact: "NotADeviation"
        comment: "MTU configuration is acceptable"

  - id: "R006-multiline"
    description: "Multi-line contains test"
    match:
      templateFileName: "OperatorHub.yaml"
    conditions:
      - type: "ExpectedNotFound"
        contains: |
          spec:
            disableAllDefaultSources: true
        impact: "Impacting"
        comment: "OLM Default sources must be disabled"

  - id: "R007-versioned-impact"
    description: "Test versioned impact"
    match:
      templateFileName: "VersionedTest.yaml"
    conditions:
      - type: "Any"
        contains: "test-value"
        impact:
          4.18: NotImpacting
          4.19: NeedsReview
          4.20: Impacting
        comment: "Impact varies by version"
`

// createTestRulesFile creates a temporary rules file and returns its path.
func createTestRulesFile(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "test-rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(testRulesYAML), 0644); err != nil {
		t.Fatalf("Failed to create test rules file: %v", err)
	}
	return rulesPath
}

// TestNewEngine tests engine creation.
func TestNewEngine(t *testing.T) {
	rulesPath := createTestRulesFile(t)

	t.Run("valid rules file", func(t *testing.T) {
		engine, err := NewEngine(rulesPath)
		if err != nil {
			t.Fatalf("NewEngine failed: %v", err)
		}
		if engine == nil {
			t.Fatal("Expected non-nil engine")
		}
		if engine.GetSettings().DefaultImpact != "NeedsReview" {
			t.Errorf("Expected default impact 'NeedsReview', got %q", engine.GetSettings().DefaultImpact)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := NewEngine("/nonexistent/path/rules.yaml")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(invalidPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
			t.Fatalf("Failed to create invalid yaml file: %v", err)
		}
		_, err := NewEngine(invalidPath)
		if err == nil {
			t.Error("Expected error for invalid YAML")
		}
	})
}

// TestNewEngineWithVersion tests engine creation with specific OCP versions.
func TestNewEngineWithVersion(t *testing.T) {
	rulesPath := createTestRulesFile(t)

	tests := []struct {
		name        string
		version     string
		wantMajor   int
		wantMinor   int
		expectError bool
	}{
		{"valid 4.18", "4.18", 4, 18, false},
		{"valid 4.19", "4.19", 4, 19, false},
		{"valid 4.20", "4.20", 4, 20, false},
		{"empty version uses highest", "", 4, 20, false},
		{"invalid version format", "invalid", 0, 0, true},
		{"invalid version single number", "4", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewEngineWithVersion(rulesPath, tt.version)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.version != "" {
				v := engine.GetTargetVersion()
				if v.Major != tt.wantMajor || v.Minor != tt.wantMinor {
					t.Errorf("Expected version %d.%d, got %d.%d", tt.wantMajor, tt.wantMinor, v.Major, v.Minor)
				}
			}
		})
	}
}

// TestEvaluate tests the main Evaluate function with various diff scenarios.
func TestEvaluate(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name        string
		diffCheck   types.DiffCheck
		wantMatched bool
		wantImpact  string
	}{
		{
			name: "empty diff - no matches",
			diffCheck: types.DiffCheck{
				CRName:           "v1_ConfigMap_test",
				TemplateFileName: "Unknown.yaml",
			},
			wantMatched: false,
			wantImpact:  "NeedsReview",
		},
		{
			name: "network diagnostics - impacting",
			diffCheck: types.DiffCheck{
				CRName:           "operator.openshift.io/v1_Network_cluster",
				TemplateFileName: "DisableSnoNetworkDiag.yaml",
				FoundValue:       []string{"disableNetworkDiagnostics: false"},
			},
			wantMatched: true,
			wantImpact:  "Impacting",
		},
		{
			name: "image registry - managementState Removed",
			diffCheck: types.DiffCheck{
				CRName:           "imageregistry.operator.openshift.io/v1_Config_cluster",
				TemplateFileName: "ImageRegistryConfig.yaml",
				FoundValue:       []string{"managementState: Removed"},
				FoundNotExpected: []string{"proxy: {}"},
			},
			wantMatched: true,
			wantImpact:  "NotADeviation",
		},
		{
			name: "image registry - rolloutStrategy diff",
			diffCheck: types.DiffCheck{
				CRName:           "imageregistry.operator.openshift.io/v1_Config_cluster",
				TemplateFileName: "ImageRegistryConfig.yaml",
				FoundValue:       []string{"rolloutStrategy: RollingUpdate"},
				ExpectedValue:    []string{"rolloutStrategy: Recreate"},
			},
			wantMatched: true,
			wantImpact:  "NotADeviation",
		},
		{
			name: "subscription - channel change is impacting",
			diffCheck: types.DiffCheck{
				CRName:           "operators.coreos.com/v1alpha1_Subscription_openshift-logging_cluster-logging",
				TemplateFileName: "ClusterLogSubscription.yaml",
				ExpectedNotFound: []string{"channel: stable-6.1"},
			},
			wantMatched: true,
			wantImpact:  "Impacting",
		},
		{
			name: "subscription - installPlanApproval Automatic",
			diffCheck: types.DiffCheck{
				CRName:           "operators.coreos.com/v1alpha1_Subscription_openshift-logging_cluster-logging",
				TemplateFileName: "ClusterLogSubscription.yaml",
				FoundValue:       []string{"installPlanApproval: Automatic"},
			},
			wantMatched: true,
			wantImpact:  "NotADeviation",
		},
		{
			name: "OLM pprof - disabled False is impacting",
			diffCheck: types.DiffCheck{
				CRName:           "v1_ConfigMap_openshift-operator-lifecycle-manager_collect-profiles-config",
				TemplateFileName: "DisableOLMPprof.yaml",
				FoundValue:       []string{"disabled: False"},
			},
			wantMatched: true,
			wantImpact:  "Impacting",
		},
		{
			name: "global rule - reference label missing",
			diffCheck: types.DiffCheck{
				CRName:           "some/random_CR",
				TemplateFileName: "SomeTemplate.yaml",
				ExpectedNotFound: []string{"ran.openshift.io/reference-configuration: ran-du.redhat.com"},
			},
			wantMatched: true,
			wantImpact:  "NotADeviation",
		},
		{
			name: "global rule - sysctl regex match",
			diffCheck: types.DiffCheck{
				CRName:           "some/random_CR",
				TemplateFileName: "SomeTemplate.yaml",
				FoundNotExpected: []string{"net.ipv4.tcp_keepalive_time: 600"},
			},
			wantMatched: true,
			wantImpact:  "NotImpacting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.diffCheck)
			if result.Matched != tt.wantMatched {
				t.Errorf("Matched = %v, want %v", result.Matched, tt.wantMatched)
			}
			if result.Impact != tt.wantImpact {
				t.Errorf("Impact = %q, want %q", result.Impact, tt.wantImpact)
			}
		})
	}
}

// TestEvaluateFromOutputJSON tests scenarios derived from testdata/output.json.
func TestEvaluateFromOutputJSON(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name        string
		diffCheck   types.DiffCheck
		wantMatched bool
		wantImpact  string
	}{
		{
			name: "ClusterVersionOperator - empty diff",
			diffCheck: types.DiffCheck{
				CRName:           "config.openshift.io/v1_ClusterVersion_version",
				TemplateFileName: "ClusterVersionOperator.yaml",
			},
			wantMatched: false,
			wantImpact:  "NeedsReview",
		},
		{
			name: "ImageRegistryConfig - managementState change",
			diffCheck: types.DiffCheck{
				CRName:           "imageregistry.operator.openshift.io/v1_Config_cluster",
				TemplateFileName: "ImageRegistryConfig.yaml",
				ExpectedValue:    []string{"managementState: Managed"},
				FoundValue:       []string{"managementState: Removed"},
				FoundNotExpected: []string{"proxy: {}"},
				ExpectedNotFound: []string{"rolloutStrategy: Recreate"},
			},
			wantMatched: true,
			wantImpact:  "NotADeviation",
		},
		{
			name: "LcaSubscription - channel and installPlanApproval",
			diffCheck: types.DiffCheck{
				CRName:           "operators.coreos.com/v1alpha1_Subscription_openshift-lifecycle-agent_lifecycle-agent",
				TemplateFileName: "LcaSubscription.yaml",
				ExpectedNotFound: []string{"channel: stable", "installPlanApproval: Manual"},
				FoundNotExpected: []string{"installPlanApproval: Automatic"},
			},
			wantMatched: true,
			wantImpact:  "Impacting", // channel: in ExpectedNotFound triggers R003
		},
		{
			name: "DisableOLMPprof - disabled False",
			diffCheck: types.DiffCheck{
				CRName:           "v1_ConfigMap_openshift-operator-lifecycle-manager_collect-profiles-config",
				TemplateFileName: "DisableOLMPprof.yaml",
				ExpectedValue:    []string{"disabled: True"},
				FoundValue:       []string{"disabled: False"},
			},
			wantMatched: true,
			wantImpact:  "Impacting",
		},
		{
			name: "SriovNetworkNodePolicy - mtu and nodeSelector",
			diffCheck: types.DiffCheck{
				CRName:           "sriovnetwork.openshift.io/v1_SriovNetworkNodePolicy_openshift-sriov-network-operator_sriov-config-dpdk-ens3f0",
				TemplateFileName: "SriovNetworkNodePolicy.yaml",
				FoundNotExpected: []string{"mtu: 9000", "needVhostNet: true"},
			},
			wantMatched: true,
			wantImpact:  "NotADeviation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.diffCheck)
			if result.Matched != tt.wantMatched {
				t.Errorf("Matched = %v, want %v", result.Matched, tt.wantMatched)
			}
			if result.Impact != tt.wantImpact {
				t.Errorf("Impact = %q, want %q", result.Impact, tt.wantImpact)
			}
		})
	}
}

// TestMatchesPattern tests glob pattern matching.
func TestMatchesPattern(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Exact match
		{"DisableSnoNetworkDiag.yaml", "DisableSnoNetworkDiag.yaml", true},
		{"DisableSnoNetworkDiag.yaml", "OtherFile.yaml", false},

		// Glob patterns
		{"SriovNetworkNodePolicy*.yaml", "SriovNetworkNodePolicy.yaml", true},
		{"SriovNetworkNodePolicy*.yaml", "SriovNetworkNodePolicyTest.yaml", true},
		{"SriovNetworkNodePolicy*.yaml", "OtherPolicy.yaml", false},

		{"*_Subscription_*", "operators.coreos.com/v1alpha1_Subscription_openshift-logging_cluster-logging", true},
		{"*_Subscription_*", "operators.coreos.com/v1alpha1_OperatorGroup_test", false},

		{"06-kdump-*.yaml", "06-kdump-master.yaml", true},
		{"06-kdump-*.yaml", "06-kdump-worker.yaml", true},
		{"06-kdump-*.yaml", "05-other.yaml", false},

		// Complex patterns
		{"required/*/test.yaml", "required/foo/test.yaml", true},
		{"*CatalogSource*", "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_cs-redhat", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := engine.matchesPattern(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestCheckContains tests the contains matching logic.
func TestCheckContains(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name       string
		searchText string
		lines      []string
		wantMatch  bool
	}{
		{
			name:       "simple match",
			searchText: "disabled: False",
			lines:      []string{"pprof-config.yaml: |", "disabled: False"},
			wantMatch:  true,
		},
		{
			name:       "no match",
			searchText: "disabled: True",
			lines:      []string{"pprof-config.yaml: |", "disabled: False"},
			wantMatch:  false,
		},
		{
			name:       "partial match",
			searchText: "managementState",
			lines:      []string{"managementState: Removed"},
			wantMatch:  true,
		},
		{
			name:       "empty search",
			searchText: "",
			lines:      []string{"some content"},
			wantMatch:  false,
		},
		{
			name:       "empty lines",
			searchText: "test",
			lines:      []string{},
			wantMatch:  false,
		},
		{
			name:       "multiline search",
			searchText: "spec:\n  disableAllDefaultSources: true",
			lines:      []string{"apiVersion: v1", "spec:", "  disableAllDefaultSources: true"},
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _ := engine.checkContains(tt.searchText, tt.lines)
			if matched != tt.wantMatch {
				t.Errorf("checkContains() matched = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

// TestCheckRegex tests regex matching.
func TestCheckRegex(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		pattern   string
		lines     []string
		wantMatch bool
	}{
		{
			name:      "sysctl pattern match",
			pattern:   `net\..*\..*`,
			lines:     []string{"net.ipv4.tcp_keepalive_time: 600"},
			wantMatch: true,
		},
		{
			name:      "sysctl pattern no match",
			pattern:   `net\..*\..*`,
			lines:     []string{"kernel.panic: 10"},
			wantMatch: false,
		},
		{
			name:      "interval regex - less than 60m",
			pattern:   `^\s*interval:\s*(?:([0-5]?\d)m|([1-9]\d{0,2}|[12]\d{3}|3[0-5]\d{2})s)$`,
			lines:     []string{"interval: 30m"},
			wantMatch: true,
		},
		{
			name:      "interval regex - 1h should not match",
			pattern:   `^\s*interval:\s*(?:([0-5]?\d)m|([1-9]\d{0,2}|[12]\d{3}|3[0-5]\d{2})s)$`,
			lines:     []string{"interval: 1h"},
			wantMatch: false,
		},
		{
			name:      "crashkernel memory match",
			pattern:   `.*crashkernel=512M$`,
			lines:     []string{"- crashkernel=512M"},
			wantMatch: true,
		},
		{
			name:      "invalid regex",
			pattern:   `[invalid`,
			lines:     []string{"test"},
			wantMatch: false,
		},
		{
			name:      "empty pattern",
			pattern:   "",
			lines:     []string{"test"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _ := engine.checkRegex(tt.pattern, tt.lines)
			if matched != tt.wantMatch {
				t.Errorf("checkRegex() matched = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

// TestEvaluateCountRules tests count-based rule evaluation.
func TestEvaluateCountRules(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name        string
		diffChecks  []types.DiffCheck
		wantCount   int
		wantMatched bool
		wantImpact  string
	}{
		{
			name: "single CatalogSource - no violation",
			diffChecks: []types.DiffCheck{
				{
					CRName:           "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_cs-redhat",
					TemplateFileName: "DefaultCatsrc.yaml",
				},
			},
			wantMatched: false,
		},
		{
			name: "multiple CatalogSources - violation",
			diffChecks: []types.DiffCheck{
				{
					CRName:           "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_cs-redhat",
					TemplateFileName: "DefaultCatsrc.yaml",
				},
				{
					CRName:           "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_cs-custom",
					TemplateFileName: "DefaultCatsrc.yaml",
				},
			},
			wantMatched: true,
			wantImpact:  "Impacting",
		},
		{
			name:        "zero CatalogSources - violation",
			diffChecks:  []types.DiffCheck{},
			wantMatched: true,
			wantImpact:  "Impacting",
		},
		{
			name: "non-matching CRs - no count",
			diffChecks: []types.DiffCheck{
				{
					CRName:           "v1_ConfigMap_test",
					TemplateFileName: "OtherTemplate.yaml",
				},
			},
			wantMatched: true, // count == 0 triggers violation
			wantImpact:  "Impacting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := engine.EvaluateCountRules(tt.diffChecks)

			if tt.wantMatched {
				if len(results) == 0 {
					t.Error("Expected matched count rule but got none")
					return
				}
				if results[0].Impact != tt.wantImpact {
					t.Errorf("Impact = %q, want %q", results[0].Impact, tt.wantImpact)
				}
			} else {
				if len(results) > 0 {
					t.Errorf("Expected no matched count rules but got %d", len(results))
				}
			}
		})
	}
}

// TestEvaluateCountCondition tests count condition parsing and evaluation.
func TestEvaluateCountCondition(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		condition string
		count     int
		want      bool
	}{
		{"count > 1", 2, true},
		{"count > 1", 1, false},
		{"count > 1", 0, false},
		{"count >= 1", 1, true},
		{"count >= 1", 0, false},
		{"count < 1", 0, true},
		{"count < 1", 1, false},
		{"count <= 1", 1, true},
		{"count <= 1", 2, false},
		{"count == 0", 0, true},
		{"count == 0", 1, false},
		{"count != 0", 1, true},
		{"count != 0", 0, false},
		{"invalid condition", 0, false},
		{"count > abc", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.condition, func(t *testing.T) {
			got := engine.evaluateCountCondition(tt.condition, tt.count)
			if got != tt.want {
				t.Errorf("evaluateCountCondition(%q, %d) = %v, want %v", tt.condition, tt.count, got, tt.want)
			}
		})
	}
}

// TestEvaluateMissingCRs tests the missing CRs evaluation based on group prefixes.
func TestEvaluateMissingCRs(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create validation issues similar to output.json
	issues := types.ValidationIssues{
		"required-cluster-logging": {
			"cluster-logging": {
				Msg: "Missing CRs",
				CRs: []string{
					"required/cluster-logging/ClusterLogNS.yaml",
					"required/cluster-logging/ClusterLogForwarder.yaml",
				},
			},
		},
		"optional-ptp-config": {
			"ptp-config": {
				Msg: "One of the following is required",
				CRs: []string{
					"optional/ptp-config/PtpConfigBoundary.yaml",
					"optional/ptp-config/PtpConfigMaster.yaml",
				},
			},
		},
		"custom-group": {
			"custom": {
				Msg: "Custom issue",
				CRs: []string{"custom/path.yaml"},
			},
		},
	}

	results := engine.EvaluateMissingCRs(issues)

	tests := []struct {
		crPath          string
		wantImpact      string
		wantOneRequired bool
	}{
		{"required/cluster-logging/ClusterLogNS.yaml", "Impacting", false},
		{"required/cluster-logging/ClusterLogForwarder.yaml", "Impacting", false},
		{"optional/ptp-config/PtpConfigBoundary.yaml", "NotImpacting", true},
		{"optional/ptp-config/PtpConfigMaster.yaml", "NotImpacting", true},
		{"custom/path.yaml", "NeedsReview", false},
	}

	for _, tt := range tests {
		t.Run(tt.crPath, func(t *testing.T) {
			result, ok := results[tt.crPath]
			if !ok {
				t.Fatalf("Missing result for %q", tt.crPath)
			}
			if result.Impact != tt.wantImpact {
				t.Errorf("Impact = %q, want %q", result.Impact, tt.wantImpact)
			}
			if result.IsOneOfRequired != tt.wantOneRequired {
				t.Errorf("IsOneOfRequired = %v, want %v", result.IsOneOfRequired, tt.wantOneRequired)
			}
		})
	}
}

// TestEvaluateLabelOrAnnotation tests label and annotation evaluation.
func TestEvaluateLabelOrAnnotation(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name        string
		key         string
		value       string
		laType      string
		wantImpact  string
		wantComment string
		isImpacting bool
	}{
		{
			name:        "impacting label - exact match",
			key:         "problematic-label",
			value:       "true",
			laType:      "label",
			wantImpact:  "Impacting",
			wantComment: "This label is problematic",
			isImpacting: true,
		},
		{
			name:        "impacting label - glob match",
			key:         "bad-prefix/something",
			value:       "value",
			laType:      "label",
			wantImpact:  "Impacting",
			wantComment: "Labels with bad-prefix are not allowed",
			isImpacting: true,
		},
		{
			name:        "non-impacting label - uses default",
			key:         "safe-label",
			value:       "value",
			laType:      "label",
			wantImpact:  "NotADeviation",
			wantComment: "Labels and annotations are acceptable",
			isImpacting: false,
		},
		{
			name:        "impacting annotation",
			key:         "problematic-annotation",
			value:       "true",
			laType:      "annotation",
			wantImpact:  "Impacting",
			wantComment: "This annotation is problematic",
			isImpacting: true,
		},
		{
			name:        "non-impacting annotation - uses default",
			key:         "safe-annotation",
			value:       "value",
			laType:      "annotation",
			wantImpact:  "NotADeviation",
			wantComment: "Labels and annotations are acceptable",
			isImpacting: false,
		},
		{
			name:        "operators.coreos.com label - no matching rule",
			key:         "operators.coreos.com/lifecycle-agent.openshift-lifecycle-agent",
			value:       "",
			laType:      "label",
			wantImpact:  "NotADeviation",
			wantComment: "Labels and annotations are acceptable",
			isImpacting: false,
		},
		{
			name:        "openshift.io/cluster-monitoring label - no matching rule",
			key:         "openshift.io/cluster-monitoring",
			value:       "true",
			laType:      "label",
			wantImpact:  "NotADeviation",
			wantComment: "Labels and annotations are acceptable",
			isImpacting: false,
		},
		{
			name:        "specificity - exact key+value wins over key-only",
			key:         "specific-key",
			value:       "specific-value",
			laType:      "label",
			wantImpact:  "NeedsReview",
			wantComment: "Exact key+value match",
			isImpacting: true,
		},
		{
			name:        "specificity - key-only match when value differs",
			key:         "specific-key",
			value:       "different-value",
			laType:      "label",
			wantImpact:  "NotImpacting",
			wantComment: "Key only match (any value)",
			isImpacting: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateLabelOrAnnotation(tt.key, tt.value, tt.laType)
			if result.Impact != tt.wantImpact {
				t.Errorf("Impact = %q, want %q", result.Impact, tt.wantImpact)
			}
			if result.Comment != tt.wantComment {
				t.Errorf("Comment = %q, want %q", result.Comment, tt.wantComment)
			}
			if result.IsImpacting != tt.isImpacting {
				t.Errorf("IsImpacting = %v, want %v", result.IsImpacting, tt.isImpacting)
			}
		})
	}
}

// TestLabelAnnotationRegexMatching tests regex-based value matching for labels and annotations.
func TestLabelAnnotationRegexMatching(t *testing.T) {
	// Create a rules file with regex-based annotation rules
	rulesYAML := `
version: "1.0"
description: "Test Rules with Regex"

settings:
  default_impact: "NeedsReview"
  default_severity: "MEDIUM"

label_annotation_rules:
  labels: []
  annotations:
    # Invalid values (below 10m)
    - key: "operatorframework.io/bundle-unpack-min-retry-interval"
      value_regex: "^[1-9]m$"
      description: "Bundle unpack retry interval must be 10m or higher"
      impact: "Impacting"

    # Valid values (10m or higher)
    - key: "operatorframework.io/bundle-unpack-min-retry-interval"
      value_regex: "^([1-9][0-9]+m|[1-9][0-9]*h)$"
      description: "Bundle unpack retry interval is correctly set"
      impact: "NotADeviation"

  default_impact: "NotADeviation"
  default_comment: "Labels and annotations are acceptable"

global_rules: []
rules: []
count_rules: []
`
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0644); err != nil {
		t.Fatalf("Failed to write rules file: %v", err)
	}

	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name        string
		key         string
		value       string
		laType      string
		wantImpact  string
		wantComment string
	}{
		{
			name:        "1m is invalid (below 10m)",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "1m",
			laType:      "annotation",
			wantImpact:  "Impacting",
			wantComment: "Bundle unpack retry interval must be 10m or higher",
		},
		{
			name:        "5m is invalid (below 10m)",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "5m",
			laType:      "annotation",
			wantImpact:  "Impacting",
			wantComment: "Bundle unpack retry interval must be 10m or higher",
		},
		{
			name:        "9m is invalid (below 10m)",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "9m",
			laType:      "annotation",
			wantImpact:  "Impacting",
			wantComment: "Bundle unpack retry interval must be 10m or higher",
		},
		{
			name:        "10m is valid",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "10m",
			laType:      "annotation",
			wantImpact:  "NotADeviation",
			wantComment: "Bundle unpack retry interval is correctly set",
		},
		{
			name:        "15m is valid",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "15m",
			laType:      "annotation",
			wantImpact:  "NotADeviation",
			wantComment: "Bundle unpack retry interval is correctly set",
		},
		{
			name:        "60m is valid",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "60m",
			laType:      "annotation",
			wantImpact:  "NotADeviation",
			wantComment: "Bundle unpack retry interval is correctly set",
		},
		{
			name:        "1h is valid",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "1h",
			laType:      "annotation",
			wantImpact:  "NotADeviation",
			wantComment: "Bundle unpack retry interval is correctly set",
		},
		{
			name:        "2h is valid",
			key:         "operatorframework.io/bundle-unpack-min-retry-interval",
			value:       "2h",
			laType:      "annotation",
			wantImpact:  "NotADeviation",
			wantComment: "Bundle unpack retry interval is correctly set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateLabelOrAnnotation(tt.key, tt.value, tt.laType)
			if result.Impact != tt.wantImpact {
				t.Errorf("Impact = %q, want %q", result.Impact, tt.wantImpact)
			}
			if result.Comment != tt.wantComment {
				t.Errorf("Comment = %q, want %q", result.Comment, tt.wantComment)
			}
		})
	}
}

// TestIsWorse tests impact priority comparison.
func TestIsWorse(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		impact1 string
		impact2 string
		want    bool
	}{
		{"Impacting", "NeedsReview", true},
		{"Impacting", "NotImpacting", true},
		{"Impacting", "NotADeviation", true},
		{"NeedsReview", "NotImpacting", true},
		{"NeedsReview", "NotADeviation", true},
		{"NotImpacting", "NotADeviation", true},
		{"NotADeviation", "Impacting", false},
		{"NeedsReview", "Impacting", false},
		{"Impacting", "Impacting", false},
		{"NotADeviation", "NotADeviation", false},
	}

	for _, tt := range tests {
		t.Run(tt.impact1+"_vs_"+tt.impact2, func(t *testing.T) {
			got := engine.isWorse(tt.impact1, tt.impact2)
			if got != tt.want {
				t.Errorf("isWorse(%q, %q) = %v, want %v", tt.impact1, tt.impact2, got, tt.want)
			}
		})
	}
}

// TestVersionedImpact tests version-specific impact resolution.
func TestVersionedImpact(t *testing.T) {
	rulesPath := createTestRulesFile(t)

	tests := []struct {
		name       string
		version    string
		wantImpact string
	}{
		{"version 4.18", "4.18", "NotImpacting"},
		{"version 4.19", "4.19", "NeedsReview"},
		{"version 4.20", "4.20", "Impacting"},
		{"version 4.17 inherits 4.18", "4.17", "NotImpacting"},
		{"version 4.21 inherits 4.20", "4.21", "Impacting"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewEngineWithVersion(rulesPath, tt.version)
			if err != nil {
				t.Fatalf("Failed to create engine: %v", err)
			}

			diffCheck := types.DiffCheck{
				CRName:           "test/cr",
				TemplateFileName: "VersionedTest.yaml",
				FoundNotExpected: []string{"test-value: something"},
			}

			result := engine.Evaluate(diffCheck)
			if !result.Matched {
				t.Fatal("Expected rule to match")
			}
			if result.Impact != tt.wantImpact {
				t.Errorf("Impact = %q, want %q", result.Impact, tt.wantImpact)
			}
		})
	}
}

// TestMergeAllResults tests merging of multiple evaluation results.
func TestMergeAllResults(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test that worst impact wins when merging
	diffCheck := types.DiffCheck{
		CRName:           "operators.coreos.com/v1alpha1_Subscription_openshift-logging_cluster-logging",
		TemplateFileName: "ClusterLogSubscription.yaml",
		ExpectedNotFound: []string{"channel: stable-6.1"},                   // Triggers R003 - Impacting
		FoundValue:       []string{"installPlanApproval: Automatic"},        // Triggers R003 - NotADeviation
		FoundNotExpected: []string{"labels:", "operators.coreos.com: true"}, // May trigger label rules
	}

	result := engine.Evaluate(diffCheck)

	// Channel change should cause Impacting to win
	if result.Impact != "Impacting" {
		t.Errorf("Merged impact = %q, want 'Impacting' (worst wins)", result.Impact)
	}
}

// TestHasLabelAnnotationRules tests detection of label/annotation rule configuration.
func TestHasLabelAnnotationRules(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	if !engine.HasLabelAnnotationRules() {
		t.Error("Expected HasLabelAnnotationRules to return true")
	}

	// Test with minimal rules (no label annotation config)
	minimalYAML := `
version: "1.0"
settings:
  default_impact: "NeedsReview"
rules: []
`
	tmpDir := t.TempDir()
	minimalPath := filepath.Join(tmpDir, "minimal.yaml")
	if err := os.WriteFile(minimalPath, []byte(minimalYAML), 0644); err != nil {
		t.Fatalf("Failed to create minimal rules file: %v", err)
	}

	minimalEngine, err := NewEngine(minimalPath)
	if err != nil {
		t.Fatalf("Failed to create minimal engine: %v", err)
	}

	if minimalEngine.HasLabelAnnotationRules() {
		t.Error("Expected HasLabelAnnotationRules to return false for minimal config")
	}
}

// TestGetters tests various getter methods.
func TestGetters(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	t.Run("GetRules", func(t *testing.T) {
		rules := engine.GetRules()
		if len(rules) == 0 {
			t.Error("Expected non-empty rules")
		}
	})

	t.Run("GetSettings", func(t *testing.T) {
		settings := engine.GetSettings()
		if settings.DefaultImpact != "NeedsReview" {
			t.Errorf("DefaultImpact = %q, want 'NeedsReview'", settings.DefaultImpact)
		}
	})

	t.Run("GetCountRules", func(t *testing.T) {
		countRules := engine.GetCountRules()
		if len(countRules) == 0 {
			t.Error("Expected non-empty count rules")
		}
	})

	t.Run("GetLabelAnnotationRules", func(t *testing.T) {
		laRules := engine.GetLabelAnnotationRules()
		if len(laRules.Labels) == 0 {
			t.Error("Expected non-empty labels")
		}
	})

	t.Run("GetTargetVersion", func(t *testing.T) {
		v := engine.GetTargetVersion()
		if v.IsZero() {
			t.Error("Expected non-zero target version")
		}
	})
}

// TestConditionTypes tests different condition types (Any, FoundNotExpected, etc).
func TestConditionTypes(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		diffCheck types.DiffCheck
		wantMatch bool
	}{
		{
			name: "Any type - matches FoundNotExpected",
			diffCheck: types.DiffCheck{
				CRName:           "test/cr",
				TemplateFileName: "SomeTemplate.yaml",
				FoundNotExpected: []string{"net.ipv4.something.else: value"},
			},
			wantMatch: true,
		},
		{
			name: "Any type - matches ExpectedNotFound",
			diffCheck: types.DiffCheck{
				CRName:           "test/cr",
				TemplateFileName: "SomeTemplate.yaml",
				ExpectedNotFound: []string{"net.ipv6.conf.value: 1"},
			},
			wantMatch: true,
		},
		{
			name: "Any type - matches FoundValue",
			diffCheck: types.DiffCheck{
				CRName:           "test/cr",
				TemplateFileName: "SomeTemplate.yaml",
				FoundValue:       []string{"net.core.rmem_max: 16777216"},
			},
			wantMatch: true,
		},
		{
			name: "ExpectedFound type - only checks FoundValue",
			diffCheck: types.DiffCheck{
				CRName:           "operator.openshift.io/v1_Network_cluster",
				TemplateFileName: "DisableSnoNetworkDiag.yaml",
				FoundValue:       []string{"disableNetworkDiagnostics: false"},
				FoundNotExpected: []string{"other: value"},
			},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.diffCheck)
			if result.Matched != tt.wantMatch {
				t.Errorf("Matched = %v, want %v", result.Matched, tt.wantMatch)
			}
		})
	}
}

// TestDeduplicateConditions tests that duplicate conditions are properly deduplicated.
func TestDeduplicateConditions(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	conditions := []ConditionResult{
		{ConditionType: "FoundNotExpected", MatchedText: "proxy: {}", Impact: "NotADeviation"},
		{ConditionType: "FoundNotExpected", MatchedText: "proxy: {}", Impact: "Impacting"},
		{ConditionType: "ExpectedNotFound", MatchedText: "other: value", Impact: "NeedsReview"},
	}

	deduped := engine.deduplicateConditions(conditions)

	// Should have 2 unique conditions
	if len(deduped) != 2 {
		t.Errorf("Expected 2 deduplicated conditions, got %d", len(deduped))
	}

	// The proxy condition should keep the Impacting one (worst)
	for _, cond := range deduped {
		if cond.MatchedText == "proxy: {}" && cond.Impact != "Impacting" {
			t.Errorf("Expected Impacting impact for duplicated proxy condition, got %q", cond.Impact)
		}
	}
}

// TestMultiMatchRegex verifies that a single regex condition matches all lines.
func TestMultiMatchRegex(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test checkRegexAll returns all matching lines
	lines := []string{
		"[sysctl]",
		"net.core.wmem_max = 16777216",
		"net.core.rmem_max = 16777216",
		"net.core.netdev_max_backlog = 16384",
		"kernel.panic = 10",
	}

	matches := engine.checkRegexAll(`net\..*\..*`, lines)

	// Should match all three net.* lines
	if len(matches) != 3 {
		t.Errorf("Expected 3 matches, got %d: %v", len(matches), matches)
	}

	// Verify each expected line is in matches
	expected := map[string]bool{
		"net.core.wmem_max = 16777216":        false,
		"net.core.rmem_max = 16777216":        false,
		"net.core.netdev_max_backlog = 16384": false,
	}
	for _, match := range matches {
		if _, ok := expected[match]; ok {
			expected[match] = true
		}
	}
	for line, found := range expected {
		if !found {
			t.Errorf("Expected to find %q in matches", line)
		}
	}
}

// TestSupportingDocPropagation verifies that supporting_doc is propagated through evaluation.
func TestSupportingDocPropagation(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	t.Run("condition with supporting_doc", func(t *testing.T) {
		diffCheck := types.DiffCheck{
			CRName:           "test/cr",
			TemplateFileName: "SomeTemplate.yaml",
			FoundNotExpected: []string{"net.ipv4.tcp_keepalive_time: 600"},
		}

		result := engine.Evaluate(diffCheck)
		if !result.Matched {
			t.Fatal("Expected rule to match")
		}

		// Find the sysctl condition result
		found := false
		for _, cond := range result.Conditions {
			if cond.RuleID == "G002-sysctls" && cond.Matched {
				found = true
				if cond.SupportingDoc != "https://docs.example.com/sysctls" {
					t.Errorf("SupportingDoc = %q, want %q", cond.SupportingDoc, "https://docs.example.com/sysctls")
				}
			}
		}
		if !found {
			t.Error("Expected to find G002-sysctls condition result")
		}
	})

	t.Run("count rule with supporting_doc", func(t *testing.T) {
		diffChecks := []types.DiffCheck{
			{
				CRName:           "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_cs-redhat",
				TemplateFileName: "DefaultCatsrc.yaml",
			},
			{
				CRName:           "operators.coreos.com/v1alpha1_CatalogSource_openshift-marketplace_cs-custom",
				TemplateFileName: "DefaultCatsrc.yaml",
			},
		}

		results := engine.EvaluateCountRules(diffChecks)
		if len(results) == 0 {
			t.Fatal("Expected count rule to match")
		}

		if results[0].SupportingDoc != "https://docs.example.com/catalogsource" {
			t.Errorf("SupportingDoc = %q, want %q", results[0].SupportingDoc, "https://docs.example.com/catalogsource")
		}
	})
}

// TestMultiMatchContains verifies that contains matches all lines with the pattern.
func TestMultiMatchContains(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	lines := []string{
		"channel: stable",
		"name: operator1",
		"channel: fast",
		"name: operator2",
		"channel: preview",
	}

	matches := engine.checkContainsAll("channel:", lines)

	if len(matches) != 3 {
		t.Errorf("Expected 3 matches, got %d: %v", len(matches), matches)
	}
}

// TestEvaluateMultiMatchCondition verifies that Evaluate returns multiple conditions.
func TestEvaluateMultiMatchCondition(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	diffCheck := types.DiffCheck{
		CRName:           "test_cr",
		TemplateFileName: "test.yaml",
		FoundNotExpected: []string{
			"[sysctl]",
			"net.core.wmem_max = 16777216",
			"net.core.rmem_max = 16777216",
			"net.core.netdev_max_backlog = 16384",
		},
	}

	result := engine.Evaluate(diffCheck)

	// Count how many conditions matched net.* pattern
	netMatches := 0
	for _, cond := range result.Conditions {
		if cond.Matched && cond.RuleID == "G002-sysctls" {
			netMatches++
		}
	}

	if netMatches != 3 {
		t.Errorf("Expected 3 net.* matches from G002-sysctls rule, got %d", netMatches)
		for _, cond := range result.Conditions {
			t.Logf("  Condition: RuleID=%s, Matched=%v, MatchedText=%q", cond.RuleID, cond.Matched, cond.MatchedText)
		}
	}
}

// TestCheckMatch tests the checkMatch function.
func TestCheckMatch(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		condition Condition
		lines     []string
		wantMatch bool
	}{
		{
			name: "contains match",
			condition: Condition{
				Contains: "test",
			},
			lines:     []string{"this is a test line"},
			wantMatch: true,
		},
		{
			name: "regex match",
			condition: Condition{
				Regex: `net\..*`,
			},
			lines:     []string{"net.core.wmem = 1000"},
			wantMatch: true,
		},
		{
			name: "no match",
			condition: Condition{
				Contains: "notfound",
			},
			lines:     []string{"some other line"},
			wantMatch: false,
		},
		{
			name:      "empty condition",
			condition: Condition{},
			lines:     []string{"any line"},
			wantMatch: false,
		},
		{
			name: "regex takes precedence over contains",
			condition: Condition{
				Regex:    `^net`,
				Contains: "other",
			},
			lines:     []string{"network config"},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _ := engine.checkMatch(tt.condition, tt.lines)
			if matched != tt.wantMatch {
				t.Errorf("checkMatch() = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

// TestContainsMultilinePattern tests the containsMultilinePattern function.
func TestContainsMultilinePattern(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name         string
		textLines    []string
		patternLines []string
		want         bool
	}{
		{
			name: "pattern found in sequence",
			textLines: []string{
				"spec:",
				"  replicas: 3",
				"  template:",
				"    name: test",
			},
			patternLines: []string{"replicas:", "template:"},
			want:         true,
		},
		{
			name: "pattern not found",
			textLines: []string{
				"spec:",
				"  replicas: 3",
			},
			patternLines: []string{"template:", "name:"},
			want:         false,
		},
		{
			name: "empty pattern",
			textLines: []string{
				"spec:",
			},
			patternLines: []string{},
			want:         false,
		},
		{
			name:         "empty text",
			textLines:    []string{},
			patternLines: []string{"spec:"},
			want:         false,
		},
		{
			name: "partial match only",
			textLines: []string{
				"spec:",
				"replicas: 3",
			},
			patternLines: []string{"replicas:", "template:", "name:"},
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.containsMultilinePattern(tt.textLines, tt.patternLines)
			if result != tt.want {
				t.Errorf("containsMultilinePattern() = %v, want %v", result, tt.want)
			}
		})
	}
}

// TestIsLabelAnnotationLine tests the IsLabelAnnotationLine function.
func TestIsLabelAnnotationLine(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name     string
		line     string
		wantType string
		wantIs   bool
	}{
		{
			name:     "labels header",
			line:     "labels:",
			wantType: "label",
			wantIs:   true,
		},
		{
			name:     "annotations header",
			line:     "annotations:",
			wantType: "annotation",
			wantIs:   true,
		},
		{
			name:     "labels with whitespace",
			line:     "  labels:",
			wantType: "label",
			wantIs:   true,
		},
		{
			name:     "annotations with whitespace",
			line:     "    annotations:",
			wantType: "annotation",
			wantIs:   true,
		},
		{
			name:     "not a label or annotation",
			line:     "spec:",
			wantType: "",
			wantIs:   false,
		},
		{
			name:     "label value",
			line:     "  app: myapp",
			wantType: "",
			wantIs:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotIs := engine.IsLabelAnnotationLine(tt.line)
			if gotType != tt.wantType {
				t.Errorf("IsLabelAnnotationLine() type = %q, want %q", gotType, tt.wantType)
			}
			if gotIs != tt.wantIs {
				t.Errorf("IsLabelAnnotationLine() isLabel = %v, want %v", gotIs, tt.wantIs)
			}
		})
	}
}

// TestCheckMatchAll tests the checkMatchAll function.
func TestCheckMatchAll(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		condition Condition
		lines     []string
		wantCount int
	}{
		{
			name: "contains multiple matches",
			condition: Condition{
				Contains: "channel",
			},
			lines:     []string{"channel: stable", "name: test", "channel: fast"},
			wantCount: 2,
		},
		{
			name: "regex multiple matches",
			condition: Condition{
				Regex: `net\..*`,
			},
			lines:     []string{"net.core.wmem", "other", "net.ipv4.forward"},
			wantCount: 2,
		},
		{
			name: "no matches",
			condition: Condition{
				Contains: "notfound",
			},
			lines:     []string{"some line", "another line"},
			wantCount: 0,
		},
		{
			name:      "empty condition",
			condition: Condition{},
			lines:     []string{"any line"},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.checkMatchAll(tt.condition, tt.lines)
			if len(result) != tt.wantCount {
				t.Errorf("checkMatchAll() returned %d matches, want %d", len(result), tt.wantCount)
			}
		})
	}
}

// TestParseOCPVersion_AllCases tests all branches of ParseOCPVersion.
func TestParseOCPVersion_AllCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantMajor int
		wantMinor int
	}{
		{
			name:      "valid version",
			input:     "4.19",
			wantErr:   false,
			wantMajor: 4,
			wantMinor: 19,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "single number",
			input:   "4",
			wantErr: true,
		},
		{
			name:    "too many parts",
			input:   "4.19.1",
			wantErr: true,
		},
		{
			name:    "invalid major version",
			input:   "x.19",
			wantErr: true,
		},
		{
			name:    "invalid minor version",
			input:   "4.x",
			wantErr: true,
		},
		{
			name:      "with whitespace",
			input:     "  4.20  ",
			wantErr:   false,
			wantMajor: 4,
			wantMinor: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseOCPVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseOCPVersion(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseOCPVersion(%q) unexpected error: %v", tt.input, err)
				}
				if v.Major != tt.wantMajor {
					t.Errorf("ParseOCPVersion(%q).Major = %d, want %d", tt.input, v.Major, tt.wantMajor)
				}
				if v.Minor != tt.wantMinor {
					t.Errorf("ParseOCPVersion(%q).Minor = %d, want %d", tt.input, v.Minor, tt.wantMinor)
				}
			}
		})
	}
}

// TestCheckContainsAll_EmptySearch tests checkContainsAll with empty search string.
func TestCheckContainsAll_EmptySearch(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Empty search string should return nil
	result := engine.checkContainsAll("", []string{"line1", "line2"})
	if result != nil {
		t.Errorf("checkContainsAll with empty search should return nil, got %v", result)
	}
}

// TestCheckContainsAll_MultiLine tests multi-line pattern matching.
func TestCheckContainsAll_MultiLine(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	lines := []string{
		"spec:",
		"  replicas: 3",
		"  template:",
		"    name: test",
	}

	tests := []struct {
		name       string
		searchText string
		wantMatch  bool
	}{
		{
			name:       "exact multi-line match",
			searchText: "spec:\n  replicas: 3",
			wantMatch:  true,
		},
		{
			name:       "multi-line pattern match",
			searchText: "replicas:\ntemplate:",
			wantMatch:  true,
		},
		{
			name:       "multi-line no match",
			searchText: "notfound:\nmissing:",
			wantMatch:  false,
		},
		{
			name:       "single line still works",
			searchText: "replicas",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.checkContainsAll(tt.searchText, lines)
			if tt.wantMatch && len(result) == 0 {
				t.Errorf("expected match for %q, got none", tt.searchText)
			}
			if !tt.wantMatch && len(result) > 0 {
				t.Errorf("expected no match for %q, got %v", tt.searchText, result)
			}
		})
	}
}

// TestVersionedImpact_GetHighestDefinedVersion tests GetHighestDefinedVersion.
func TestVersionedImpact_GetHighestDefinedVersion(t *testing.T) {
	tests := []struct {
		name     string
		impact   VersionedImpact
		wantZero bool
		wantStr  string
	}{
		{
			name: "not versioned returns zero",
			impact: VersionedImpact{
				IsVersioned: false,
				Simple:      "Impacting",
			},
			wantZero: true,
		},
		{
			name: "single version",
			impact: VersionedImpact{
				IsVersioned: true,
				VersionMap:  map[string]string{"4.19": "Impacting"},
			},
			wantStr: "4.19",
		},
		{
			name: "multiple versions returns highest",
			impact: VersionedImpact{
				IsVersioned: true,
				VersionMap: map[string]string{
					"4.17": "NotImpacting",
					"4.20": "Impacting",
					"4.19": "NeedsReview",
				},
			},
			wantStr: "4.20",
		},
		{
			name: "invalid version in map skipped",
			impact: VersionedImpact{
				IsVersioned: true,
				VersionMap: map[string]string{
					"invalid": "Impacting",
					"4.18":    "NotImpacting",
				},
			},
			wantStr: "4.18",
		},
		{
			name: "all invalid versions returns zero",
			impact: VersionedImpact{
				IsVersioned: true,
				VersionMap: map[string]string{
					"invalid":  "Impacting",
					"also-bad": "NotImpacting",
				},
			},
			wantZero: true,
		},
		{
			name: "empty version map",
			impact: VersionedImpact{
				IsVersioned: true,
				VersionMap:  map[string]string{},
			},
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.impact.GetHighestDefinedVersion()
			if tt.wantZero {
				if !result.IsZero() {
					t.Errorf("expected zero version, got %s", result.String())
				}
			} else {
				if result.String() != tt.wantStr {
					t.Errorf("got %s, want %s", result.String(), tt.wantStr)
				}
			}
		})
	}
}

// TestLabelAnnotationIndentationHandling verifies that non-label/annotation fields
// at the same indentation level as labels:/annotations: are not incorrectly matched.
func TestLabelAnnotationIndentationHandling(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name             string
		lines            []string
		wantMatchedTexts []string
		description      string
	}{
		{
			name: "annotations followed by spec field at same indent",
			lines: []string{
				"  annotations:",
				"    oauth-apiserver.openshift.io/secure-token-storage: \"true\"",
				"  audit:",
				"    profile: Default",
			},
			wantMatchedTexts: []string{
				"annotations:",
				"oauth-apiserver.openshift.io/secure-token-storage: \"true\"",
			},
			description: "audit: and profile: should NOT be matched as annotations",
		},
		{
			name: "labels followed by spec field at same indent",
			lines: []string{
				"  labels:",
				"    app: myapp",
				"  spec:",
				"    replicas: 3",
			},
			wantMatchedTexts: []string{
				"labels:",
				"app: myapp",
			},
			description: "spec: and replicas: should NOT be matched as labels",
		},
		{
			name: "nested annotations with deeper content",
			lines: []string{
				"metadata:",
				"  annotations:",
				"    key1: value1",
				"    key2: value2",
				"  name: test",
			},
			wantMatchedTexts: []string{
				"annotations:",
				"key1: value1",
				"key2: value2",
			},
			description: "name: at same level as annotations: should NOT be matched",
		},
		{
			name: "no labels or annotations",
			lines: []string{
				"spec:",
				"  replicas: 3",
				"  selector:",
				"    matchLabels:",
			},
			wantMatchedTexts: []string{},
			description:      "no label-annotation matches expected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diffCheck := types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				FoundNotExpected: tt.lines,
			}

			result := engine.Evaluate(diffCheck)

			// Collect matched texts from label-annotation-rules.
			matchedTexts := make(map[string]bool)
			for _, cond := range result.Conditions {
				if cond.RuleID == "label-annotation-rules" && cond.Matched {
					matchedTexts[cond.MatchedText] = true
				}
			}

			if len(matchedTexts) != len(tt.wantMatchedTexts) {
				t.Errorf("%s: got %d matches, want %d.\nGot: %v\nWant: %v",
					tt.description, len(matchedTexts), len(tt.wantMatchedTexts), matchedTexts, tt.wantMatchedTexts)
				return
			}

			for _, want := range tt.wantMatchedTexts {
				if !matchedTexts[want] {
					t.Errorf("%s: expected match %q not found in results: %v",
						tt.description, want, matchedTexts)
				}
			}
		})
	}
}

// TestLabelAnnotationWithContextLines verifies that labels/annotations are correctly
// identified when the section header (labels:/annotations:) is a context line, not a changed line.
func TestLabelAnnotationWithContextLines(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name             string
		diffCheck        types.DiffCheck
		wantMatchedTexts []string
		description      string
	}{
		{
			name: "label header is context, value is changed",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				FoundWithContext: []types.DiffLine{
					{Content: "  labels:", IsChanged: false},                            // context
					{Content: "    config.nokia.com/reboot: required", IsChanged: true}, // changed
					{Content: "    existing-label: value", IsChanged: false},            // context
				},
				FoundNotExpected: []string{
					"    config.nokia.com/reboot: required",
				},
			},
			wantMatchedTexts: []string{
				"config.nokia.com/reboot: required",
			},
			description: "Should match label even when labels: is a context line",
		},
		{
			name: "annotation header is context, value is changed",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				FoundWithContext: []types.DiffLine{
					{Content: "metadata:", IsChanged: false},
					{Content: "  annotations:", IsChanged: false},                      // context
					{Content: "    openshift.io/node-selector: \"\"", IsChanged: true}, // changed
					{Content: "    workload.openshift.io/allowed: management", IsChanged: false},
				},
				FoundNotExpected: []string{
					"    openshift.io/node-selector: \"\"",
				},
			},
			wantMatchedTexts: []string{
				"openshift.io/node-selector: \"\"",
			},
			description: "Should match annotation even when annotations: is a context line",
		},
		{
			name: "mixed: some labels changed, some context",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				FoundWithContext: []types.DiffLine{
					{Content: "  annotations:", IsChanged: false},
					{Content: "    new-annotation: value1", IsChanged: true},
					{Content: "    existing-annotation: value2", IsChanged: false},
					{Content: "  labels:", IsChanged: false},
					{Content: "    new-label: value3", IsChanged: true},
				},
				FoundNotExpected: []string{
					"    new-annotation: value1",
					"    new-label: value3",
				},
			},
			wantMatchedTexts: []string{
				"new-annotation: value1",
				"new-label: value3",
			},
			description: "Should match only changed lines in both sections",
		},
		{
			name: "no context available - falls back to plain evaluation",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				FoundWithContext: nil, // No context
				FoundNotExpected: []string{
					"  labels:",
					"    app: myapp",
				},
			},
			wantMatchedTexts: []string{
				"labels:",
				"app: myapp",
			},
			description: "Should fall back to plain evaluation when no context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.diffCheck)

			// Collect matched texts from label-annotation-rules.
			matchedTexts := make(map[string]bool)
			for _, cond := range result.Conditions {
				if cond.RuleID == "label-annotation-rules" && cond.Matched {
					matchedTexts[cond.MatchedText] = true
				}
			}

			if len(matchedTexts) != len(tt.wantMatchedTexts) {
				t.Errorf("%s: got %d matches, want %d.\nGot: %v\nWant: %v",
					tt.description, len(matchedTexts), len(tt.wantMatchedTexts), matchedTexts, tt.wantMatchedTexts)
				return
			}

			for _, want := range tt.wantMatchedTexts {
				if !matchedTexts[want] {
					t.Errorf("%s: expected match %q not found in results: %v",
						tt.description, want, matchedTexts)
				}
			}
		})
	}
}

// TestLabelAnnotationValueDifferences verifies that labels/annotations with value
// differences (same key, different values) are evaluated.
func TestLabelAnnotationValueDifferences(t *testing.T) {
	rulesPath := createTestRulesFile(t)
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name             string
		diffCheck        types.DiffCheck
		wantMatchedTexts []string
		description      string
	}{
		{
			name: "annotation value difference with context",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				ExpectedValue: []string{
					"    operatorframework.io/bundle-unpack-min-retry-interval: 10m",
				},
				FoundValue: []string{
					"    operatorframework.io/bundle-unpack-min-retry-interval: 5m",
				},
				ExpectedWithContext: []types.DiffLine{
					{Content: "metadata:", IsChanged: false},
					{Content: "  annotations:", IsChanged: false},
					{Content: "    operatorframework.io/bundle-unpack-min-retry-interval: 10m", IsChanged: true},
				},
				FoundWithContext: []types.DiffLine{
					{Content: "metadata:", IsChanged: false},
					{Content: "  annotations:", IsChanged: false},
					{Content: "    operatorframework.io/bundle-unpack-min-retry-interval: 5m", IsChanged: true},
					{Content: "  labels:", IsChanged: false},
					{Content: "    config.nokia.com/reboot: required", IsChanged: true},
				},
			},
			wantMatchedTexts: []string{
				// Only FoundValue is matched for labels/annotations, not ExpectedValue
				"operatorframework.io/bundle-unpack-min-retry-interval: 5m",
			},
			description: "Should match annotation value differences",
		},
		{
			name: "label value difference",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				ExpectedValue: []string{
					"    app.kubernetes.io/version: v1",
				},
				FoundValue: []string{
					"    app.kubernetes.io/version: v2",
				},
				ExpectedWithContext: []types.DiffLine{
					{Content: "  labels:", IsChanged: false},
					{Content: "    app.kubernetes.io/version: v1", IsChanged: true},
				},
				FoundWithContext: []types.DiffLine{
					{Content: "  labels:", IsChanged: false},
					{Content: "    app.kubernetes.io/version: v2", IsChanged: true},
				},
			},
			wantMatchedTexts: []string{
				// Only FoundValue is matched for labels/annotations, not ExpectedValue
				"app.kubernetes.io/version: v2",
			},
			description: "Should match label value differences",
		},
		{
			name: "mixed: value diff and new labels",
			diffCheck: types.DiffCheck{
				CRName:           "test-cr",
				TemplateFileName: "test.yaml",
				FoundNotExpected: []string{
					"    new-label: value",
				},
				ExpectedValue: []string{
					"    existing-annotation: old-value",
				},
				FoundValue: []string{
					"    existing-annotation: new-value",
				},
				FoundWithContext: []types.DiffLine{
					{Content: "  annotations:", IsChanged: false},
					{Content: "    existing-annotation: new-value", IsChanged: true},
					{Content: "  labels:", IsChanged: false},
					{Content: "    new-label: value", IsChanged: true},
				},
				ExpectedWithContext: []types.DiffLine{
					{Content: "  annotations:", IsChanged: false},
					{Content: "    existing-annotation: old-value", IsChanged: true},
				},
			},
			wantMatchedTexts: []string{
				"new-label: value",
				// Only FoundValue is matched for labels/annotations, not ExpectedValue
				"existing-annotation: new-value",
			},
			description: "Should match both new labels and value differences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.diffCheck)

			// Collect matched texts from label-annotation-rules.
			matchedTexts := make(map[string]bool)
			for _, cond := range result.Conditions {
				if cond.RuleID == "label-annotation-rules" && cond.Matched {
					matchedTexts[cond.MatchedText] = true
				}
			}

			if len(matchedTexts) != len(tt.wantMatchedTexts) {
				t.Errorf("%s: got %d matches, want %d.\nGot: %v\nWant: %v",
					tt.description, len(matchedTexts), len(tt.wantMatchedTexts), matchedTexts, tt.wantMatchedTexts)
				return
			}

			for _, want := range tt.wantMatchedTexts {
				if !matchedTexts[want] {
					t.Errorf("%s: expected match %q not found in results: %v",
						tt.description, want, matchedTexts)
				}
			}
		})
	}
}
