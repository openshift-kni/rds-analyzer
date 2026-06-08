// Package analyzer provides the core analysis orchestration for RDS validation.
// It coordinates the rule engine, parsing, and report generation.
package analyzer

import (
	"fmt"
	"io"

	"github.com/openshift-kni/rds-analyzer/pkg/report"
	"github.com/openshift-kni/rds-analyzer/pkg/rules"
	"github.com/openshift-kni/rds-analyzer/pkg/types"
)

// Analyzer orchestrates the RDS validation analysis.
// It loads rules, evaluates validation reports, and generates output.
type Analyzer struct {
	ruleEngine *rules.Engine
}

// New creates a new Analyzer with rules loaded from the specified YAML file.
// If version is non-empty, rules are evaluated against that OCP version.
func New(rulesFile string, version string) (*Analyzer, error) {
	if err := rules.ValidateRulesRegexpPatterns(rulesFile); err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine: %w", err)
	}
	engine, err := rules.NewEngineWithVersion(rulesFile, version)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine: %w", err)
	}

	return &Analyzer{ruleEngine: engine}, nil
}

// NewFromBytes creates a new Analyzer with rules loaded from in-memory YAML bytes.
// This allows creating an analyzer from rules data fetched from a ConfigMap or other
// in-memory source instead of a file path.
// If version is non-empty, rules are evaluated against that OCP version.
func NewFromBytes(rulesData []byte, version string) (*Analyzer, error) {
	if err := rules.ValidateRulesRegexpPatternsFromBytes(rulesData, "rules"); err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine: %w", err)
	}
	engine, err := rules.NewEngineFromBytes(rulesData, version)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine: %w", err)
	}

	return &Analyzer{ruleEngine: engine}, nil
}

// Analyze processes a validation report and writes results to the given writer.
// The format parameter determines output type: "text", "html", or "json".
// The mode parameter determines output mode: "simple" or "reporting".
func (a *Analyzer) Analyze(w io.Writer, validationReport types.ValidationReport, format, mode string) error {
	switch mode {
	case "reporting":
		return a.generateReportingOutput(w, validationReport)
	case "simple":
		return a.generateFormattedOutput(w, validationReport, format)
	default:
		return fmt.Errorf("unsupported output mode: %s (valid: simple, reporting)", mode)
	}
}

// generateReportingOutput generates output in reporting mode.
func (a *Analyzer) generateReportingOutput(w io.Writer, validationReport types.ValidationReport) error {
	generator := report.NewReportingGenerator(a.ruleEngine)
	return generator.Generate(w, validationReport)
}

// generateFormattedOutput generates output in the specified format.
func (a *Analyzer) generateFormattedOutput(w io.Writer, validationReport types.ValidationReport, format string) error {
	switch format {
	case "text":
		generator := report.NewTextGenerator(a.ruleEngine)
		return generator.Generate(w, validationReport)
	case "html":
		generator := report.NewHTMLGenerator(a.ruleEngine)
		return generator.Generate(w, validationReport)
	case "json":
		generator := report.NewJSONGenerator(a.ruleEngine)
		return generator.Generate(w, validationReport)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// GetTargetVersion returns the OCP version being used for analysis.
func (a *Analyzer) GetTargetVersion() string {
	if v := a.ruleEngine.GetTargetVersion(); !v.IsZero() {
		return v.String()
	}
	return ""
}
