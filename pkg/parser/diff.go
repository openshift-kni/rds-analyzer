// Package parser provides utilities for parsing diff output and YAML-like content.
// It transforms raw unified diff output into structured data suitable for rule evaluation.
package parser

import (
	"strings"

	"github.com/openshift-kni/rds-analyzer/pkg/types"
)

// diffLineInfo holds parsed line info during diff processing.
type diffLineInfo struct {
	content  string // Line content without diff marker
	lineType string // "context", "expected", or "found"
}

// ParseExpectedAndFound transforms unified diff output into a structured DiffCheck.
// It categorizes diff lines into expected-not-found, found-not-expected, and value differences.
// It also builds contextual views with 3-4 lines of surrounding context.
//
// The function handles three scenarios:
//  1. Lines only in expected (prefixed with -): added to ExpectedNotFound
//  2. Lines only in found (prefixed with +): added to FoundNotExpected
//  3. Lines with same key but different values: paired in ExpectedValue/FoundValue
func ParseExpectedAndFound(diffOutput, crName, templateFileName string) types.DiffCheck {
	diffCheck := types.DiffCheck{
		CRName:           crName,
		TemplateFileName: templateFileName,
	}

	if diffOutput == "" {
		return diffCheck
	}

	lines := strings.Split(diffOutput, "\n")
	var expectedLines, foundLines []string
	var parsedLines []diffLineInfo

	// First pass: parse all lines and separate by type.
	for _, line := range lines {
		// Skip diff headers
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") ||
			strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "diff ") {
			continue
		}

		if strings.HasPrefix(line, "-") {
			content := strings.TrimPrefix(line, "-")
			expectedLines = append(expectedLines, content)
			parsedLines = append(parsedLines, diffLineInfo{content: content, lineType: "expected"})
		} else if strings.HasPrefix(line, "+") {
			content := strings.TrimPrefix(line, "+")
			foundLines = append(foundLines, content)
			parsedLines = append(parsedLines, diffLineInfo{content: content, lineType: "found"})
		} else if len(line) > 0 && line[0] == ' ' {
			content := line[1:] // Remove leading space (diff context marker)
			parsedLines = append(parsedLines, diffLineInfo{content: content, lineType: "context"})
		}
	}

	if len(expectedLines) == 0 && len(foundLines) == 0 {
		return diffCheck
	}

	// Build contextual views with limited context (3 lines before/after).
	diffCheck.ExpectedWithContext = buildContextualView(parsedLines, "expected", 3)
	diffCheck.FoundWithContext = buildContextualView(parsedLines, "found", 3)

	// Build maps of key -> line for matching value differences.
	expectedMap := make(map[string]string)
	foundMap := make(map[string]string)

	for _, line := range expectedLines {
		key, _ := ParseKeyValue(line)
		if key != "" {
			expectedMap[key] = line
		}
	}

	for _, line := range foundLines {
		key, _ := ParseKeyValue(line)
		if key != "" {
			foundMap[key] = line
		}
	}

	// Categorize expected lines: either value difference (key exists in both)
	// or missing (key only in expected).
	for _, line := range expectedLines {
		key, _ := ParseKeyValue(line)
		if key != "" {
			if foundLine, exists := foundMap[key]; exists {
				diffCheck.ExpectedValue = append(diffCheck.ExpectedValue, line)
				diffCheck.FoundValue = append(diffCheck.FoundValue, foundLine)
			} else {
				diffCheck.ExpectedNotFound = append(diffCheck.ExpectedNotFound, line)
			}
		}
	}

	// Find lines that are only in found (not in expected).
	for _, line := range foundLines {
		key, _ := ParseKeyValue(line)
		if key != "" {
			if _, exists := expectedMap[key]; !exists {
				diffCheck.FoundNotExpected = append(diffCheck.FoundNotExpected, line)
			}
		}
	}

	return diffCheck
}

// buildContextualView creates a view with changed lines and limited surrounding context.
// targetType is either "expected" or "found".
// contextLines is the number of context lines to include before/after changes.
func buildContextualView(lines []diffLineInfo, targetType string, contextLines int) []types.DiffLine {
	if len(lines) == 0 {
		return nil
	}

	// Find indices of target lines (expected or found).
	var targetIndices []int
	for i, line := range lines {
		if line.lineType == targetType {
			targetIndices = append(targetIndices, i)
		}
	}

	if len(targetIndices) == 0 {
		return nil
	}

	// Build a set of indices to include (targets + context).
	includeSet := make(map[int]bool)
	for _, idx := range targetIndices {
		includeSet[idx] = true
		// Add context before
		for j := 1; j <= contextLines && idx-j >= 0; j++ {
			if lines[idx-j].lineType == "context" {
				includeSet[idx-j] = true
			}
		}
		// Add context after
		for j := 1; j <= contextLines && idx+j < len(lines); j++ {
			if lines[idx+j].lineType == "context" {
				includeSet[idx+j] = true
			}
		}
	}

	// Build the result in order.
	var result []types.DiffLine
	for i, line := range lines {
		if !includeSet[i] {
			continue
		}
		// Only include context and target lines (skip the opposite type).
		if line.lineType == "context" || line.lineType == targetType {
			result = append(result, types.DiffLine{
				Content:   line.content,
				IsChanged: line.lineType == targetType,
			})
		}
	}

	return result
}

// ParseKeyValue extracts key-value pairs from YAML-like lines.
// It handles various formats:
//   - Standard YAML: "key: value"
//   - List items with key-value: "- key: value" or "- key=value"
//   - Plain list items: "- value" (returns value as key, empty string as value)
//   - Lines without separators: returns whole line as key
func ParseKeyValue(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", ""
	}

	// Handle YAML list items (lines starting with "- ").
	if strings.HasPrefix(trimmed, "- ") {
		listItem := strings.TrimPrefix(trimmed, "- ")
		listItem = strings.TrimSpace(listItem)

		// Try key=value format (common in kernel args, env vars).
		if strings.Contains(listItem, "=") {
			parts := strings.SplitN(listItem, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			}
		}

		// Try key: value format.
		if strings.Contains(listItem, ":") {
			parts := strings.SplitN(listItem, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			}
		}

		// Plain list item (e.g., "- vrf") - use item as key.
		return listItem, ""
	}

	// Handle bare "-" (empty list item marker).
	if trimmed == "-" {
		return trimmed, ""
	}

	// Standard key: value format.
	if !strings.Contains(trimmed, ":") {
		return trimmed, ""
	}

	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

// RemoveEmptyDiffs filters out diffs that have no actual differences.
func RemoveEmptyDiffs(diffs []types.Diff) []types.Diff {
	result := make([]types.Diff, 0, len(diffs))
	for _, d := range diffs {
		if d.DiffOutput != "" {
			result = append(result, d)
		}
	}
	return result
}

// LabelAnnotation represents a parsed label or annotation.
type LabelAnnotation struct {
	Key   string
	Value string
	Type  string // "label" or "annotation"
	Line  string // Original line from diff
}

// ExtractLabelsAndAnnotations parses diff lines and extracts labels and annotations.
// It detects sections starting with "labels:" or "annotations:" and extracts
// the key-value pairs that follow.
func ExtractLabelsAndAnnotations(lines []string) []LabelAnnotation {
	var results []LabelAnnotation
	var currentType string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect section headers
		if trimmed == "labels:" {
			currentType = "label"
			continue
		}
		if trimmed == "annotations:" {
			currentType = "annotation"
			continue
		}

		// If we're in a label/annotation section and hit a non-indented line,
		// we've left the section
		if currentType != "" && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			currentType = ""
		}

		// Extract label/annotation if we're in a section
		if currentType != "" && trimmed != "" {
			key, value := ParseKeyValue(trimmed)
			if key != "" && key != "labels" && key != "annotations" {
				results = append(results, LabelAnnotation{
					Key:   key,
					Value: value,
					Type:  currentType,
					Line:  line,
				})
			}
		}
	}

	return results
}

// IsLabelOrAnnotationLine checks if a line is part of a labels or annotations section.
func IsLabelOrAnnotationLine(line string, allLines []string, lineIndex int) (bool, string) {
	trimmed := strings.TrimSpace(line)

	// Direct section headers
	if trimmed == "labels:" || trimmed == "annotations:" {
		return true, strings.TrimSuffix(trimmed, ":")
	}

	// Check if this line is indented under a labels: or annotations: section
	// by looking backwards for the section header
	for i := lineIndex - 1; i >= 0; i-- {
		prevTrimmed := strings.TrimSpace(allLines[i])

		// If we hit a non-indented line that's not labels/annotations, stop
		if len(allLines[i]) > 0 && allLines[i][0] != ' ' && allLines[i][0] != '\t' {
			if prevTrimmed == "labels:" {
				return true, "label"
			}
			if prevTrimmed == "annotations:" {
				return true, "annotation"
			}
			return false, ""
		}
	}

	return false, ""
}
