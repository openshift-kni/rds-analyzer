package parser

import (
	"testing"

	"github.com/openshift-kni/rds-analyzer/pkg/types"
)

func TestParseKeyValue(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantKey   string
		wantValue string
	}{
		{
			name:      "standard key-value",
			line:      "channel: stable",
			wantKey:   "channel",
			wantValue: "stable",
		},
		{
			name:      "indented key-value",
			line:      "    channel: stable",
			wantKey:   "channel",
			wantValue: "stable",
		},
		{
			name:      "list item with key-value",
			line:      "- name: audit",
			wantKey:   "name",
			wantValue: "audit",
		},
		{
			name:      "list item with equals",
			line:      "- key=value",
			wantKey:   "key",
			wantValue: "value",
		},
		{
			name:      "plain list item",
			line:      "- audit",
			wantKey:   "audit",
			wantValue: "",
		},
		{
			name:      "empty line",
			line:      "",
			wantKey:   "",
			wantValue: "",
		},
		{
			name:      "key without value",
			line:      "somekey",
			wantKey:   "somekey",
			wantValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotValue := ParseKeyValue(tt.line)
			if gotKey != tt.wantKey {
				t.Errorf("ParseKeyValue(%q) key = %q, want %q", tt.line, gotKey, tt.wantKey)
			}
			if gotValue != tt.wantValue {
				t.Errorf("ParseKeyValue(%q) value = %q, want %q", tt.line, gotValue, tt.wantValue)
			}
		})
	}
}

func TestParseExpectedAndFound(t *testing.T) {
	tests := []struct {
		name                 string
		diffOutput           string
		crName               string
		templateFileName     string
		wantExpectedNotFound int
		wantFoundNotExpected int
		wantExpectedValue    int
		wantFoundValue       int
		wantExpectedContext  int
		wantFoundContext     int
	}{
		{
			name:                 "empty diff",
			diffOutput:           "",
			crName:               "test-cr",
			templateFileName:     "test.yaml",
			wantExpectedNotFound: 0,
			wantFoundNotExpected: 0,
		},
		{
			name:                 "expected not found",
			diffOutput:           "-  channel: stable",
			crName:               "test-cr",
			templateFileName:     "test.yaml",
			wantExpectedNotFound: 1,
			wantFoundNotExpected: 0,
		},
		{
			name:                 "found not expected",
			diffOutput:           "+  proxy: {}",
			crName:               "test-cr",
			templateFileName:     "test.yaml",
			wantExpectedNotFound: 0,
			wantFoundNotExpected: 1,
		},
		{
			name:                 "value difference",
			diffOutput:           "-  channel: stable\n+  channel: unstable",
			crName:               "test-cr",
			templateFileName:     "test.yaml",
			wantExpectedNotFound: 0,
			wantFoundNotExpected: 0,
			wantExpectedValue:    1,
			wantFoundValue:       1,
		},
		{
			name: "contextual view with surrounding lines",
			diffOutput: ` spec:
   pipelines:
-    name: audit
+    name: infrastructure
   outputRefs:`,
			crName:              "test-cr",
			templateFileName:    "test.yaml",
			wantExpectedValue:   1,
			wantFoundValue:      1,
			wantExpectedContext: 4, // 2 context before, 1 changed, 1 context after
			wantFoundContext:    4, // 2 context before, 1 changed, 1 context after
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseExpectedAndFound(tt.diffOutput, tt.crName, tt.templateFileName)

			if len(result.ExpectedNotFound) != tt.wantExpectedNotFound {
				t.Errorf("ExpectedNotFound count = %d, want %d", len(result.ExpectedNotFound), tt.wantExpectedNotFound)
			}
			if len(result.FoundNotExpected) != tt.wantFoundNotExpected {
				t.Errorf("FoundNotExpected count = %d, want %d", len(result.FoundNotExpected), tt.wantFoundNotExpected)
			}
			if len(result.ExpectedValue) != tt.wantExpectedValue {
				t.Errorf("ExpectedValue count = %d, want %d", len(result.ExpectedValue), tt.wantExpectedValue)
			}
			if len(result.FoundValue) != tt.wantFoundValue {
				t.Errorf("FoundValue count = %d, want %d", len(result.FoundValue), tt.wantFoundValue)
			}
			if tt.wantExpectedContext > 0 && len(result.ExpectedWithContext) != tt.wantExpectedContext {
				t.Errorf("ExpectedWithContext count = %d, want %d", len(result.ExpectedWithContext), tt.wantExpectedContext)
			}
			if tt.wantFoundContext > 0 && len(result.FoundWithContext) != tt.wantFoundContext {
				t.Errorf("FoundWithContext count = %d, want %d", len(result.FoundWithContext), tt.wantFoundContext)
			}
		})
	}
}

func TestBuildContextualView(t *testing.T) {
	tests := []struct {
		name         string
		lines        []diffLineInfo
		targetType   string
		contextLines int
		wantCount    int
		wantChanged  int
	}{
		{
			name:         "empty lines",
			lines:        []diffLineInfo{},
			targetType:   "expected",
			contextLines: 3,
			wantCount:    0,
			wantChanged:  0,
		},
		{
			name: "single changed line with context",
			lines: []diffLineInfo{
				{content: "context1", lineType: "context"},
				{content: "context2", lineType: "context"},
				{content: "changed", lineType: "expected"},
				{content: "context3", lineType: "context"},
			},
			targetType:   "expected",
			contextLines: 2,
			wantCount:    4, // 2 context before + 1 changed + 1 context after
			wantChanged:  1,
		},
		{
			name: "limit context lines",
			lines: []diffLineInfo{
				{content: "context1", lineType: "context"},
				{content: "context2", lineType: "context"},
				{content: "context3", lineType: "context"},
				{content: "context4", lineType: "context"},
				{content: "changed", lineType: "expected"},
				{content: "context5", lineType: "context"},
				{content: "context6", lineType: "context"},
				{content: "context7", lineType: "context"},
				{content: "context8", lineType: "context"},
			},
			targetType:   "expected",
			contextLines: 2,
			wantCount:    5, // 2 context before + 1 changed + 2 context after
			wantChanged:  1,
		},
		{
			name: "skip opposite type lines",
			lines: []diffLineInfo{
				{content: "context1", lineType: "context"},
				{content: "expected_line", lineType: "expected"},
				{content: "found_line", lineType: "found"},
				{content: "context2", lineType: "context"},
			},
			targetType:   "expected",
			contextLines: 3,
			wantCount:    3, // context1 + expected_line + context2 (found_line skipped)
			wantChanged:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildContextualView(tt.lines, tt.targetType, tt.contextLines)

			if len(result) != tt.wantCount {
				t.Errorf("buildContextualView() count = %d, want %d", len(result), tt.wantCount)
			}

			changedCount := 0
			for _, dl := range result {
				if dl.IsChanged {
					changedCount++
				}
			}
			if changedCount != tt.wantChanged {
				t.Errorf("buildContextualView() changed count = %d, want %d", changedCount, tt.wantChanged)
			}
		})
	}
}

func TestExtractLabelsAndAnnotations(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  int
	}{
		{
			name:  "no labels or annotations",
			lines: []string{"spec:", "  replicas: 3"},
			want:  0,
		},
		{
			name: "labels section",
			lines: []string{
				"labels:",
				"  app: myapp",
				"  version: v1",
			},
			want: 2,
		},
		{
			name: "annotations section",
			lines: []string{
				"annotations:",
				"  description: test",
			},
			want: 1,
		},
		{
			name: "mixed labels and annotations",
			lines: []string{
				"labels:",
				"  app: myapp",
				"annotations:",
				"  desc: test",
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractLabelsAndAnnotations(tt.lines)
			if len(result) != tt.want {
				t.Errorf("ExtractLabelsAndAnnotations() count = %d, want %d", len(result), tt.want)
			}
		})
	}
}

func TestRemoveEmptyDiffs(t *testing.T) {
	tests := []struct {
		name     string
		input    []types.Diff
		expected int
	}{
		{
			name:     "empty list",
			input:    []types.Diff{},
			expected: 0,
		},
		{
			name: "all non-empty",
			input: []types.Diff{
				{DiffOutput: "-  key: value", CRName: "cr1"},
				{DiffOutput: "+  key: value2", CRName: "cr2"},
			},
			expected: 2,
		},
		{
			name: "some empty",
			input: []types.Diff{
				{DiffOutput: "-  key: value", CRName: "cr1"},
				{DiffOutput: "", CRName: "cr2"},
				{DiffOutput: "+  key: value2", CRName: "cr3"},
			},
			expected: 2,
		},
		{
			name: "all empty",
			input: []types.Diff{
				{DiffOutput: "", CRName: "cr1"},
				{DiffOutput: "", CRName: "cr2"},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveEmptyDiffs(tt.input)
			if len(result) != tt.expected {
				t.Errorf("RemoveEmptyDiffs() returned %d diffs, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestIsLabelOrAnnotationLine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		allLines  []string
		lineIndex int
		wantMatch bool
		wantType  string
	}{
		{
			name:      "labels header",
			line:      "labels:",
			allLines:  []string{"labels:"},
			lineIndex: 0,
			wantMatch: true,
			wantType:  "labels",
		},
		{
			name:      "annotations header",
			line:      "annotations:",
			allLines:  []string{"annotations:"},
			lineIndex: 0,
			wantMatch: true,
			wantType:  "annotations",
		},
		{
			name:      "label under labels section",
			line:      "  app: myapp",
			allLines:  []string{"labels:", "  app: myapp"},
			lineIndex: 1,
			wantMatch: true,
			wantType:  "label",
		},
		{
			name:      "annotation under annotations section",
			line:      "  description: test",
			allLines:  []string{"annotations:", "  description: test"},
			lineIndex: 1,
			wantMatch: true,
			wantType:  "annotation",
		},
		{
			name:      "non-label line",
			line:      "spec:",
			allLines:  []string{"spec:", "  replicas: 3"},
			lineIndex: 0,
			wantMatch: false,
			wantType:  "",
		},
		{
			name:      "nested line not under labels",
			line:      "  replicas: 3",
			allLines:  []string{"spec:", "  replicas: 3"},
			lineIndex: 1,
			wantMatch: false,
			wantType:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotType := IsLabelOrAnnotationLine(tt.line, tt.allLines, tt.lineIndex)
			if gotMatch != tt.wantMatch {
				t.Errorf("IsLabelOrAnnotationLine() match = %v, want %v", gotMatch, tt.wantMatch)
			}
			if gotType != tt.wantType {
				t.Errorf("IsLabelOrAnnotationLine() type = %q, want %q", gotType, tt.wantType)
			}
		})
	}
}

func TestParseKeyValue_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantKey   string
		wantValue string
	}{
		{
			name:      "value with colons",
			line:      "url: http://example.com:8080",
			wantKey:   "url",
			wantValue: "http://example.com:8080",
		},
		{
			name:      "quoted value",
			line:      `name: "my value"`,
			wantKey:   "name",
			wantValue: `"my value"`,
		},
		{
			name:      "whitespace only",
			line:      "   ",
			wantKey:   "",
			wantValue: "",
		},
		{
			name:      "equals sign in list item",
			line:      "- key=value",
			wantKey:   "key",
			wantValue: "value",
		},
		{
			name:      "equals sign without list prefix",
			line:      "key=value",
			wantKey:   "key=value",
			wantValue: "",
		},
		{
			name:      "deeply indented",
			line:      "        deep: nested",
			wantKey:   "deep",
			wantValue: "nested",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotValue := ParseKeyValue(tt.line)
			if gotKey != tt.wantKey {
				t.Errorf("ParseKeyValue(%q) key = %q, want %q", tt.line, gotKey, tt.wantKey)
			}
			if gotValue != tt.wantValue {
				t.Errorf("ParseKeyValue(%q) value = %q, want %q", tt.line, gotValue, tt.wantValue)
			}
		})
	}
}

func TestParseExpectedAndFound_ComplexDiffs(t *testing.T) {
	tests := []struct {
		name       string
		diffOutput string
		crName     string
		template   string
		checkFunc  func(t *testing.T, result types.DiffCheck)
	}{
		{
			name: "multiple expected not found",
			diffOutput: `-  key1: value1
-  key2: value2
-  key3: value3`,
			crName:   "test-cr",
			template: "test.yaml",
			checkFunc: func(t *testing.T, result types.DiffCheck) {
				if len(result.ExpectedNotFound) != 3 {
					t.Errorf("expected 3 ExpectedNotFound, got %d", len(result.ExpectedNotFound))
				}
			},
		},
		{
			name: "multiple found not expected",
			diffOutput: `+  extra1: val1
+  extra2: val2`,
			crName:   "test-cr",
			template: "test.yaml",
			checkFunc: func(t *testing.T, result types.DiffCheck) {
				if len(result.FoundNotExpected) != 2 {
					t.Errorf("expected 2 FoundNotExpected, got %d", len(result.FoundNotExpected))
				}
			},
		},
		{
			name: "mixed value differences",
			diffOutput: `-  name: old1
+  name: new1
-  count: 1
+  count: 5`,
			crName:   "test-cr",
			template: "test.yaml",
			checkFunc: func(t *testing.T, result types.DiffCheck) {
				if len(result.ExpectedValue) != 2 {
					t.Errorf("expected 2 ExpectedValue, got %d", len(result.ExpectedValue))
				}
				if len(result.FoundValue) != 2 {
					t.Errorf("expected 2 FoundValue, got %d", len(result.FoundValue))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseExpectedAndFound(tt.diffOutput, tt.crName, tt.template)
			tt.checkFunc(t, result)
		})
	}
}
