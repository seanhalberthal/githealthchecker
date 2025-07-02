package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/githealthchecker/git-health-checker/internal/scanner"
)

const failedToCleanUpError = "Failed to clean up temp directory %s: %v\n"

func TestQualityAnalyzer_Analyze(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "quality_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			fmt.Printf(failedToCleanUpError, path, err)
		}
	}(tempDir)

	// Create a large Go file that exceeds line limits
	largeGoFile := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}

` + strings.Repeat("// This is line padding\n", 200) // Create 200+ lines

	// Create a small Go file within limits
	smallGoFile := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`

	// Create test files
	testFiles := map[string]string{
		"large.go":  largeGoFile,
		"small.go":  smallGoFile,
		"test.py":   strings.Repeat("# Python comment\n", 150), // Large Python file
		"normal.js": "console.log('Hello');",
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create a file scanner
	fileScanner, err := scanner.NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create file scanner: %v", err)
	}

	// Create quality config
	cfg := &config.QualityConfig{
		MaxFileLines:     100,
		MaxFunctionLines: 50,
	}

	// Create analyzer
	analyzer := NewQualityAnalyzer(cfg, fileScanner)

	// Run analysis
	issues, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Verify we found issues
	if len(issues) == 0 {
		t.Error("Expected to find quality issues, but none were found")
	}

	// Check that all issues are quality category
	for _, issue := range issues {
		if issue.Category != report.CategoryQuality {
			t.Errorf("Expected quality category, got %s", issue.Category)
		}
	}

	// Check that we found large file issues
	foundLargeFileIssue := false
	for _, issue := range issues {
		if issue.Rule == "max-file-lines" {
			foundLargeFileIssue = true
			if !strings.Contains(issue.Description, "exceeding the maximum") {
				t.Errorf("Expected large file description, got: %s", issue.Description)
			}
		}
	}

	if !foundLargeFileIssue {
		t.Error("Expected to find at least one large file issue")
	}
}

func TestQualityAnalyzer_DetermineSeverityBySize(t *testing.T) {
	cfg := &config.QualityConfig{
		MaxFileLines: 100,
	}
	analyzer := &QualityAnalyzer{config: cfg}

	tests := []struct {
		lines    int
		expected report.Severity
	}{
		{350, report.SeverityHigh},   // > 3 * maxLines
		{250, report.SeverityMedium}, // > 2 * maxLines
		{150, report.SeverityLow},    // > maxLines but < 2 * maxLines
		{50, report.SeverityLow},     // < maxLines (shouldn't be called)
	}

	for _, test := range tests {
		result := analyzer.determineSeverityBySize(test.lines)
		if result != test.expected {
			t.Errorf("For %d lines, expected severity %s, got %s",
				test.lines, test.expected, result)
		}
	}
}

func TestQualityAnalyzer_DetermineSeverityByComplexity(t *testing.T) {
	cfg := &config.QualityConfig{
		ComplexityThreshold: 10,
	}
	analyzer := &QualityAnalyzer{config: cfg}

	tests := []struct {
		complexity int
		expected   report.Severity
	}{
		{35, report.SeverityHigh},   // > 3 * threshold (30)
		{25, report.SeverityMedium}, // > 2 * threshold (20)
		{15, report.SeverityLow},    // > threshold but < 2 * threshold
		{5, report.SeverityLow},     // < threshold (shouldn't be called in practice)
	}

	for _, test := range tests {
		result := analyzer.determineSeverityByComplexity(test.complexity)
		if result != test.expected {
			t.Errorf("For complexity %d, expected severity %s, got %s",
				test.complexity, test.expected, result)
		}
	}
}

func TestQualityAnalyzer_CheckLargeFiles(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "quality_large_files_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			fmt.Printf(failedToCleanUpError, path, err)
		}
	}(tempDir)

	// Create test files with different sizes
	smallFile := strings.Repeat("line\n", 50)  // 50 lines
	largeFile := strings.Repeat("line\n", 150) // 150 lines

	testFiles := map[string]string{
		"small.go": smallFile,
		"large.go": largeFile,
		"huge.py":  strings.Repeat("line\n", 300), // 300 lines
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create a file scanner
	fileScanner, err := scanner.NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create file scanner: %v", err)
	}

	// Create a quality config with a low threshold
	cfg := &config.QualityConfig{
		MaxFileLines:     100,
		MaxFunctionLines: 50,
	}

	analyzer := &QualityAnalyzer{
		config:  cfg,
		scanner: fileScanner,
	}

	// Run large files check
	issues, err := analyzer.checkLargeFiles()
	if err != nil {
		t.Fatalf("checkLargeFiles failed: %v", err)
	}

	// Should find 2 large files (large.go and huge.py)
	if len(issues) != 2 {
		t.Errorf("Expected 2 large file issues, got %d", len(issues))
	}

	// Verify issue details
	for _, issue := range issues {
		if issue.Rule != "max-file-lines" {
			t.Errorf("Expected rule 'max-file-lines', got '%s'", issue.Rule)
		}
		if issue.Severity == "" {
			t.Error("Expected severity to be set")
		}
	}
}
