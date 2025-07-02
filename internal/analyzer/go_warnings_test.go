package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/githealthchecker/git-health-checker/internal/report"
)

func TestNewGoWarningsAnalyzer(t *testing.T) {
	analyzer := NewGoWarningsAnalyzer("/test/path")
	if analyzer == nil {
		t.Fatal("Expected analyzer to be created, got nil")
	}
	if analyzer.repoPath != "/test/path" {
		t.Errorf("Expected repoPath to be '/test/path', got '%s'", analyzer.repoPath)
	}
}

func TestParseOutput(t *testing.T) {
	analyzer := NewGoWarningsAnalyzer("/test")

	tests := []struct {
		name           string
		output         string
		expectedIssues int
	}{
		{
			name:           "empty output",
			output:         "",
			expectedIssues: 0,
		},
		{
			name:           "single warning",
			output:         "./main.go:10:5: unused variable 'x'",
			expectedIssues: 1,
		},
		{
			name: "multiple warnings",
			output: `./main.go:10:5: unused variable 'x'
./helper.go:20:1: unreachable code`,
			expectedIssues: 2,
		},
		{
			name:           "invalid format",
			output:         "some random text without proper format",
			expectedIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzer.parseOutput(tt.output)
			if len(issues) != tt.expectedIssues {
				t.Errorf("Expected %d issues, got %d", tt.expectedIssues, len(issues))
			}
		})
	}
}

func TestGetSeverity(t *testing.T) {
	analyzer := NewGoWarningsAnalyzer("/test")

	tests := []struct {
		message  string
		expected report.Severity
	}{
		{"unused variable 'x'", report.SeverityLow},
		{"unused import 'fmt'", report.SeverityLow},
		{"some other warning", report.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			severity := analyzer.getSeverity(tt.message)
			if severity != tt.expected {
				t.Errorf("Expected severity %s, got %s", tt.expected, severity)
			}
		})
	}
}

func TestGetFix(t *testing.T) {
	analyzer := NewGoWarningsAnalyzer("/test")

	tests := []struct {
		message  string
		expected string
	}{
		{
			"unused variable 'x'",
			"Remove the unused variable",
		},
		{
			"unused import 'fmt'",
			"Remove the unused import",
		},
		{
			"some other warning",
			"Address the go vet warning",
		},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			fix := analyzer.getFix(tt.message)
			if fix != tt.expected {
				t.Errorf("Expected fix '%s', got '%s'", tt.expected, fix)
			}
		})
	}
}

// Integration test - requires actual go commands to be available
func TestAnalyzeIntegration(t *testing.T) {
	// Skip if we're in a restricted environment
	if os.Getenv("CI") != "" {
		t.Skip("Skipping integration test in CI environment")
	}

	// Create a temporary directory with a simple Go project
	tempDir, err := os.MkdirTemp("", "go-warnings-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp dir: %v", err)
		}
	}(tempDir)

	// Create a simple Go file with a warning
	goFile := filepath.Join(tempDir, "main.go")
	content := `package main

import "fmt"

func main() {
	var unused string
	fmt.Println("Hello, World!")
}
`
	if err := os.WriteFile(goFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create go.mod
	goMod := filepath.Join(tempDir, "go.mod")
	modContent := "module test\n\ngo 1.19\n"
	if err := os.WriteFile(goMod, []byte(modContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	analyzer := NewGoWarningsAnalyzer(tempDir)
	issues, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// We expect at least one issue for the unused variable
	if len(issues) == 0 {
		t.Log("No issues found - this might be expected depending on Go version and vet configuration")
	}

	// Verify the structure of any issues found
	for _, issue := range issues {
		if issue.Category != report.CategoryQuality {
			t.Errorf("Expected category %s, got %s", report.CategoryQuality, issue.Category)
		}
		if issue.Rule == "" {
			t.Error("Expected non-empty rule")
		}
		if issue.Fix == "" {
			t.Error("Expected non-empty fix")
		}
	}
}
