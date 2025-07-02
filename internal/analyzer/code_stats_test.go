package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/githealthchecker/git-health-checker/internal/scanner"
)

func TestCodeStatsAnalyzer_Analyze(t *testing.T) {
	// Create a temporary directory with test files
	tmpDir, err := os.MkdirTemp("", "code_stats_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to remove temp dir %s: %v", path, err)
		}
	}(tmpDir)

	// Create test files
	testFiles := map[string]string{
		"main.go": `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}`,
		"utils.py": `def hello():
    print("Hello from Python")
    return "done"`,
		"app.js": `function hello() {
    console.log("Hello from JavaScript");
    return true;
}`,
		"README.md": `# Test Project

This is a test project.

## Features
- Feature 1
- Feature 2`,
		"config.json": `{
  "name": "test"
}`,
		".hidden":             "should be ignored",
		"node_modules/lib.js": "should be ignored",
		"image.png":           "binary content should be ignored",
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tmpDir, filename)

		// Create a directory if needed
		if dir := filepath.Dir(filePath); dir != tmpDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatalf("Failed to create dir %s: %v", dir, err)
			}
		}

		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write file %s: %v", filename, err)
		}
	}

	// Create a file scanner
	fileScanner, err := scanner.NewFileScanner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file scanner: %v", err)
	}

	// Create a code stats analyzer
	analyzer := NewCodeStatsAnalyzer(fileScanner)

	// Run analysis
	stats, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Verify results
	expectedFiles := 5 // main.go, utils.py, app.js, README.md, config.json
	if stats.TotalFiles != expectedFiles {
		t.Errorf("Expected %d files, got %d", expectedFiles, stats.TotalFiles)
	}

	if stats.TotalLines == 0 {
		t.Error("Expected non-zero total lines")
	}

	// Check language breakdown
	expectedLanguages := map[string]bool{
		"Go":         true,
		"Python":     true,
		"JavaScript": true,
		"Markdown":   true,
		"JSON":       true,
	}

	if len(stats.LanguageBreakdown) != len(expectedLanguages) {
		t.Errorf("Expected %d languages, got %d", len(expectedLanguages), len(stats.LanguageBreakdown))
	}

	for lang := range expectedLanguages {
		if _, exists := stats.LanguageBreakdown[lang]; !exists {
			t.Errorf("Expected language %s not found in breakdown", lang)
		}
	}

	// Check percentages sum to 100
	totalPercent := 0.0
	for _, percent := range stats.LanguagePercent {
		totalPercent += percent
	}
	if totalPercent < 99.9 || totalPercent > 100.1 { // Allow small floating point errors
		t.Errorf("Expected percentages to sum to 100, got %.2f", totalPercent)
	}
}

func TestCodeStatsAnalyzer_DetectLanguage(t *testing.T) {
	fileScanner, _ := scanner.NewFileScanner(".")
	analyzer := NewCodeStatsAnalyzer(fileScanner)

	tests := []struct {
		filename string
		expected string
	}{
		{"main.go", "Go"},
		{"script.py", "Python"},
		{"app.js", "JavaScript"},
		{"component.tsx", "TypeScript"},
		{"style.css", "CSS"},
		{"index.html", "HTML"},
		{"README.md", "Markdown"},
		{"config.json", "JSON"},
		{"docker-compose.yml", "YAML"},
		{"Dockerfile", "Dockerfile"},
		{"Makefile", "Makefile"},
		{"unknown.xyz", ""},
	}

	for _, test := range tests {
		result := analyzer.detectLanguage(test.filename)
		if result != test.expected {
			t.Errorf("detectLanguage(%s) = %s, expected %s", test.filename, result, test.expected)
		}
	}
}

func TestCodeStatsAnalyzer_ShouldSkipFile(t *testing.T) {
	fileScanner, _ := scanner.NewFileScanner(".")
	analyzer := NewCodeStatsAnalyzer(fileScanner)

	tests := []struct {
		filePath    string
		shouldSkip  bool
		description string
	}{
		{"main.go", false, "regular Go file"},
		{".hidden", true, "hidden file"},
		{"node_modules/lib.js", true, "node_modules directory"},
		{"vendor/pkg.go", true, "vendor directory"},
		{".git/config", true, ".git directory"},
		{"dist/app.js", true, "dist directory"},
		{"build/main.o", true, "build directory"},
		{"image.png", true, "binary file"},
		{"archive.zip", true, "binary file"},
		{"document.pdf", true, "binary file"},
		{"regular.txt", false, "text file"},
	}

	for _, test := range tests {
		result := analyzer.shouldSkipFile(test.filePath)
		if result != test.shouldSkip {
			t.Errorf("shouldSkipFile(%s) = %v, expected %v (%s)",
				test.filePath, result, test.shouldSkip, test.description)
		}
	}
}

func TestCodeStatsAnalyzer_IsBinaryFile(t *testing.T) {
	fileScanner, _ := scanner.NewFileScanner(".")
	analyzer := NewCodeStatsAnalyzer(fileScanner)

	tests := []struct {
		filename string
		isBinary bool
	}{
		{"main.go", false},
		{"image.png", true},
		{"video.mp4", true},
		{"archive.zip", true},
		{"document.pdf", true},
		{"executable.exe", true},
		{"library.dll", true},
		{"data.json", false},
		{"style.css", false},
		{"script.js", false},
	}

	for _, test := range tests {
		result := analyzer.isBinaryFile(test.filename)
		if result != test.isBinary {
			t.Errorf("isBinaryFile(%s) = %v, expected %v", test.filename, result, test.isBinary)
		}
	}
}

func TestCodeStatsAnalyzer_CountLinesInFile(t *testing.T) {
	// Create a temporary file with known content
	tmpFile, err := os.CreateTemp("", "line_count_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			t.Fatalf("Failed to remove temp file %s: %v", name, err)
		}
	}(tmpFile.Name())

	content := `line 1
line 2

line 4
line 5`

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	err = tmpFile.Close()
	if err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	fileScanner, _ := scanner.NewFileScanner(".")
	analyzer := NewCodeStatsAnalyzer(fileScanner)

	count, err := analyzer.countLinesInFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("countLinesInFile failed: %v", err)
	}

	// Should count only non-empty lines: line 1, line 2, line 4, line 5 = 4 lines
	expected := 4
	if count != expected {
		t.Errorf("Expected %d lines, got %d", expected, count)
	}
}

func TestCodeStatsAnalyzer_EmptyDirectory(t *testing.T) {
	// Create an empty temporary directory
	tmpDir, err := os.MkdirTemp("", "empty_stats_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to remove temp dir %s: %v", path, err)
		}
	}(tmpDir)

	fileScanner, err := scanner.NewFileScanner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file scanner: %v", err)
	}

	analyzer := NewCodeStatsAnalyzer(fileScanner)

	stats, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if stats.TotalFiles != 0 {
		t.Errorf("Expected 0 files in empty directory, got %d", stats.TotalFiles)
	}

	if stats.TotalLines != 0 {
		t.Errorf("Expected 0 lines in empty directory, got %d", stats.TotalLines)
	}

	if len(stats.LanguageBreakdown) != 0 {
		t.Errorf("Expected empty language breakdown, got %d languages", len(stats.LanguageBreakdown))
	}
}
