package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileScanner(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create .gitignore file
	gitignoreContent := `*.log
*.tmp
build/
node_modules/
.env
`
	gitignorePath := filepath.Join(tempDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		t.Fatalf("Failed to create .gitignore: %v", err)
	}

	// Create scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Verify scanner properties
	if scanner.rootPath != tempDir {
		t.Errorf("Expected rootPath %s, got %s", tempDir, scanner.rootPath)
	}

	// Verify gitignore patterns were loaded
	expectedPatterns := []string{"*.log", "*.tmp", "build/", "node_modules/", ".env"}
	if len(scanner.gitIgnores) != len(expectedPatterns) {
		t.Errorf("Expected %d gitignore patterns, got %d", len(expectedPatterns), len(scanner.gitIgnores))
	}
}

func TestFileScanner_ScanFiles(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "scan_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create a test directory structure
	testFiles := map[string]string{
		"main.go":          "package main\nfunc main() {}",
		"util.py":          "print('hello')",
		"README.md":        "# Test Project",
		"config.json":      `{"name": "test"}`,
		"binary_file":      string([]byte{0x00, 0x01, 0x02, 0x03}), // Binary content
		"subdir/nested.js": "console.log('nested');",
	}

	// Create .gitignore to ignore some files
	gitignoreContent := "*.log\nbinary_*\n"
	gitignorePath := filepath.Join(tempDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		t.Fatalf("Failed to create .gitignore: %v", err)
	}

	// Create subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create test files
	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create some files that should be ignored
	ignoredFiles := []string{"app.log", "binary_data"}
	for _, filename := range ignoredFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte("ignored content"), 0644); err != nil {
			t.Fatalf("Failed to create ignored file %s: %v", filename, err)
		}
	}

	// Create scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Scan files
	files, err := scanner.ScanFiles()
	if err != nil {
		t.Fatalf("Failed to scan files: %v", err)
	}

	// Verify we found the expected files (excluding ignored ones)
	expectedFileCount := len(testFiles) - 1 // -1 for binary_file which should be ignored
	if len(files) != expectedFileCount {
		t.Errorf("Expected %d files, got %d", expectedFileCount, len(files))
	}

	// Verify file properties
	foundGo := false
	foundPython := false
	foundNested := false

	for _, file := range files {
		// Check that the file has required properties
		if file.Path == "" {
			t.Error("File path should not be empty")
		}
		if file.RelativePath == "" {
			t.Error("Relative path should not be empty")
		}
		if file.Size <= 0 {
			t.Error("File size should be greater than 0")
		}

		// Check specific files
		switch file.RelativePath {
		case "main.go":
			foundGo = true
			if file.Extension != ".go" {
				t.Errorf("Expected .go extension, got %s", file.Extension)
			}
			if !file.IsText {
				t.Error("Go file should be detected as text")
			}
		case "util.py":
			foundPython = true
			if file.Extension != ".py" {
				t.Errorf("Expected .py extension, got %s", file.Extension)
			}
		case "subdir/nested.js":
			foundNested = true
			if file.Extension != ".js" {
				t.Errorf("Expected .js extension, got %s", file.Extension)
			}
		}
	}

	if !foundGo {
		t.Error("Should have found main.go")
	}
	if !foundPython {
		t.Error("Should have found util.py")
	}
	if !foundNested {
		t.Error("Should have found nested.js")
	}
}

func TestFileScanner_SearchInFiles(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "search_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create test files with patterns to search
	testFiles := map[string]string{
		"main.go":   "package main\nfunc main() {\n\tapi_key := \"test123\"\n}",
		"config.py": "PASSWORD = \"secret123\"\nAPI_TOKEN = \"abc456\"",
		"readme.md": "# Project\nThis is documentation",
		"normal.js": "console.log('hello world');",
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test searching for an API keys pattern (simplified)
	pattern := `api_key`
	extensions := []string{".go", ".py", ".js"}

	matches, err := scanner.SearchInFiles(pattern, extensions)
	if err != nil {
		t.Fatalf("Failed to search in files: %v", err)
	}

	// Should find the api_key in the main.go
	if len(matches) == 0 {
		t.Error("Expected to find matches, but none were found")
	}

	foundInGo := false
	for _, match := range matches {
		if match.File == "main.go" && strings.Contains(match.Content, "api_key") {
			foundInGo = true
			if match.Line != 3 {
				t.Errorf("Expected match on line 3, got line %d", match.Line)
			}
		}
	}

	if !foundInGo {
		t.Error("Should have found api_key pattern in main.go")
	}
}

func TestFileScanner_GetFilesByExtension(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "extension_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create test files with different extensions
	testFiles := []string{
		"main.go",
		"util.go",
		"script.py",
		"config.json",
		"style.css",
		"app.js",
	}

	for _, filename := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		content := "// test content for " + filename
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test getting Go files
	goFiles, err := scanner.GetFilesByExtension([]string{".go"})
	if err != nil {
		t.Fatalf("Failed to get Go files: %v", err)
	}

	if len(goFiles) != 2 {
		t.Errorf("Expected 2 Go files, got %d", len(goFiles))
	}

	// Test getting multiple extensions
	webFiles, err := scanner.GetFilesByExtension([]string{".js", ".css"})
	if err != nil {
		t.Fatalf("Failed to get web files: %v", err)
	}

	if len(webFiles) != 2 {
		t.Errorf("Expected 2 web files, got %d", len(webFiles))
	}
}

func TestFileScanner_IsTextFile(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "text_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create a text file
	textFile := filepath.Join(tempDir, "text.txt")
	if err := os.WriteFile(textFile, []byte("Hello, World!"), 0644); err != nil {
		t.Fatalf("Failed to create text file: %v", err)
	}

	// Create a binary file
	binaryFile := filepath.Join(tempDir, "binary.bin")
	binaryContent := []byte{0x00, 0x01, 0x02, 0x03, 0x89, 0x50, 0x4E, 0x47} // PNG header
	if err := os.WriteFile(binaryFile, binaryContent, 0644); err != nil {
		t.Fatalf("Failed to create binary file: %v", err)
	}

	// Create scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test text file detection
	if !scanner.isTextFile(textFile) {
		t.Error("Text file should be detected as text")
	}

	if scanner.isTextFile(binaryFile) {
		t.Error("Binary file should not be detected as text")
	}
}

func TestFileScanner_ShouldIgnore(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "ignore_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create .gitignore with patterns
	gitignoreContent := `*.log
*.tmp
build/
node_modules/
.env
.DS_Store
`
	gitignorePath := filepath.Join(tempDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		t.Fatalf("Failed to create .gitignore: %v", err)
	}

	// Create scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"app.log", true},
		{"temp.tmp", true},
		{"build/", true}, // Directory pattern
		{"build", true},  // Directory name
		{".env", true},
		{".DS_Store", true},
		{"main.go", false},
		{"README.md", false},
		{"src/util.py", false},
	}

	for _, test := range tests {
		result := scanner.shouldIgnore(test.path)
		if result != test.expected {
			t.Errorf("For path '%s', expected shouldIgnore=%v, got %v",
				test.path, test.expected, result)
		}
	}
}
