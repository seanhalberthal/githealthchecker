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

// Test unified file scanning with caching
func TestUnifiedFileScanning(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "unified_scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create test files with various characteristics
	testFiles := map[string]string{
		"small.go":  "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}",
		"medium.py": strings.Repeat("print('line')\n", 100),
		"large.txt": strings.Repeat("This is a test line.\n", 2000), // Large file for streaming test
	}

	// Create binary file separately to control inclusion
	binaryPath := filepath.Join(tempDir, "binary.bin")
	binaryContent := []byte{0x00, 0x01, 0x02, 0x03, 0x89, 0x50} // Binary content
	if err := os.WriteFile(binaryPath, binaryContent, 0644); err != nil {
		t.Fatalf("Failed to create binary file: %v", err)
	}

	for fileName, content := range testFiles {
		filePath := filepath.Join(tempDir, fileName)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", fileName, err)
		}
	}

	// Initialize scanner
	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test unified scanning
	cachedFiles, err := scanner.ScanAllFiles()
	if err != nil {
		t.Fatalf("Failed to scan files: %v", err)
	}

	// Verify expected number of files (binary files are still included in cache, just marked as non-text)
	expectedFiles := 4 // small.go, medium.py, large.txt, binary.bin
	if len(cachedFiles) != expectedFiles {
		t.Errorf("Expected %d files, got %d", expectedFiles, len(cachedFiles))
	}

	// Test cached access
	retrievedFiles := scanner.GetCachedFiles()
	if len(retrievedFiles) != len(cachedFiles) {
		t.Errorf("Expected %d cached files, got %d", len(cachedFiles), len(retrievedFiles))
	}

	// Verify file properties and caching behavior
	for relPath, file := range cachedFiles {
		// Check that all files have proper metadata
		if file.Path == "" || file.RelativePath == "" {
			t.Errorf("File %s missing required path information", relPath)
		}

		if file.Size <= 0 {
			t.Errorf("File %s should have positive size", relPath)
		}

		// Test content caching based on file size
		switch relPath {
		case "small.go", "medium.py":
			// Small/medium files should have content cached if they're text and under 1MB
			if file.IsText && len(file.Content) == 0 {
				t.Errorf("Small file %s should have cached content", relPath)
			}
			if file.LineCount == 0 {
				t.Errorf("File %s should have line count calculated", relPath)
			}
		case "large.txt":
			// Large files may or may not have content cached depending on size vs 1MB threshold
			// But should always have line count
			if file.LineCount == 0 {
				t.Errorf("Large file %s should have line count calculated", relPath)
			}
		case "binary.bin":
			// Binary files should not have content cached
			if len(file.Content) > 0 {
				t.Errorf("Binary file %s should not have cached content", relPath)
			}
		}

		// Verify text detection
		if strings.HasSuffix(relPath, ".bin") {
			if file.IsText {
				t.Errorf("Binary file %s should not be detected as text", relPath)
			}
		} else {
			if !file.IsText {
				t.Errorf("Text file %s should be detected as text", relPath)
			}
		}
	}

	// Test filter functionality
	goFiles := scanner.FilterCachedFiles(func(file *UnifiedFileInfo) bool {
		return file.Extension == ".go"
	})
	if len(goFiles) != 1 {
		t.Errorf("Expected 1 Go file, got %d", len(goFiles))
	}

	// Test specific file retrieval
	smallFile, exists := scanner.GetCachedFile("small.go")
	if !exists {
		t.Error("Should find small.go in cache")
	}
	if smallFile.Extension != ".go" {
		t.Errorf("Expected .go extension, got %s", smallFile.Extension)
	}

	t.Logf("Unified scan completed successfully with %d files cached", len(cachedFiles))
}

// Test streaming optimization for large files
func TestStreamingOptimization(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "streaming_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create a large file (>1MB) to trigger streaming
	largeContent := strings.Repeat("This is a test line with sufficient content to trigger streaming optimization.\n", 20000)
	largePath := filepath.Join(tempDir, "large.txt")
	if err := os.WriteFile(largePath, []byte(largeContent), 0644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	scanner, err := NewFileScanner(tempDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test streaming line counting
	lineCount, err := scanner.countLinesStreaming(largePath)
	if err != nil {
		t.Fatalf("Streaming line count failed: %v", err)
	}

	if lineCount == 0 {
		t.Errorf("Expected non-zero line count")
	}

	// Verify line count is approximately correct (should be around 20000)
	if lineCount < 19900 || lineCount > 20100 {
		t.Errorf("Line count seems incorrect: got %d, expected around 20000", lineCount)
	}

	t.Logf("Streaming line count completed: %d lines", lineCount)
}
