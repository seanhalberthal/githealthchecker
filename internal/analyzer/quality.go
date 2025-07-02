package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/githealthchecker/git-health-checker/internal/scanner"
)

type QualityAnalyzer struct {
	config  *config.QualityConfig
	scanner *scanner.FileScanner
}

func NewQualityAnalyzer(cfg *config.QualityConfig, fileScanner *scanner.FileScanner) *QualityAnalyzer {
	return &QualityAnalyzer{
		config:  cfg,
		scanner: fileScanner,
	}
}

func (a *QualityAnalyzer) Analyze() ([]report.Issue, error) {
	var issues []report.Issue

	// Use cached files if available for better performance
	cachedFiles := a.scanner.GetCachedFiles()
	if len(cachedFiles) > 0 {
		return a.analyzeFromCache(cachedFiles)
	}

	// Fallback to original method
	fileSizeIssues, err := a.checkLargeFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to check large files: %w", err)
	}
	issues = append(issues, fileSizeIssues...)

	complexityIssues, err := a.checkComplexity()
	if err != nil {
		return nil, fmt.Errorf("failed to check complexity: %w", err)
	}
	issues = append(issues, complexityIssues...)

	return issues, nil
}

// analyzeFromCache performs quality analysis using cached file data
func (a *QualityAnalyzer) analyzeFromCache(cachedFiles map[string]*scanner.UnifiedFileInfo) ([]report.Issue, error) {
	var issues []report.Issue

	// Check large files using cached data
	largeFileIssues := a.checkLargeFilesFromCache(cachedFiles)
	issues = append(issues, largeFileIssues...)

	// Check complexity using cached data
	complexityIssues, err := a.checkComplexityFromCache(cachedFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to check complexity from cache: %w", err)
	}
	issues = append(issues, complexityIssues...)

	return issues, nil
}

// checkLargeFilesFromCache checks for large files using cached data
func (a *QualityAnalyzer) checkLargeFilesFromCache(cachedFiles map[string]*scanner.UnifiedFileInfo) []report.Issue {
	var issues []report.Issue
	codeExtensions := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".py": true, ".java": true, ".rb": true, ".php": true, ".cs": true, ".cpp": true, ".c": true, ".rs": true, ".kt": true,
	}

	for _, file := range cachedFiles {
		// Skip if not a code file
		if !codeExtensions[file.Extension] {
			continue
		}

		if file.LineCount > a.config.MaxFileLines {
			issue := report.Issue{
				ID:          fmt.Sprintf("large-file-lines-%s", strings.ReplaceAll(file.RelativePath, "/", "-")),
				Title:       "File has too many lines",
				Description: fmt.Sprintf("File %s has %d lines, exceeding the maximum of %d lines", file.RelativePath, file.LineCount, a.config.MaxFileLines),
				Category:    report.CategoryQuality,
				Severity:    a.determineSeverityBySize(file.LineCount),
				File:        file.RelativePath,
				Rule:        "max-file-lines",
				Fix:         "Consider breaking this file into smaller, more focused modules",
				CreatedAt:   time.Now(),
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

func (a *QualityAnalyzer) checkLargeFiles() ([]report.Issue, error) {
	var issues []report.Issue

	codeExtensions := []string{".go", ".js", ".ts", ".py", ".java", ".rb", ".php", ".cs", ".cpp", ".c", ".rs", ".kt"}
	codeFiles, err := a.scanner.GetFilesByExtension(codeExtensions)
	if err != nil {
		return nil, err
	}

	for _, file := range codeFiles {
		if file.LineCount > a.config.MaxFileLines {
			issue := report.Issue{
				ID:          fmt.Sprintf("large-file-lines-%s", strings.ReplaceAll(file.RelativePath, "/", "-")),
				Title:       "File has too many lines",
				Description: fmt.Sprintf("File %s has %d lines, exceeding the maximum of %d lines", file.RelativePath, file.LineCount, a.config.MaxFileLines),
				Category:    report.CategoryQuality,
				Severity:    a.determineSeverityBySize(file.LineCount),
				File:        file.RelativePath,
				Rule:        "max-file-lines",
				Fix:         "Consider breaking this file into smaller, more focused modules",
				CreatedAt:   time.Now(),
			}
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

// checkComplexityFromCache checks function complexity using cached data
func (a *QualityAnalyzer) checkComplexityFromCache(cachedFiles map[string]*scanner.UnifiedFileInfo) ([]report.Issue, error) {
	var issues []report.Issue

	for _, file := range cachedFiles {
		// Only analyze Go files
		if file.Extension != ".go" || !file.IsText {
			continue
		}

		// Use cached content if available, otherwise read file
		var content string
		if len(file.Content) > 0 {
			content = string(file.Content)
		} else {
			// For large files, read content on demand
			fileContent, err := a.readFileContent(file.Path)
			if err != nil {
				continue // Skip files that can't be read
			}
			content = string(fileContent)
		}

		functionIssues := a.analyzeFunctionComplexity(content, file.RelativePath)
		issues = append(issues, functionIssues...)
	}

	return issues, nil
}

func (a *QualityAnalyzer) checkComplexity() ([]report.Issue, error) {
	var issues []report.Issue

	goFiles, err := a.scanner.GetFilesByExtension([]string{".go"})
	if err != nil {
		return nil, err
	}

	for _, file := range goFiles {
		complexityIssues, err := a.analyzeCyclomaticComplexity(file)
		if err != nil {
			continue // Skip files we can't analyze
		}
		issues = append(issues, complexityIssues...)
	}

	return issues, nil
}

func (a *QualityAnalyzer) analyzeCyclomaticComplexity(file scanner.FileInfo) ([]report.Issue, error) {
	var issues []report.Issue

	// Find all function declarations
	functionMatches, err := a.scanner.SearchInFiles(`func\s+(\([^)]+\)\s+)?(\w+\s*)?\(`, []string{".go"})
	if err != nil {
		return nil, err
	}

	// Analyze each function for complexity
	for _, match := range functionMatches {
		if match.File == file.RelativePath {
			// Skip test files - they often need higher complexity for setup and scenarios
			if a.isTestFile(file.RelativePath) {
				continue
			}

			complexity, err := a.calculateFunctionComplexity(file, match.Line)
			if err != nil {
				continue
			}

			if complexity > a.config.ComplexityThreshold {
				issue := report.Issue{
					ID:          fmt.Sprintf("high-complexity-%s-%d", strings.ReplaceAll(file.RelativePath, "/", "-"), match.Line),
					Title:       "High function complexity",
					Description: fmt.Sprintf("Complexity: %d (threshold: %d). This function has many decision points making it harder to understand and test.", complexity, a.config.ComplexityThreshold),
					Category:    report.CategoryQuality,
					Severity:    a.determineSeverityByComplexity(complexity),
					File:        file.RelativePath,
					Line:        match.Line,
					Rule:        "cyclomatic-complexity",
					Fix:         "Break into smaller functions, reduce nested conditions, or use early returns",
					CreatedAt:   time.Now(),
				}
				issues = append(issues, issue)
			}
		}
	}

	return issues, nil
}

func (a *QualityAnalyzer) determineSeverityBySize(lines int) report.Severity {
	maxLines := a.config.MaxFileLines

	switch {
	case lines > maxLines*3:
		return report.SeverityHigh
	case lines > maxLines*2:
		return report.SeverityMedium
	default:
		return report.SeverityLow
	}
}

func (a *QualityAnalyzer) calculateFunctionComplexity(file scanner.FileInfo, startLine int) (int, error) {
	endLine, err := a.findFunctionEndLine(file, startLine)
	if err != nil {
		return 0, err
	}

	complexity := a.countComplexityPatterns(file, startLine, endLine)
	return complexity, nil
}

func (a *QualityAnalyzer) findFunctionEndLine(file scanner.FileInfo, startLine int) (int, error) {
	functionMatches, err := a.scanner.SearchInFiles(`func\s+(\([^)]+\)\s+)?(\w+\s*)?\(`, []string{".go"})
	if err != nil {
		return 0, err
	}

	endLine := file.LineCount
	for _, match := range functionMatches {
		if match.File == file.RelativePath && match.Line > startLine {
			endLine = match.Line
			break
		}
	}
	return endLine, nil
}

func (a *QualityAnalyzer) countComplexityPatterns(file scanner.FileInfo, startLine, endLine int) int {
	// Start with a baseline complexity of 1
	complexity := 1

	complexityPatterns := []string{
		`\bif\b`, `\bfor\b`, `\brange\b`, `\bswitch\b`,
		`\bcase\b`, `\bselect\b`, `&&`, `\|\|`, `\bgoto\b`,
	}

	for _, pattern := range complexityPatterns {
		matches, err := a.scanner.SearchInFiles(pattern, []string{".go"})
		if err != nil {
			continue
		}

		for _, match := range matches {
			if a.isMatchInFunction(match, file.RelativePath, startLine, endLine) {
				complexity++
			}
		}
	}

	return complexity
}

func (a *QualityAnalyzer) isMatchInFunction(match scanner.Match, filePath string, startLine, endLine int) bool {
	return match.File == filePath && match.Line >= startLine && match.Line < endLine
}

func (a *QualityAnalyzer) isTestFile(filePath string) bool {
	return a.hasTestFilePattern(filePath) || a.isInTestDirectory(filePath)
}

func (a *QualityAnalyzer) hasTestFilePattern(filePath string) bool {
	fileName := strings.ToLower(filepath.Base(filePath))

	testPatterns := []string{
		"_test.go", "_test.js", "_test.py", "_test.java",
		".test.js", ".spec.js", ".spec.ts", "test_",
	}

	for _, pattern := range testPatterns {
		if strings.HasSuffix(fileName, pattern) || strings.HasPrefix(fileName, pattern) {
			return true
		}
	}
	return false
}

func (a *QualityAnalyzer) isInTestDirectory(filePath string) bool {
	dirPath := strings.ToLower(filepath.Dir(filePath))
	testDirs := []string{
		"test", "tests", "testing", "__tests__", "spec", "specs",
		"testdata", "test-data", "fixtures", "mocks", "mock",
	}

	pathParts := strings.Split(dirPath, "/")
	for _, part := range pathParts {
		for _, testDir := range testDirs {
			if part == testDir {
				return true
			}
		}
	}
	return false
}

func (a *QualityAnalyzer) determineSeverityByComplexity(complexity int) report.Severity {
	threshold := a.config.ComplexityThreshold

	switch {
	case complexity > threshold*3: // Very high complexity
		return report.SeverityHigh
	case complexity > threshold*2: // Moderately high complexity
		return report.SeverityMedium
	default: // Slightly above the threshold
		return report.SeverityLow
	}
}

// readFileContent reads the entire content of a file
func (a *QualityAnalyzer) readFileContent(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", filePath, err)
		}
	}(file)

	return io.ReadAll(file)
}

// analyzeFunctionComplexity analyzes function complexity from file content
func (a *QualityAnalyzer) analyzeFunctionComplexity(content, filePath string) []report.Issue {
	var issues []report.Issue

	// Skip test files
	if a.isTestFile(filePath) {
		return issues
	}

	// Find all function declarations using regex
	funcRegex := regexp.MustCompile(`func\s+(\([^)]+\)\s+)?(\w+\s*)?\(`)
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if funcRegex.MatchString(line) {
			// Calculate complexity for this function
			complexity := a.calculateComplexityFromContent(content, lineNum+1)
			if complexity > a.config.ComplexityThreshold {
				issue := report.Issue{
					ID:          fmt.Sprintf("high-complexity-%s-%d", strings.ReplaceAll(filePath, "/", "-"), lineNum+1),
					Title:       "High function complexity",
					Description: fmt.Sprintf("Complexity: %d (threshold: %d). This function has many decision points making it harder to understand and test.", complexity, a.config.ComplexityThreshold),
					Category:    report.CategoryQuality,
					Severity:    a.determineSeverityByComplexity(complexity),
					File:        filePath,
					Line:        lineNum + 1,
					Rule:        "cyclomatic-complexity",
					Fix:         "Break into smaller functions, reduce nested conditions, or use early returns",
					CreatedAt:   time.Now(),
				}
				issues = append(issues, issue)
			}
		}
	}

	return issues
}

// calculateComplexityFromContent calculates cyclomatic complexity from file content
func (a *QualityAnalyzer) calculateComplexityFromContent(content string, startLine int) int {
	// Start with a baseline complexity of 1
	complexity := 1
	lines := strings.Split(content, "\n")

	// Find the end of the function (next function or end of file)
	endLine := len(lines)
	funcRegex := regexp.MustCompile(`func\s+(\([^)]+\)\s+)?(\w+\s*)?\(`)
	for i := startLine; i < len(lines); i++ {
		if funcRegex.MatchString(lines[i]) {
			endLine = i
			break
		}
	}

	// Count complexity patterns in the function
	complexityPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\bif\b`),
		regexp.MustCompile(`\bfor\b`),
		regexp.MustCompile(`\brange\b`),
		regexp.MustCompile(`\bswitch\b`),
		regexp.MustCompile(`\bcase\b`),
		regexp.MustCompile(`\bselect\b`),
		regexp.MustCompile(`&&`),
		regexp.MustCompile(`\|\|`),
		regexp.MustCompile(`\bgoto\b`),
	}

	for i := startLine - 1; i < endLine && i < len(lines); i++ {
		line := lines[i]
		for _, pattern := range complexityPatterns {
			if pattern.MatchString(line) {
				complexity++
			}
		}
	}

	return complexity
}
