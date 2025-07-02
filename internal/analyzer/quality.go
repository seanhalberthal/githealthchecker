package analyzer

import (
	"fmt"
	"path/filepath"
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
