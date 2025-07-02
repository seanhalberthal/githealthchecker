package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/githealthchecker/git-health-checker/internal/scanner"
)

type SecurityAnalyzer struct {
	config           *config.SecurityConfig
	scanner          *scanner.FileScanner
	compiledPatterns []*regexp.Regexp
	patternOnce      sync.Once
}

func NewSecurityAnalyzer(cfg *config.SecurityConfig, fileScanner *scanner.FileScanner) *SecurityAnalyzer {
	analyzer := &SecurityAnalyzer{
		config:  cfg,
		scanner: fileScanner,
	}
	// Pre-compile patterns on creation
	analyzer.compilePatterns()
	return analyzer
}

// compilePatterns pre-compiles all regex patterns for better performance
func (a *SecurityAnalyzer) compilePatterns() {
	a.patternOnce.Do(func() {
		a.compiledPatterns = make([]*regexp.Regexp, 0, len(a.config.SecretPatterns))
		for _, pattern := range a.config.SecretPatterns {
			if compiled, err := regexp.Compile(pattern); err == nil {
				a.compiledPatterns = append(a.compiledPatterns, compiled)
			}
			// Skip invalid patterns silently to avoid breaking the analyzer
		}
	})
}

func (a *SecurityAnalyzer) Analyze() ([]report.Issue, error) {
	var issues []report.Issue

	secretIssues, err := a.scanForSecrets()
	if err != nil {
		return nil, fmt.Errorf("failed to scan for secrets: %w", err)
	}
	issues = append(issues, secretIssues...)

	suspiciousIssues, err := a.scanForSuspiciousFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to scan for suspicious files: %w", err)
	}
	issues = append(issues, suspiciousIssues...)

	return issues, nil
}

func (a *SecurityAnalyzer) scanForSecrets() ([]report.Issue, error) {
	// Use cached files if available for better performance
	cachedFiles := a.scanner.GetCachedFiles()
	if len(cachedFiles) > 0 {
		return a.scanSecretsFromCache(cachedFiles)
	}

	// Fallback to original pattern-based search
	return a.scanSecretsWithPatterns()
}

// scanSecretsWithPatterns performs pattern-based secret scanning
func (a *SecurityAnalyzer) scanSecretsWithPatterns() ([]report.Issue, error) {
	var issues []report.Issue
	extensions := []string{".go", ".mod", ".sum", ".yaml", ".yml", ".json", ".env"}

	for _, pattern := range a.config.SecretPatterns {
		patternIssues, err := a.searchPatternForSecrets(pattern, extensions)
		if err != nil {
			return nil, err
		}
		issues = append(issues, patternIssues...)
	}

	return issues, nil
}

// searchPatternForSecrets searches for a specific pattern and creates issues
func (a *SecurityAnalyzer) searchPatternForSecrets(pattern string, extensions []string) ([]report.Issue, error) {
	matches, err := a.scanner.SearchInFiles(pattern, extensions)
	if err != nil {
		return nil, fmt.Errorf("failed to search for pattern %s: %w", pattern, err)
	}

	var issues []report.Issue
	for _, match := range matches {
		if issue := a.processSecretMatch(match); issue != nil {
			issues = append(issues, *issue)
		}
	}

	return issues, nil
}

// processSecretMatch processes a single secret match and returns issue if valid
func (a *SecurityAnalyzer) processSecretMatch(match scanner.Match) *report.Issue {
	if a.shouldSkipSecretMatch(match) {
		return nil
	}

	if a.isAllowedSecret(match.Content) {
		return nil
	}

	severity := a.determineSecretSeverity(match.Content)
	return &report.Issue{
		ID:          fmt.Sprintf("secret-%s-%d", strings.ReplaceAll(match.File, "/", "-"), match.Line),
		Title:       "Potential secret detected",
		Description: fmt.Sprintf("Found pattern that may contain credentials: %s", truncateString(match.Content, 80)),
		Category:    report.CategorySecurity,
		Severity:    severity,
		File:        match.File,
		Line:        match.Line,
		Rule:        "secret-detection",
		Fix:         "Use environment variables or secure secret management",
		CreatedAt:   time.Now(),
	}
}

// shouldSkipSecretMatch determines if a secret match should be skipped
func (a *SecurityAnalyzer) shouldSkipSecretMatch(match scanner.Match) bool {
	return a.isTestFile(match.File) || a.isSecurityAnalyzerFile(match.File)
}

// scanSecretsFromCache scans for secrets using cached file content with pre-compiled patterns
func (a *SecurityAnalyzer) scanSecretsFromCache(cachedFiles map[string]*scanner.UnifiedFileInfo) ([]report.Issue, error) {
	var issues []report.Issue
	relevantExtensions := map[string]bool{
		".go": true, ".mod": true, ".sum": true, ".yaml": true, ".yml": true, ".json": true, ".env": true,
	}

	for _, file := range cachedFiles {
		if !a.shouldProcessCachedFile(file, relevantExtensions) {
			continue
		}

		content := a.getFileContentForScanning(file)
		if content == nil {
			continue
		}

		fileIssues := a.searchSecretsInContent(string(content), file.RelativePath)
		issues = append(issues, fileIssues...)
	}

	return issues, nil
}

// shouldProcessCachedFile determines if a cached file should be processed for secrets
func (a *SecurityAnalyzer) shouldProcessCachedFile(file *scanner.UnifiedFileInfo, relevantExtensions map[string]bool) bool {
	// Skip if not a relevant file type
	if !relevantExtensions[file.Extension] && file.Extension != "" {
		return false
	}

	// Skip test files and security analyzer files
	if a.isTestFile(file.RelativePath) || a.isSecurityAnalyzerFile(file.RelativePath) {
		return false
	}

	// Only scan text files
	return file.IsText
}

// getFileContentForScanning gets file content for scanning (cached or read on demand)
func (a *SecurityAnalyzer) getFileContentForScanning(file *scanner.UnifiedFileInfo) []byte {
	if len(file.Content) > 0 {
		return file.Content
	}

	// For large files, read content on demand
	fileContent, err := a.readFileContent(file.Path)
	if err != nil {
		return nil // Skip files that can't be read
	}
	return fileContent
}

// searchSecretsInContent searches for secrets in file content using compiled patterns
func (a *SecurityAnalyzer) searchSecretsInContent(content, filePath string) []report.Issue {
	var issues []report.Issue
	lines := strings.Split(content, "\n")

	for _, pattern := range a.compiledPatterns {
		for lineNum, line := range lines {
			if matches := pattern.FindAllString(line, -1); len(matches) > 0 {
				for _, match := range matches {
					if a.isAllowedSecret(match) {
						continue
					}

					severity := a.determineSecretSeverity(match)

					issue := report.Issue{
						ID:          fmt.Sprintf("secret-%s-%d", strings.ReplaceAll(filePath, "/", "-"), lineNum+1),
						Title:       "Potential secret detected",
						Description: fmt.Sprintf("Found pattern that may contain credentials: %s", truncateString(line, 80)),
						Category:    report.CategorySecurity,
						Severity:    severity,
						File:        filePath,
						Line:        lineNum + 1,
						Rule:        "secret-detection",
						Fix:         "Use environment variables or secure secret management",
						CreatedAt:   time.Now(),
					}
					issues = append(issues, issue)
				}
			}
		}
	}

	return issues
}

func (a *SecurityAnalyzer) scanForSuspiciousFiles() ([]report.Issue, error) {
	var issues []report.Issue

	// Use cached files if available for better performance
	cachedFiles := a.scanner.GetCachedFiles()
	if len(cachedFiles) > 0 {
		for _, file := range cachedFiles {
			// Skip test files - they often contain test data files
			if a.isTestFile(file.RelativePath) {
				continue
			}

			if a.isSuspiciousFile(file.RelativePath) {
				severity := a.determineSuspiciousFileSeverity(file.RelativePath)

				issue := report.Issue{
					ID:          fmt.Sprintf("suspicious-file-%s", strings.ReplaceAll(file.RelativePath, "/", "-")),
					Title:       "Suspicious file detected",
					Description: fmt.Sprintf("File %s may contain sensitive information and should not be in version control", file.RelativePath),
					Category:    report.CategorySecurity,
					Severity:    severity,
					File:        file.RelativePath,
					Rule:        "suspicious-file-detection",
					Fix:         "Remove the file from version control and add to .gitignore",
					CreatedAt:   time.Now(),
				}
				issues = append(issues, issue)
			}
		}
		return issues, nil
	}

	// Fallback to original method
	files, err := a.scanner.ScanFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to scan files: %w", err)
	}

	for _, file := range files {
		// Skip test files - they often contain test data files
		if a.isTestFile(file.RelativePath) {
			continue
		}

		if a.isSuspiciousFile(file.RelativePath) {
			severity := a.determineSuspiciousFileSeverity(file.RelativePath)

			issue := report.Issue{
				ID:          fmt.Sprintf("suspicious-file-%s", strings.ReplaceAll(file.RelativePath, "/", "-")),
				Title:       "Suspicious file detected",
				Description: fmt.Sprintf("File %s may contain sensitive information and should not be in version control", file.RelativePath),
				Category:    report.CategorySecurity,
				Severity:    severity,
				File:        file.RelativePath,
				Rule:        "suspicious-file-detection",
				Fix:         "Remove the file from version control and add to .gitignore",
				CreatedAt:   time.Now(),
			}
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

func (a *SecurityAnalyzer) isAllowedSecret(content string) bool {
	content = strings.ToLower(content)
	for _, allowed := range a.config.AllowedSecrets {
		if strings.Contains(content, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

func (a *SecurityAnalyzer) determineSecretSeverity(content string) report.Severity {
	content = strings.ToLower(content)

	// Only check for actual assignment patterns, not just words
	highRiskPatterns := []string{
		"private_key", "private key", "secret_key", "secret key",
		"password[:=]", "password =", "password:", "token[:=]", "token =", "token:",
	}
	mediumRiskPatterns := []string{
		"api_key", "api key", "access_key", "access key",
		"apikey[:=]", "apikey =", "apikey:",
	}

	for _, pattern := range highRiskPatterns {
		if strings.Contains(content, pattern) {
			return report.SeverityHigh
		}
	}

	for _, pattern := range mediumRiskPatterns {
		if strings.Contains(content, pattern) {
			return report.SeverityMedium
		}
	}

	return report.SeverityLow
}

func (a *SecurityAnalyzer) isSuspiciousFile(filePath string) bool {
	fileName := filepath.Base(filePath)

	for _, pattern := range a.config.SuspiciousFiles {
		if matched, _ := filepath.Match(pattern, fileName); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
	}

	return false
}

func (a *SecurityAnalyzer) determineSuspiciousFileSeverity(filePath string) report.Severity {
	fileName := strings.ToLower(filepath.Base(filePath))

	criticalFiles := []string{".env", "id_rsa", "id_dsa", "private.key", "server.key"}
	highRiskExtensions := []string{".pem", ".key", ".p12", ".pfx", ".jks"}

	for _, critical := range criticalFiles {
		if fileName == critical || strings.HasSuffix(fileName, critical) {
			return report.SeverityCritical
		}
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	for _, riskExt := range highRiskExtensions {
		if ext == riskExt {
			return report.SeverityHigh
		}
	}

	return report.SeverityMedium
}

func (a *SecurityAnalyzer) isTestFile(filePath string) bool {
	return a.hasTestFilePattern(filePath) || a.isInTestDirectory(filePath)
}

func (a *SecurityAnalyzer) hasTestFilePattern(filePath string) bool {
	fileName := strings.ToLower(filepath.Base(filePath))

	testPatterns := []string{
		"_test.go", "test_",
	}

	for _, pattern := range testPatterns {
		if strings.HasSuffix(fileName, pattern) || strings.HasPrefix(fileName, pattern) {
			return true
		}
	}
	return false
}

func (a *SecurityAnalyzer) isInTestDirectory(filePath string) bool {
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

func (a *SecurityAnalyzer) isSecurityAnalyzerFile(filePath string) bool {
	// Skip files that contain security detection patterns (to avoid false positives)
	return strings.Contains(filePath, "security.go") ||
		strings.Contains(filePath, "analyzer/security") ||
		strings.Contains(filePath, "security_test.go")
}

// readFileContent reads the entire content of a file
func (a *SecurityAnalyzer) readFileContent(filePath string) ([]byte, error) {
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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
