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

type SecurityAnalyzer struct {
	config  *config.SecurityConfig
	scanner *scanner.FileScanner
}

func NewSecurityAnalyzer(cfg *config.SecurityConfig, fileScanner *scanner.FileScanner) *SecurityAnalyzer {
	return &SecurityAnalyzer{
		config:  cfg,
		scanner: fileScanner,
	}
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
	var issues []report.Issue

	for _, pattern := range a.config.SecretPatterns {
		matches, err := a.scanner.SearchInFiles(pattern, []string{".go", ".js", ".py", ".java", ".rb", ".php", ".cs", ".cpp", ".c", ".sh", ".yaml", ".yml", ".json", ".xml", ".properties", ".env"})
		if err != nil {
			return nil, fmt.Errorf("failed to search for pattern %s: %w", pattern, err)
		}

		for _, match := range matches {
			// Skip test files - they often contain test data that looks like secrets
			if a.isTestFile(match.File) {
				continue
			}

			// Skip security analyzer files that contain the detection patterns
			if a.isSecurityAnalyzerFile(match.File) {
				continue
			}

			if a.isAllowedSecret(match.Content) {
				continue
			}

			severity := a.determineSecretSeverity(match.Content)

			issue := report.Issue{
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
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

func (a *SecurityAnalyzer) scanForSuspiciousFiles() ([]report.Issue, error) {
	var issues []report.Issue

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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
