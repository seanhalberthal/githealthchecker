package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/githealthchecker/git-health-checker/internal/scanner"
)

func TestSecurityAnalyzer_Analyze(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "security_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	// Create test files with different types of content
	testFiles := map[string]string{
		"secret.go":   `package main\nconst apiKey = "sk_test_1234567890abcdef"\nfunc main() {}`,
		"password.py": `#!/usr/bin/env python\nPASSWORD = "super_secret_password"\nprint("Hello")`,
		"normal.go":   `package main\nfunc main() {\n\tfmt.Println("Hello, World!")\n}`,
		"config.env":  `DATABASE_URL=postgres://user:pass@localhost/db\nAPI_SECRET=secret123`,
		"private.key": `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----`,
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

	// Create security config
	cfg := &config.SecurityConfig{
		SecretPatterns: []string{
			`(?i)api[_-]?key[\\s]*[:=][\\s]*['\"]?[a-zA-Z0-9]{20,}['\"]?`,
			`(?i)password[\\s]*[:=][\\s]*['\"]?[^\\s'\"]{8,}['\"]?`,
			`(?i)secret[\\s]*[:=][\\s]*['\"]?[a-zA-Z0-9]{8,}['\"]?`,
		},
		SuspiciousFiles: []string{
			"*.key",
			"*.env",
			"private.*",
		},
		AllowedSecrets: []string{
			"test_key",
			"example_password",
		},
	}

	// Create analyzer
	analyzer := NewSecurityAnalyzer(cfg, fileScanner)

	// Run analysis
	issues, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Verify we found issues
	if len(issues) == 0 {
		t.Error("Expected to find security issues, but none were found")
	}

	// Check that we found both secret and suspicious file issues
	foundSecretIssue := false
	foundSuspiciousFileIssue := false

	for _, issue := range issues {
		if issue.Category != report.CategorySecurity {
			t.Errorf("Expected security category, got %s", issue.Category)
		}

		switch issue.Rule {
		case "secret-detection":
			foundSecretIssue = true
			if issue.Title != "Potential secret detected" {
				t.Errorf("Expected 'Potential secret detected', got '%s'", issue.Title)
			}
		case "suspicious-file-detection":
			foundSuspiciousFileIssue = true
			if issue.Title != "Suspicious file detected" {
				t.Errorf("Expected 'Suspicious file detected', got '%s'", issue.Title)
			}
		}
	}

	if !foundSecretIssue {
		t.Error("Expected to find at least one secret detection issue")
	}

	if !foundSuspiciousFileIssue {
		t.Error("Expected to find at least one suspicious file issue")
	}
}

func TestSecurityAnalyzer_DetermineSecretSeverity(t *testing.T) {
	cfg := &config.SecurityConfig{}
	analyzer := &SecurityAnalyzer{config: cfg}

	tests := []struct {
		content  string
		expected report.Severity
	}{
		{"private_key = value", report.SeverityHigh},
		{"password = secret123", report.SeverityHigh},
		{"secret_key = abc123", report.SeverityHigh},
		{"api_key = test_value", report.SeverityMedium},
		{"access_key = value", report.SeverityMedium},
		{"some_config = value", report.SeverityLow},
	}

	for _, test := range tests {
		result := analyzer.determineSecretSeverity(test.content)
		if result != test.expected {
			t.Errorf("For content '%s', expected severity %s, got %s",
				test.content, test.expected, result)
		}
	}
}

func TestSecurityAnalyzer_IsAllowedSecret(t *testing.T) {
	cfg := &config.SecurityConfig{
		AllowedSecrets: []string{"test_key", "example_password"},
	}
	analyzer := &SecurityAnalyzer{config: cfg}

	tests := []struct {
		content  string
		expected bool
	}{
		{"api_key = test_key", true},
		{"password = example_password", true},
		{"secret = real_secret", false},
		{"token = actual_token", false},
	}

	for _, test := range tests {
		result := analyzer.isAllowedSecret(test.content)
		if result != test.expected {
			t.Errorf("For content '%s', expected %v, got %v",
				test.content, test.expected, result)
		}
	}
}

func TestSecurityAnalyzer_DetermineSuspiciousFileSeverity(t *testing.T) {
	cfg := &config.SecurityConfig{}
	a := &SecurityAnalyzer{config: cfg}

	tests := []struct {
		filePath string
		expected report.Severity
	}{
		{".env", report.SeverityCritical},
		{"id_rsa", report.SeverityCritical},
		{"private.key", report.SeverityCritical},
		{"server.key", report.SeverityCritical},
		{"cert.pem", report.SeverityHigh},
		{"keystore.jks", report.SeverityHigh},
		{"config.p12", report.SeverityHigh},
		{"backup.sql", report.SeverityMedium},
	}

	for _, test := range tests {
		result := a.determineSuspiciousFileSeverity(test.filePath)
		if result != test.expected {
			t.Errorf("For file '%s', expected severity %s, got %s",
				test.filePath, test.expected, result)
		}
	}
}
