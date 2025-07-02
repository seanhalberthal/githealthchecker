package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
)

func TestDependencyAnalyzer_Analyze(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dependency_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{
		CheckOutdated:        true,
		CheckVulnerabilities: true,
		MaxDaysOutdated:      180,
		BlockedPackages:      []string{"lodash", "moment"},
	}

	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Test with no dependency files
	issues, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analyze() failed: %v", err)
	}

	if len(issues) != 0 {
		t.Errorf("Expected 0 issues for empty directory, got %d", len(issues))
	}
}

func TestDependencyAnalyzer_HasGoMod(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gomod_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Test without go.mod
	if analyzer.hasGoMod() {
		t.Error("hasGoMod() should return false when go.mod doesn't exist")
	}

	// Create go.mod file
	goModContent := `module test/project

go 1.21

require (
	github.com/spf13/cobra v1.7.0
)
`
	goModPath := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to create go.mod: %v", err)
	}

	// Test with go.mod
	if !analyzer.hasGoMod() {
		t.Error("hasGoMod() should return true when go.mod exists")
	}
}

func TestDependencyAnalyzer_HasPackageJson(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "packagejson_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Test without package.json
	if analyzer.hasPackageJson() {
		t.Error("hasPackageJson() should return false when package.json doesn't exist")
	}

	// Create package.json file
	packageJsonContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.2"
  }
}`
	packageJsonPath := filepath.Join(tempDir, "package.json")
	if err := os.WriteFile(packageJsonPath, []byte(packageJsonContent), 0644); err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	// Test with package.json
	if !analyzer.hasPackageJson() {
		t.Error("hasPackageJson() should return true when package.json exists")
	}
}

func TestDependencyAnalyzer_AnalyzeNodeModules(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "node_deps_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{
		BlockedPackages: []string{"lodash", "moment"},
	}
	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Create package.json with blocked dependency
	packageJsonContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.2"
  }
}`
	packageJsonPath := filepath.Join(tempDir, "package.json")
	if err := os.WriteFile(packageJsonPath, []byte(packageJsonContent), 0644); err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	issues, err := analyzer.analyzeNodeModules()
	if err != nil {
		t.Fatalf("analyzeNodeModules() failed: %v", err)
	}

	if len(issues) != 1 {
		t.Errorf("Expected 1 issue for blocked dependency, got %d", len(issues))
	}

	if len(issues) > 0 {
		issue := issues[0]
		if issue.Title != "Blocked Node.js dependency" {
			t.Errorf("Expected title 'Blocked Node.js dependency', got '%s'", issue.Title)
		}
		if issue.Severity != report.SeverityHigh {
			t.Errorf("Expected high severity, got %s", issue.Severity)
		}
		if issue.File != "package.json" {
			t.Errorf("Expected file 'package.json', got '%s'", issue.File)
		}
	}
}

func TestDependencyAnalyzer_IsBlockedPackage(t *testing.T) {
	cfg := &config.DependencyConfig{
		BlockedPackages: []string{"lodash", "moment", "github.com/spf13/cobra"},
	}
	analyzer := NewDependencyAnalyzer(cfg, "")

	tests := []struct {
		packageName string
		expected    bool
	}{
		{"lodash", true},
		{"moment", true},
		{"github.com/spf13/cobra", true},
		{"express", false},
		{"react", false},
		{"github.com/gin-gonic/gin", false},
	}

	for _, test := range tests {
		result := analyzer.isBlockedPackage(test.packageName)
		if result != test.expected {
			t.Errorf("isBlockedPackage(%s) = %v, expected %v", test.packageName, result, test.expected)
		}
	}
}

func TestDependencyAnalyzer_DetermineOutdatedSeverity(t *testing.T) {
	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, "")

	tests := []struct {
		daysOld  int
		expected report.Severity
	}{
		{30, report.SeverityLow},
		{200, report.SeverityMedium},
		{400, report.SeverityHigh},
		{100, report.SeverityLow},
	}

	for _, test := range tests {
		result := analyzer.determineOutdatedSeverity(test.daysOld)
		if result != test.expected {
			t.Errorf("determineOutdatedSeverity(%d) = %s, expected %s", test.daysOld, result, test.expected)
		}
	}
}

func TestDependencyAnalyzer_CalculateDaysOld(t *testing.T) {
	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, "")

	// Test valid time strings - using a time from 100 days ago
	pastTime := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)

	days := analyzer.calculateDaysOld(pastTime)

	// Should be approximately 100 days (allowing for some variance due to timing)
	if days < 95 || days > 105 {
		t.Errorf("calculateDaysOld() = %d, expected around 100 days", days)
	}
}

func TestDependencyAnalyzer_GetModuleName(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "module_name_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Test without go.mod
	moduleName := analyzer.getModuleName()
	if moduleName != "" {
		t.Errorf("getModuleName() should return empty string when go.mod doesn't exist, got '%s'", moduleName)
	}

	// Create go.mod file
	goModContent := `module github.com/test/project

go 1.21

require (
	github.com/spf13/cobra v1.7.0
)
`
	goModPath := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to create go.mod: %v", err)
	}

	// Test with go.mod
	moduleName = analyzer.getModuleName()
	expected := "github.com/test/project"
	if moduleName != expected {
		t.Errorf("getModuleName() = '%s', expected '%s'", moduleName, expected)
	}
}

func TestDependencyAnalyzer_GetGoModDependencies(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gomod_deps_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Create go.mod file with dependencies
	goModContent := `module github.com/test/project

go 1.21

require (
	github.com/spf13/cobra v1.7.0
	github.com/fatih/color v1.15.0
	github.com/olekukonko/tablewriter v1.0.5
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
)
`
	goModPath := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to create go.mod: %v", err)
	}

	dependencies, err := analyzer.getGoModDependencies()
	if err != nil {
		t.Fatalf("getGoModDependencies() failed: %v", err)
	}

	expectedDeps := []string{
		"github.com/spf13/cobra",
		"github.com/fatih/color",
		"github.com/olekukonko/tablewriter",
		"github.com/inconshreveable/mousetrap",
		"github.com/mattn/go-colorable",
	}

	if len(dependencies) != len(expectedDeps) {
		t.Errorf("Expected %d dependencies, got %d", len(expectedDeps), len(dependencies))
	}

	depMap := make(map[string]bool)
	for _, dep := range dependencies {
		depMap[dep] = true
	}

	for _, expected := range expectedDeps {
		if !depMap[expected] {
			t.Errorf("Expected dependency %s not found", expected)
		}
	}
}

func TestDependencyAnalyzer_ExtractDependencyName(t *testing.T) {
	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, ".")

	tests := []struct {
		line     string
		expected string
	}{
		{"github.com/spf13/cobra v1.7.0", "github.com/spf13/cobra"},
		{"  github.com/fatih/color v1.15.0  ", "github.com/fatih/color"},
		{"github.com/inconshreveable/mousetrap v1.1.0 // indirect", "github.com/inconshreveable/mousetrap"},
		{"", ""},
		{"// comment line", ""},
		{"(github.com/test/pkg v1.0.0)", "github.com/test/pkg"},
	}

	for _, test := range tests {
		result := analyzer.extractDependencyName(test.line)
		if result != test.expected {
			t.Errorf("extractDependencyName(%q) = %q, expected %q", test.line, result, test.expected)
		}
	}
}

func TestDependencyAnalyzer_ExtractImportPath(t *testing.T) {
	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, ".")

	tests := []struct {
		line     string
		expected string
	}{
		{`"fmt"`, "fmt"},
		{`"github.com/spf13/cobra"`, "github.com/spf13/cobra"},
		{`_ "github.com/lib/pq"`, "github.com/lib/pq"},
		{`color "github.com/fatih/color"`, "github.com/fatih/color"},
		{`  "strings"  `, "strings"},
		{`'github.com/test/pkg'`, "github.com/test/pkg"},
		{"", ""},
		{"// comment", ""},
	}

	for _, test := range tests {
		result := analyzer.extractImportPath(test.line)
		if result != test.expected {
			t.Errorf("extractImportPath(%q) = %q, expected %q", test.line, result, test.expected)
		}
	}
}

func TestDependencyAnalyzer_ExtractImportsFromFile(t *testing.T) {
	tempFile, err := os.CreateTemp("", "imports_test_*.go")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			t.Fatalf("Failed to remove temp file %s: %v", name, err)
		}
	}(tempFile.Name())

	content := `package main

import (
	"fmt"
	"strings"
	
	"github.com/spf13/cobra"
	color "github.com/fatih/color"
	_ "github.com/lib/pq"
)

import "os"

func main() {
	// some code
}
`

	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	err = tempFile.Close()
	if err != nil {
		return
	}

	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, ".")

	imports, err := analyzer.extractImportsFromFile(tempFile.Name())
	if err != nil {
		t.Fatalf("extractImportsFromFile() failed: %v", err)
	}

	expectedImports := []string{
		"fmt",
		"strings",
		"github.com/spf13/cobra",
		"github.com/fatih/color",
		"github.com/lib/pq",
		"os",
	}

	if len(imports) != len(expectedImports) {
		t.Errorf("Expected %d imports, got %d", len(expectedImports), len(imports))
	}

	for _, expected := range expectedImports {
		if !imports[expected] {
			t.Errorf("Expected import %s not found", expected)
		}
	}
}

func TestDependencyAnalyzer_IsImportUsed(t *testing.T) {
	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, ".")

	imports := map[string]bool{
		"fmt":                    true,
		"github.com/spf13/cobra": true,
		"github.com/fatih/color": true,
		"github.com/go-git/go-git/v5/storage/filesystem": true,
	}

	tests := []struct {
		dependency string
		expected   bool
	}{
		{"fmt", true},                         // exact match
		{"github.com/spf13/cobra", true},      // exact match
		{"github.com/fatih/color", true},      // exact match
		{"github.com/go-git/go-git/v5", true}, // subpackage used
		{"github.com/unused/package", false},  // not used
		{"strings", false},                    // not imported
	}

	for _, test := range tests {
		result := analyzer.isImportUsed(test.dependency, imports)
		if result != test.expected {
			t.Errorf("isImportUsed(%q) = %v, expected %v", test.dependency, result, test.expected)
		}
	}
}

func TestDependencyAnalyzer_IsStandardLibrary(t *testing.T) {
	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, ".")

	tests := []struct {
		pkg      string
		expected bool
	}{
		{"fmt", true},
		{"strings", true},
		{"net/http", true},
		{"crypto/sha256", true},
		{"encoding/json", true},
		{"github.com/spf13/cobra", false},
		{"golang.org/x/crypto", false},
		{"gopkg.in/yaml.v2", false},
		{"internal/package", true}, // no dots, likely stdlib
	}

	for _, test := range tests {
		result := analyzer.isStandardLibrary(test.pkg)
		if result != test.expected {
			t.Errorf("isStandardLibrary(%q) = %v, expected %v", test.pkg, result, test.expected)
		}
	}
}

func TestDependencyAnalyzer_AnalyzeUnusedGoModules_Integration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unused_deps_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	cfg := &config.DependencyConfig{}
	analyzer := NewDependencyAnalyzer(cfg, tempDir)

	// Create go.mod file
	goModContent := `module github.com/test/project

go 1.21

require (
	github.com/spf13/cobra v1.7.0
	github.com/fatih/color v1.15.0
	github.com/olekukonko/tablewriter v1.0.5
)
`
	goModPath := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to create go.mod: %v", err)
	}

	// Create Go file that uses only some dependencies
	mainContent := `package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

func main() {
	cmd := cobra.Command{}
	fmt.Println("Hello")
}
`
	mainPath := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
		t.Fatalf("Failed to create main.go: %v", err)
	}

	// Analyze unused dependencies
	issues, err := analyzer.analyzeUnusedGoModules()
	if err != nil {
		t.Fatalf("analyzeUnusedGoModules() failed: %v", err)
	}

	// Should find 2 unused dependencies: fatih/color and olekukonko/tablewriter
	expectedUnused := []string{
		"github.com/fatih/color",
		"github.com/olekukonko/tablewriter",
	}

	if len(issues) != len(expectedUnused) {
		t.Errorf("Expected %d unused dependencies, got %d", len(expectedUnused), len(issues))
	}

	foundUnused := make(map[string]bool)
	for _, issue := range issues {
		if issue.Category == report.CategoryDependencies && issue.Rule == "unused-dependencies" {
			// Extract package name from description
			for _, pkg := range expectedUnused {
				if strings.Contains(issue.Description, pkg) {
					foundUnused[pkg] = true
					break
				}
			}
		}
	}

	for _, expected := range expectedUnused {
		if !foundUnused[expected] {
			t.Errorf("Expected unused dependency %s not found in issues", expected)
		}
	}
}
