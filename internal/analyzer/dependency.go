package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
)

const goMod = "go.mod"
const packageJson = "package.json"
const failedToCloseGoModError = "failed to close " + goMod + " file: %v\n"

type DependencyAnalyzer struct {
	config   *config.DependencyConfig
	repoPath string
}

type GoModInfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Time    string `json:"Time"`
	Update  struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
		Time    string `json:"Time"`
	} `json:"Update"`
}

type PackageInfo struct {
	Name             string
	CurrentVersion   string
	LatestVersion    string
	DaysOld          int
	HasVulnerability bool
	IsBlocked        bool
}

func NewDependencyAnalyzer(cfg *config.DependencyConfig, repoPath string) *DependencyAnalyzer {
	return &DependencyAnalyzer{
		config:   cfg,
		repoPath: repoPath,
	}
}

func (a *DependencyAnalyzer) Analyze() ([]report.Issue, error) {
	var issues []report.Issue

	// Check for Go dependencies
	if a.hasGoMod() {
		goIssues, err := a.analyzeGoModules()
		if err != nil {
			return nil, fmt.Errorf("failed to analyze Go modules: %w", err)
		}
		issues = append(issues, goIssues...)

		// Check for unused Go dependencies
		unusedIssues, err := a.analyzeUnusedGoModules()
		if err != nil {
			return nil, fmt.Errorf("failed to analyze unused Go modules: %w", err)
		}
		issues = append(issues, unusedIssues...)
	}

	// Check for Node.js dependencies
	if a.hasPackageJson() {
		nodeIssues, err := a.analyzeNodeModules()
		if err != nil {
			return nil, fmt.Errorf("failed to analyze Node modules: %w", err)
		}
		issues = append(issues, nodeIssues...)
	}

	return issues, nil
}

func (a *DependencyAnalyzer) hasGoMod() bool {
	_, err := os.Stat(filepath.Join(a.repoPath, goMod))
	return err == nil
}

func (a *DependencyAnalyzer) hasPackageJson() bool {
	_, err := os.Stat(filepath.Join(a.repoPath, packageJson))
	return err == nil
}

func (a *DependencyAnalyzer) analyzeGoModules() ([]report.Issue, error) {
	if !a.config.CheckOutdated {
		return []report.Issue{}, nil
	}

	packages, err := a.getGoModulePackages()
	if err != nil {
		return nil, err
	}

	return a.processGoModulePackages(packages), nil
}

func (a *DependencyAnalyzer) getGoModulePackages() ([]PackageInfo, error) {
	cmd := exec.Command("go", "list", "-u", "-m", "-json", "all")
	cmd.Dir = a.repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run go list: %w", err)
	}

	packages, err := a.parseGoModules(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go modules: %w", err)
	}

	return packages, nil
}

func (a *DependencyAnalyzer) processGoModulePackages(packages []PackageInfo) []report.Issue {
	var issues []report.Issue
	moduleName := a.getModuleName()

	for _, pkg := range packages {
		if a.shouldSkipPackage(pkg, moduleName) {
			continue
		}

		if issue := a.checkBlockedGoPackage(pkg); issue != nil {
			issues = append(issues, *issue)
			continue
		}

		if issue := a.checkOutdatedGoPackage(pkg); issue != nil {
			issues = append(issues, *issue)
		}
	}

	return issues
}

func (a *DependencyAnalyzer) shouldSkipPackage(pkg PackageInfo, moduleName string) bool {
	// Skip the main module
	if strings.HasPrefix(pkg.Name, moduleName) {
		return true
	}

	// Skip indirect/transitive dependencies for outdated checks
	// Only check direct dependencies that users can control
	return a.isTransitiveDependency(pkg.Name)
}

func (a *DependencyAnalyzer) checkBlockedGoPackage(pkg PackageInfo) *report.Issue {
	if !a.isBlockedPackage(pkg.Name) {
		return nil
	}

	return &report.Issue{
		ID:          fmt.Sprintf("blocked-dependency-%s", strings.ReplaceAll(pkg.Name, "/", "-")),
		Title:       "Blocked dependency detected",
		Description: fmt.Sprintf("Package %s is in the blocked list and should not be used", pkg.Name),
		Category:    report.CategorySecurity,
		Severity:    report.SeverityHigh,
		File:        goMod,
		Rule:        "blocked-dependencies",
		Fix:         fmt.Sprintf("Remove %s and find an alternative package", pkg.Name),
		CreatedAt:   time.Now(),
	}
}

func (a *DependencyAnalyzer) checkOutdatedGoPackage(pkg PackageInfo) *report.Issue {
	if pkg.DaysOld <= a.config.MaxDaysOutdated {
		return nil
	}

	severity := a.determineOutdatedSeverity(pkg.DaysOld)
	return &report.Issue{
		ID:          fmt.Sprintf("outdated-dependency-%s", strings.ReplaceAll(pkg.Name, "/", "-")),
		Title:       "Outdated dependency",
		Description: fmt.Sprintf("Package %s is %d days old (current: %s, latest: %s)", pkg.Name, pkg.DaysOld, pkg.CurrentVersion, pkg.LatestVersion),
		Category:    report.CategoryDependencies,
		Severity:    severity,
		File:        goMod,
		Rule:        "outdated-dependencies",
		Fix:         fmt.Sprintf("Update to latest version: go get %s@%s", pkg.Name, pkg.LatestVersion),
		CreatedAt:   time.Now(),
	}
}

func (a *DependencyAnalyzer) analyzeNodeModules() ([]report.Issue, error) {
	var issues []report.Issue

	// Simple check for known vulnerable packages in package.json
	packageJsonPath := filepath.Join(a.repoPath, packageJson)
	file, err := os.Open(packageJsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open package.json: %w", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("failed to close package.json file: %v\n", err)
		}
	}(file)

	var packageData map[string]interface{}
	if err := json.NewDecoder(file).Decode(&packageData); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Check dependencies
	if deps, ok := packageData["dependencies"].(map[string]interface{}); ok {
		for pkg := range deps {
			if a.isBlockedPackage(pkg) {
				issue := report.Issue{
					ID:          fmt.Sprintf("blocked-node-dependency-%s", strings.ReplaceAll(pkg, "/", "-")),
					Title:       "Blocked Node.js dependency",
					Description: fmt.Sprintf("Package %s is in the blocked list and should not be used", pkg),
					Category:    report.CategorySecurity,
					Severity:    report.SeverityHigh,
					File:        packageJson,
					Rule:        "blocked-dependencies",
					Fix:         fmt.Sprintf("Remove %s from dependencies and find an alternative", pkg),
					CreatedAt:   time.Now(),
				}
				issues = append(issues, issue)
			}
		}
	}

	return issues, nil
}

func (a *DependencyAnalyzer) parseGoModules(output []byte) ([]PackageInfo, error) {
	var packages []PackageInfo

	// Use a JSON decoder to handle multiple JSON objects
	decoder := json.NewDecoder(strings.NewReader(string(output)))

	for decoder.More() {
		var currentModule GoModInfo
		if err := decoder.Decode(&currentModule); err != nil {
			continue // Skip malformed JSON
		}

		pkg := PackageInfo{
			Name:           currentModule.Path,
			CurrentVersion: currentModule.Version,
		}

		// Check if there's an update available
		if currentModule.Update.Version != "" {
			pkg.LatestVersion = currentModule.Update.Version
			// Calculate how old the current version is
			pkg.DaysOld = a.calculateDaysOld(currentModule.Time)
			// If age calculation failed but there's an update available,
			// mark it as outdated (assume the current version is old enough)
			if pkg.DaysOld == 0 && pkg.LatestVersion != pkg.CurrentVersion {
				pkg.DaysOld = a.config.MaxDaysOutdated + 1 // Mark as outdated
			}
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}

func (a *DependencyAnalyzer) calculateDaysOld(currentTime string) int {
	if currentTime == "" {
		return 0
	}

	current, err := time.Parse(time.RFC3339, currentTime)
	if err != nil {
		return 0
	}

	// Calculate days between current version time and now
	// This gives us how old the current version is
	now := time.Now()
	return int(now.Sub(current).Hours() / 24)
}

func (a *DependencyAnalyzer) getModuleName() string {
	goModPath := filepath.Join(a.repoPath, goMod)
	file, err := os.Open(goModPath)
	if err != nil {
		return ""
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(failedToCloseGoModError, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimPrefix(line, "module ")
		}
	}

	return ""
}

func (a *DependencyAnalyzer) isBlockedPackage(name string) bool {
	for _, blocked := range a.config.BlockedPackages {
		if name == blocked || strings.Contains(name, blocked) {
			return true
		}
	}
	return false
}

func (a *DependencyAnalyzer) determineOutdatedSeverity(daysOld int) report.Severity {
	switch {
	case daysOld > 365: // More than a year
		return report.SeverityHigh
	case daysOld > 180: // More than 6 months
		return report.SeverityMedium
	default:
		return report.SeverityLow
	}
}

func (a *DependencyAnalyzer) analyzeUnusedGoModules() ([]report.Issue, error) {
	var issues []report.Issue

	// Get all dependencies from go.mod
	dependencies, err := a.getGoModDependencies()
	if err != nil {
		return nil, fmt.Errorf("failed to get go.mod dependencies: %w", err)
	}

	// Get all imports from Go source files
	imports, err := a.getGoImports()
	if err != nil {
		return nil, fmt.Errorf("failed to get Go imports: %w", err)
	}

	// Find unused dependencies
	for _, dep := range dependencies {
		if !a.isImportUsed(dep, imports) && !a.isStandardLibrary(dep) && !a.isIndirectDependency(dep) {
			issue := report.Issue{
				ID:          fmt.Sprintf("unused-dependency-%s", strings.ReplaceAll(dep, "/", "-")),
				Title:       "Unused dependency",
				Description: fmt.Sprintf("Package %s is declared in go.mod but not imported in any Go files", dep),
				Category:    report.CategoryDependencies,
				Severity:    report.SeverityLow,
				File:        goMod,
				Rule:        "unused-dependencies",
				Fix:         fmt.Sprintf("Remove %s from go.mod with: go mod tidy", dep),
				CreatedAt:   time.Now(),
			}
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

func (a *DependencyAnalyzer) getGoModDependencies() ([]string, error) {
	goModPath := filepath.Join(a.repoPath, goMod)
	file, err := os.Open(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open go.mod: %w", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(failedToCloseGoModError, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	parser := &goModParser{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parser.parseLine(line, a)
	}

	return parser.dependencies, scanner.Err()
}

type goModParser struct {
	dependencies   []string
	inRequireBlock bool
}

func (p *goModParser) parseLine(line string, analyzer *DependencyAnalyzer) {
	if strings.HasPrefix(line, "require") {
		p.handleRequireLine(line, analyzer)
		return
	}

	if p.inRequireBlock {
		p.handleRequireBlockLine(line, analyzer)
	}
}

func (p *goModParser) handleRequireLine(line string, analyzer *DependencyAnalyzer) {
	if strings.Contains(line, "(") {
		p.inRequireBlock = true
		// Handle single line require if it contains a package name
		if !strings.HasSuffix(line, "(") {
			p.addDependencyFromLine(strings.TrimPrefix(line, "require"), analyzer)
		}
	} else {
		// Single line require
		p.addDependencyFromLine(strings.TrimPrefix(line, "require"), analyzer)
	}
}

func (p *goModParser) handleRequireBlockLine(line string, analyzer *DependencyAnalyzer) {
	if strings.Contains(line, ")") {
		p.inRequireBlock = false
		return
	}
	p.addDependencyFromLine(line, analyzer)
}

func (p *goModParser) addDependencyFromLine(line string, analyzer *DependencyAnalyzer) {
	dep := analyzer.extractDependencyName(line)
	if dep != "" {
		p.dependencies = append(p.dependencies, dep)
	}
}

func (a *DependencyAnalyzer) extractDependencyName(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return ""
	}

	// Remove trailing comments and version info
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ""
	}

	depName := parts[0]

	// Remove parentheses if present
	depName = strings.Trim(depName, "()")

	return depName
}

func (a *DependencyAnalyzer) getGoImports() (map[string]bool, error) {
	imports := make(map[string]bool)

	err := filepath.Walk(a.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !a.shouldProcessFile(path) {
			return nil // Continue walking
		}

		fileImports, err := a.extractImportsFromFile(path)
		if err != nil {
			return nil // Continue even if we can't parse one file
		}

		a.mergeImports(imports, fileImports)
		return nil
	})

	return imports, err
}

func (a *DependencyAnalyzer) shouldProcessFile(path string) bool {
	if !strings.HasSuffix(path, ".go") {
		return false
	}

	if strings.Contains(path, "vendor/") || strings.Contains(path, ".git/") {
		return false
	}

	return true
}

func (a *DependencyAnalyzer) mergeImports(allImports map[string]bool, fileImports map[string]bool) {
	for imp := range fileImports {
		allImports[imp] = true
	}
}

func (a *DependencyAnalyzer) extractImportsFromFile(filePath string) (map[string]bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("failed to close file %s: %v\n", filePath, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	parser := &importParser{imports: make(map[string]bool)}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if parser.shouldStopParsing(line) {
			break
		}

		parser.parseLine(line, a)
	}

	return parser.imports, scanner.Err()
}

type importParser struct {
	imports       map[string]bool
	inImportBlock bool
}

func (p *importParser) shouldStopParsing(line string) bool {
	return !p.inImportBlock &&
		!strings.HasPrefix(line, "package") &&
		!strings.HasPrefix(line, "import") &&
		line != "" &&
		!strings.HasPrefix(line, "//")
}

func (p *importParser) parseLine(line string, analyzer *DependencyAnalyzer) {
	if strings.HasPrefix(line, "import") {
		p.handleImportLine(line, analyzer)
		return
	}

	if p.inImportBlock {
		p.handleImportBlockLine(line, analyzer)
	}
}

func (p *importParser) handleImportLine(line string, analyzer *DependencyAnalyzer) {
	if strings.Contains(line, "(") {
		p.inImportBlock = true
		// Handle single line import if it contains a package name
		if !strings.HasSuffix(line, "(") {
			p.addImportFromLine(strings.TrimPrefix(line, "import"), analyzer)
		}
	} else {
		// Single-line import
		p.addImportFromLine(strings.TrimPrefix(line, "import"), analyzer)
	}
}

func (p *importParser) handleImportBlockLine(line string, analyzer *DependencyAnalyzer) {
	if strings.Contains(line, ")") {
		p.inImportBlock = false
		return
	}
	p.addImportFromLine(line, analyzer)
}

func (p *importParser) addImportFromLine(line string, analyzer *DependencyAnalyzer) {
	imp := analyzer.extractImportPath(line)
	if imp != "" {
		p.imports[imp] = true
	}
}

func (a *DependencyAnalyzer) extractImportPath(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return ""
	}

	// Remove alias if present (e.g., "alias 'path'" or "_ 'path'")
	parts := strings.Fields(line)
	var importPath string

	if len(parts) >= 2 {
		// Has alias, take the last part
		importPath = parts[len(parts)-1]
	} else if len(parts) == 1 {
		// No alias
		importPath = parts[0]
	}

	// Remove quotes
	importPath = strings.Trim(importPath, `"'`)

	return importPath
}

func (a *DependencyAnalyzer) isImportUsed(dependency string, imports map[string]bool) bool {
	// Check the exact match
	if imports[dependency] {
		return true
	}

	// Check if any import starts with this dependency (for subpackages)
	for imp := range imports {
		if strings.HasPrefix(imp, dependency+"/") {
			return true
		}
	}

	return false
}

func (a *DependencyAnalyzer) isStandardLibrary(pkg string) bool {
	// Common standard library packages (not exhaustive but covers most cases)
	stdLibs := []string{
		"bufio", "bytes", "context", "crypto", "database", "encoding", "errors", "fmt", "io", "log", "net", "os", "path", "reflect", "regexp", "runtime", "sort", "strconv", "strings", "sync", "syscall", "testing", "time", "unsafe",
	}

	for _, std := range stdLibs {
		if pkg == std || strings.HasPrefix(pkg, std+"/") {
			return true
		}
	}

	// Check if it doesn't contain a dot (standard library packages typically don't have dots)
	return !strings.Contains(pkg, ".")
}

func (a *DependencyAnalyzer) isIndirectDependency(pkg string) bool {
	// Check if the dependency is marked as '// indirect' in go.mod
	goModPath := filepath.Join(a.repoPath, goMod)
	file, err := os.Open(goModPath)
	if err != nil {
		return false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(failedToCloseGoModError, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for lines that contain the package and // indirect comment
		if strings.Contains(line, pkg) && strings.Contains(line, "// indirect") {
			return true
		}
	}

	return false
}

func (a *DependencyAnalyzer) isTransitiveDependency(pkg string) bool {
	// Check if this package is a direct dependency in go.mod
	// If it's not in the main require block, it's a transitive dependency
	directDeps, err := a.getDirectDependencies()
	if err != nil {
		return false
	}

	for _, directDep := range directDeps {
		if directDep == pkg {
			return false // It's a direct dependency
		}
	}

	return true // It's a transitive dependency
}

func (a *DependencyAnalyzer) getDirectDependencies() ([]string, error) {
	file, err := a.openGoModFile()
	if err != nil {
		return nil, err
	}
	defer a.closeGoModFile(file)

	return a.parseDirectDependencies(file)
}

func (a *DependencyAnalyzer) openGoModFile() (*os.File, error) {
	goModPath := filepath.Join(a.repoPath, goMod)
	file, err := os.Open(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open go.mod: %w", err)
	}
	return file, nil
}

func (a *DependencyAnalyzer) closeGoModFile(file *os.File) {
	err := file.Close()
	if err != nil {
		fmt.Printf(failedToCloseGoModError, err)
	}
}

func (a *DependencyAnalyzer) parseDirectDependencies(file *os.File) ([]string, error) {
	var directDeps []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if a.isStartOfMainRequireBlock(line) {
			deps, err := a.extractDependenciesFromRequireBlock(scanner)
			if err != nil {
				return nil, err
			}
			directDeps = append(directDeps, deps...)
			break
		}
	}

	return directDeps, scanner.Err()
}

func (a *DependencyAnalyzer) isStartOfMainRequireBlock(line string) bool {
	return strings.HasPrefix(line, "require (")
}

func (a *DependencyAnalyzer) extractDependenciesFromRequireBlock(scanner *bufio.Scanner) ([]string, error) {
	var deps []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if a.isEndOfRequireBlock(line) {
			break
		}

		if dep := a.extractValidDependency(line); dep != "" {
			deps = append(deps, dep)
		}
	}

	return deps, nil
}

func (a *DependencyAnalyzer) isEndOfRequireBlock(line string) bool {
	return strings.Contains(line, ")")
}

func (a *DependencyAnalyzer) extractValidDependency(line string) string {
	if a.isValidDependencyLine(line) {
		return a.extractDependencyName(line)
	}
	return ""
}

func (a *DependencyAnalyzer) isValidDependencyLine(line string) bool {
	return line != "" && !strings.HasPrefix(line, "//")
}
