package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/analyzer"
	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/git"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/githealthchecker/git-health-checker/internal/scanner"
	"github.com/spf13/cobra"
)

const failedToCreateScannerError = "failed to create file scanner: %w"

var checkCmd = &cobra.Command{
	Use:   "check [path]",
	Short: "Analyze a Git repository for health issues",
	Long: `Analyze a Git repository for common issues, security vulnerabilities, 
and maintenance problems. If no path is provided, the current directory is used.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCheck,
}

var (
	enableSecurity     bool
	enablePerformance  bool
	enableQuality      bool
	enableMaintenance  bool
	enableWorkflow     bool
	enableDependencies bool
	enableGoWarnings   bool
	failOnIssues       bool
	severityThreshold  string
)

func init() {
	rootCmd.AddCommand(checkCmd)

	checkCmd.Flags().BoolVar(&enableSecurity, "security", false, "enable security analysis")
	checkCmd.Flags().BoolVar(&enablePerformance, "performance", false, "enable performance analysis")
	checkCmd.Flags().BoolVar(&enableQuality, "quality", false, "enable code quality analysis")
	checkCmd.Flags().BoolVar(&enableMaintenance, "maintenance", false, "enable maintenance analysis")
	checkCmd.Flags().BoolVar(&enableWorkflow, "workflow", false, "enable workflow analysis")
	checkCmd.Flags().BoolVar(&enableDependencies, "dependencies", false, "enable dependency analysis")
	checkCmd.Flags().BoolVar(&enableGoWarnings, "go-warnings", false, "enable Go compiler warnings analysis")
	checkCmd.Flags().BoolVar(&failOnIssues, "fail-on-issues", false, "exit with non-zero code if issues found")
	checkCmd.Flags().StringVar(&severityThreshold, "severity", "low", "minimum severity level (low, medium, high, critical)")
}

func runCheck(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	context, err := setupCheckContext(cmd, args)
	if err != nil {
		return err
	}

	healthReport, err := performHealthCheck(context, startTime)
	if err != nil {
		return err
	}

	if err := outputResults(cmd, healthReport, context.verbose); err != nil {
		return err
	}

	suggestFixCommand(healthReport)
	handleFailOnIssues(healthReport)
	return nil
}

type checkContext struct {
	absPath string
	repo    *git.Repository
	cfg     *config.Config
	branch  string
	commit  string
	verbose bool
}

func setupCheckContext(cmd *cobra.Command, args []string) (*checkContext, error) {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path %s: %w", targetPath, err)
	}

	if !git.IsGitRepository(absPath) {
		return nil, fmt.Errorf("path %s is not a Git repository", absPath)
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	repo, err := git.OpenRepository(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	branch, err := repo.GetCurrentBranch()
	if err != nil {
		branch = "unknown"
	}

	commit, err := repo.GetCurrentCommit()
	if err != nil {
		commit = "unknown"
	}

	verbose, _ := cmd.Flags().GetBool("verbose")

	return &checkContext{
		absPath: absPath,
		repo:    repo,
		cfg:     cfg,
		branch:  branch,
		commit:  commit,
		verbose: verbose,
	}, nil
}

func performHealthCheck(context *checkContext, startTime time.Time) (*report.Report, error) {
	healthReport := &report.Report{
		Repository: context.absPath,
		Branch:     context.branch,
		CommitHash: context.commit,
		Timestamp:  startTime,
		Issues:     []report.Issue{},
		Duration:   time.Since(startTime).String(),
		Version:    "1.0.0",
	}

	enableAllAnalysisIfNoneSelected()

	if context.verbose {
		fmt.Printf("Analyzing repository: %s\n", context.absPath)
		fmt.Printf("Branch: %s | Commit: %s\n", context.branch, context.commit[:8])
		fmt.Println("Running health checks...")
	}

	if err := runAnalyses(context.repo, context.cfg, healthReport, context.verbose); err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	// Analyze code statistics
	if err := runCodeStatsAnalysis(context.repo, healthReport, context.verbose); err != nil {
		return nil, fmt.Errorf("code stats analysis failed: %w", err)
	}

	healthReport.Duration = time.Since(startTime).String()
	healthReport.Summary = calculateSummary(healthReport.Issues)

	return healthReport, nil
}

func enableAllAnalysisIfNoneSelected() {
	if !anyAnalysisEnabled() {
		enableSecurity = true
		enablePerformance = true
		enableQuality = true
		enableMaintenance = true
		enableWorkflow = true
		enableDependencies = true
		enableGoWarnings = true
	}
}

func outputResults(cmd *cobra.Command, healthReport *report.Report, verbose bool) error {
	formatFlag, _ := cmd.Flags().GetString("format")
	formatter := report.GetFormatter(formatFlag)

	output, err := formatter.Format(healthReport)
	if err != nil {
		return fmt.Errorf("failed to format report: %w", err)
	}

	outputPath, _ := cmd.Flags().GetString("output")
	if outputPath != "" {
		if err := writeOutputToFile(output, outputPath); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if verbose {
			fmt.Printf("Report written to: %s\n", outputPath)
		}
	} else {
		fmt.Print(output)
	}

	return nil
}

func handleFailOnIssues(healthReport *report.Report) {
	if failOnIssues && len(healthReport.Issues) > 0 {
		filteredIssues := filterIssuesBySeverity(healthReport.Issues, severityThreshold)
		if len(filteredIssues) > 0 {
			os.Exit(1)
		}
	}
}

func anyAnalysisEnabled() bool {
	return enableSecurity || enablePerformance || enableQuality || enableMaintenance || enableWorkflow || enableDependencies || enableGoWarnings
}

type analysisRunner struct {
	name    string
	enabled bool
	runner  func() error
}

func (a *analysisRunner) execute(verbose bool) error {
	if !a.enabled {
		return nil
	}

	if verbose {
		fmt.Printf("  - Running %s analysis...\n", a.name)
	}

	if a.runner != nil {
		if err := a.runner(); err != nil {
			return fmt.Errorf("%s analysis failed: %w", a.name, err)
		}
	}

	return nil
}

func runAnalyses(repo *git.Repository, cfg *config.Config, healthReport *report.Report, verbose bool) error {
	analyses := []analysisRunner{
		{name: "security", enabled: enableSecurity, runner: func() error {
			return runSecurityAnalysis(repo, cfg, healthReport)
		}},
		{name: "performance", enabled: enablePerformance, runner: func() error {
			return runPerformanceAnalysis(repo, cfg, healthReport)
		}},
		{name: "quality", enabled: enableQuality, runner: func() error {
			return runQualityAnalysis(repo, cfg, healthReport)
		}},
		{name: "maintenance", enabled: enableMaintenance, runner: func() error {
			return runMaintenanceAnalysis(repo, cfg, healthReport)
		}},
		{name: "workflow", enabled: enableWorkflow, runner: func() error {
			return runWorkflowAnalysis(repo, cfg, healthReport)
		}},
		{name: "dependencies", enabled: enableDependencies, runner: func() error {
			return runDependencyAnalysis(repo, cfg, healthReport)
		}},
		{name: "go-warnings", enabled: enableGoWarnings, runner: func() error {
			return runGoWarningsAnalysis(repo, cfg, healthReport)
		}},
	}

	for _, analysis := range analyses {
		if err := analysis.execute(verbose); err != nil {
			return err
		}
	}

	return nil
}

func runSecurityAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	fileScanner, err := scanner.NewFileScanner(repo.GetPath())
	if err != nil {
		return fmt.Errorf(failedToCreateScannerError, err)
	}

	securityAnalyzer := analyzer.NewSecurityAnalyzer(&cfg.Security, fileScanner)

	issues, err := securityAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("security analysis failed: %w", err)
	}

	healthReport.Issues = append(healthReport.Issues, issues...)
	return nil
}

func runPerformanceAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	largeFiles, err := repo.GetLargeFiles(int64(cfg.Performance.LargeFileSizeMB * 1024 * 1024))
	if err != nil {
		return err
	}

	for _, file := range largeFiles {
		if isBinaryFile(file, cfg.Performance.BinaryExtensions) {
			continue
		}

		issue := report.Issue{
			ID:          fmt.Sprintf("large-file-%s", file),
			Title:       "Large source file detected",
			Description: fmt.Sprintf("Source file %s is larger than %dMB threshold", file, cfg.Performance.LargeFileSizeMB),
			Category:    report.CategoryPerformance,
			Severity:    report.SeverityMedium,
			File:        file,
			Rule:        "large-file-check",
			Fix:         "Consider refactoring large source files or splitting into smaller modules",
			CreatedAt:   time.Now(),
		}
		healthReport.Issues = append(healthReport.Issues, issue)
	}

	return nil
}

func runQualityAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	fileScanner, err := scanner.NewFileScanner(repo.GetPath())
	if err != nil {
		return fmt.Errorf(failedToCreateScannerError, err)
	}

	qualityAnalyzer := analyzer.NewQualityAnalyzer(&cfg.Quality, fileScanner)

	issues, err := qualityAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("quality analysis failed: %w", err)
	}

	healthReport.Issues = append(healthReport.Issues, issues...)
	return nil
}

func runWorkflowAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	workflowAnalyzer := analyzer.NewWorkflowAnalyzer(&cfg.Workflow, repo)

	issues, err := workflowAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("workflow analysis failed: %w", err)
	}

	healthReport.Issues = append(healthReport.Issues, issues...)
	return nil
}

func runDependencyAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	dependencyAnalyzer := analyzer.NewDependencyAnalyzer(&cfg.Dependencies, repo.GetPath())

	issues, err := dependencyAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("dependency analysis failed: %w", err)
	}

	healthReport.Issues = append(healthReport.Issues, issues...)
	return nil
}

func runGoWarningsAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	if !cfg.GoWarnings.Enabled {
		return nil
	}

	goWarningsAnalyzer := analyzer.NewGoWarningsAnalyzer(repo.GetPath())
	issues, err := goWarningsAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("go warnings analysis failed: %w", err)
	}

	// Filter issues based on ignore patterns
	filteredIssues := filterGoWarningsByPatterns(issues, cfg.GoWarnings.IgnorePatterns)
	healthReport.Issues = append(healthReport.Issues, filteredIssues...)
	return nil
}

func filterGoWarningsByPatterns(issues []report.Issue, ignorePatterns []string) []report.Issue {
	if len(ignorePatterns) == 0 {
		return issues
	}

	var filtered []report.Issue
	for _, issue := range issues {
		shouldIgnore := false
		for _, pattern := range ignorePatterns {
			if strings.Contains(issue.File, pattern) {
				shouldIgnore = true
				break
			}
		}
		if !shouldIgnore {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

func runCodeStatsAnalysis(repo *git.Repository, healthReport *report.Report, verbose bool) error {
	if verbose {
		fmt.Println("  - Analyzing code statistics...")
	}

	fileScanner, err := scanner.NewFileScanner(repo.GetPath())
	if err != nil {
		return fmt.Errorf(failedToCreateScannerError, err)
	}

	codeStatsAnalyzer := analyzer.NewCodeStatsAnalyzer(fileScanner)

	stats, err := codeStatsAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("code stats analysis failed: %w", err)
	}

	healthReport.CodeStats = stats
	return nil
}

func runMaintenanceAnalysis(repo *git.Repository, cfg *config.Config, healthReport *report.Report) error {
	repoPath := repo.GetPath()

	for _, requiredFile := range cfg.Maintenance.RequiredFiles {
		filePath := filepath.Join(repoPath, requiredFile)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			severity := report.SeverityLow
			description := fmt.Sprintf("Required file %s is missing from repository", requiredFile)
			fix := fmt.Sprintf("Add %s file to repository root", requiredFile)

			if requiredFile == "go.mod" {
				severity = report.SeverityHigh
				description = "Go module file (go.mod) is missing - this is required for Go projects"
				fix = "Run 'go mod init <module-name>' to initialize Go module"
			} else if requiredFile == ".gitignore" {
				severity = report.SeverityMedium
				description = ".gitignore file is missing - important for excluding build artifacts and sensitive files"
				fix = "Create .gitignore file with appropriate patterns for your programming language"
			}

			issue := report.Issue{
				ID:          fmt.Sprintf("missing-file-%s", strings.ReplaceAll(requiredFile, "/", "-")),
				Title:       "Missing required file",
				Description: description,
				Category:    report.CategoryMaintenance,
				Severity:    severity,
				File:        requiredFile,
				Rule:        "required-files-check",
				Fix:         fix,
				CreatedAt:   time.Now(),
			}
			healthReport.Issues = append(healthReport.Issues, issue)
		}
	}

	return nil
}

func calculateSummary(issues []report.Issue) report.Summary {
	summary := report.Summary{
		TotalIssues:      len(issues),
		IssuesBySeverity: make(map[report.Severity]int),
		IssuesByCategory: make(map[report.Category]int),
	}

	for _, issue := range issues {
		summary.IssuesBySeverity[issue.Severity]++
		summary.IssuesByCategory[issue.Category]++
	}

	summary.Score = calculateHealthScore(summary.IssuesBySeverity)
	summary.Grade = calculateGrade(summary.Score)

	return summary
}

func calculateHealthScore(issuesBySeverity map[report.Severity]int) int {
	score := 100

	score -= issuesBySeverity[report.SeverityCritical] * 25
	score -= issuesBySeverity[report.SeverityHigh] * 15
	score -= issuesBySeverity[report.SeverityMedium] * 8
	score -= issuesBySeverity[report.SeverityLow] * 3

	if score < 0 {
		score = 0
	}

	return score
}

func calculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func filterIssuesBySeverity(issues []report.Issue, threshold string) []report.Issue {
	severityOrder := map[report.Severity]int{
		report.SeverityLow:      1,
		report.SeverityMedium:   2,
		report.SeverityHigh:     3,
		report.SeverityCritical: 4,
	}

	thresholdLevel, exists := severityOrder[report.Severity(threshold)]
	if !exists {
		thresholdLevel = 1
	}

	var filtered []report.Issue
	for _, issue := range issues {
		if severityOrder[issue.Severity] >= thresholdLevel {
			filtered = append(filtered, issue)
		}
	}

	return filtered
}

func isBinaryFile(filePath string, binaryExtensions []string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, binaryExt := range binaryExtensions {
		if ext == strings.ToLower(binaryExt) {
			return true
		}
	}

	fileName := strings.ToLower(filepath.Base(filePath))

	commonBinaries := []string{
		"git-health-checker", "main", "a.out", "*.exe",
	}

	for _, binary := range commonBinaries {
		if fileName == binary || strings.HasSuffix(fileName, binary) {
			return true
		}
	}

	return false
}

func writeOutputToFile(content, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(content), 0644)
}

func suggestFixCommand(healthReport *report.Report) {
	hasDependencyIssues := false

	for _, issue := range healthReport.Issues {
		if issue.Category == report.CategoryDependencies {
			hasDependencyIssues = true
			break
		}
	}

	if hasDependencyIssues {
		fmt.Println("\n💡 Found dependency issues? Run 'githealthchecker fix .' to automatically resolve them.")
	}
}
