package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/githealthchecker/git-health-checker/internal/analyzer"
	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/git"
	"github.com/githealthchecker/git-health-checker/internal/report"
)

var (
	dryRun bool
)

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Automatically fix dependency issues",
	Long: `Automatically fix dependency issues in your repository.

This command will:
- Remove unused dependencies with 'go mod tidy'
- Update outdated dependencies to their latest versions
- Show what would be fixed with --dry-run

Examples:
  githealthchecker fix                   # Fix all dependency issues in current directory
  githealthchecker fix /path/to/repo     # Fix issues in specific directory
  githealthchecker fix --dry-run         # Show what would be fixed without making changes`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFix,
}

func init() {
	rootCmd.AddCommand(fixCmd)

	fixCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be fixed without making changes")
}

func runFix(cmd *cobra.Command, args []string) error {
	fixContext, err := setupFixContext(cmd, args)
	if err != nil {
		return err
	}

	printFixHeader(fixContext.absPath, dryRun)

	totalFixed, didFix, err := performFixes(fixContext)
	if err != nil {
		return err
	}

	err = printFixSummary(totalFixed, didFix, dryRun, fixContext.absPath)
	return err
}

type fixContext struct {
	absPath string
	repo    *git.Repository
	cfg     *config.Config
}

func setupFixContext(cmd *cobra.Command, args []string) (*fixContext, error) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	if !git.IsGitRepository(absPath) {
		return nil, fmt.Errorf("path %s is not a Git repository", absPath)
	}

	repo, err := git.OpenRepository(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Git repository: %w", err)
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return &fixContext{
		absPath: absPath,
		repo:    repo,
		cfg:     cfg,
	}, nil
}

func printFixHeader(absPath string, isDryRun bool) {
	fmt.Printf("🔧 Fixing dependency issues in: %s\n", absPath)
	if isDryRun {
		fmt.Println("🔍 DRY RUN MODE - No changes will be made")
	}
	fmt.Println()
}

func performFixes(ctx *fixContext) (int, bool, error) {
	var totalFixed int

	// Fix unused dependencies
	fixed, err := fixUnusedDependencies(ctx.repo, ctx.cfg, dryRun)
	if err != nil {
		return 0, false, fmt.Errorf("failed to fix unused dependencies: %w", err)
	}
	totalFixed += fixed

	// Fix outdated dependencies
	fixed, err = fixOutdatedDependencies(ctx.repo, ctx.cfg, dryRun)
	if err != nil {
		return 0, false, fmt.Errorf("failed to fix outdated dependencies: %w", err)
	}
	totalFixed += fixed

	var runGoModTidy bool
	if totalFixed == 0 {
		runGoModTidy = true
	}

	return totalFixed, runGoModTidy, nil
}

func printFixSummary(totalFixed int, didFix, isDryRun bool, repoPath string) error {
	fmt.Println()
	if isDryRun {
		fmt.Printf("✨ Would fix %d dependency issues\n", totalFixed)
		fmt.Println("Run without --dry-run to apply the fixes")
		if totalFixed > 0 {
			fmt.Println("💡 Will run 'go mod tidy' after applying fixes")
		}
		if !didFix {
			fmt.Println("✅ No dependency issues found to fix")
		}
	} else {
		fmt.Printf("✅ Fixed %d dependency issues successfully!\n", totalFixed)
		if totalFixed > 0 {
			fmt.Println()
			fmt.Println("🧹 Running final cleanup...")
			if err := runFinalGoModTidy(repoPath); err != nil {
				return fmt.Errorf("failed to run final 'go mod tidy': %w", err)
			}
			fmt.Println("✅ All dependency fixes completed successfully!")
			fmt.Println("💡 Please test your application to ensure everything works correctly")
		}
	}
	return nil
}

func runFinalGoModTidy(repoPath string) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = repoPath

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run 'go mod tidy': %w\nOutput: %s", err, string(output))
	}

	fmt.Println("  ✅ Ran final 'go mod tidy' to clean up go.mod and go.sum")
	return nil
}

func fixUnusedDependencies(repo *git.Repository, cfg *config.Config, dryRun bool) (int, error) {
	fmt.Println("🧹 Checking for unused dependencies...")

	unusedIssues, err := getUnusedDependencyIssues(repo, cfg)
	if err != nil {
		return 0, err
	}

	if len(unusedIssues) == 0 {
		fmt.Println("  ✅ No unused dependencies found")
		return 0, nil
	}

	printUnusedDependencies(unusedIssues, dryRun)

	if !dryRun {
		if err := runGoModTidy(repo.GetPath()); err != nil {
			return 0, err
		}
	}

	return len(unusedIssues), nil
}

func getUnusedDependencyIssues(repo *git.Repository, cfg *config.Config) ([]report.Issue, error) {
	dependencyAnalyzer := analyzer.NewDependencyAnalyzer(&cfg.Dependencies, repo.GetPath())

	issues, err := dependencyAnalyzer.Analyze()
	if err != nil {
		return nil, fmt.Errorf("failed to analyze dependencies: %w", err)
	}

	var unusedIssues []report.Issue
	for _, issue := range issues {
		if issue.Rule == "unused-dependencies" {
			unusedIssues = append(unusedIssues, issue)
		}
	}

	return unusedIssues, nil
}

func printUnusedDependencies(unusedIssues []report.Issue, dryRun bool) {
	fmt.Printf("  📦 Found %d unused dependencies\n", len(unusedIssues))
	for _, issue := range unusedIssues {
		packageName := extractPackageNameFromDescription(issue.Description)
		if dryRun {
			fmt.Printf("    ℹ️  Would remove: %s\n", packageName)
		} else {
			fmt.Printf("    🗑️  Removing: %s\n", packageName)
		}
	}
}

func runGoModTidy(repoPath string) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = repoPath

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run 'go mod tidy': %w\nOutput: %s", err, string(output))
	}

	fmt.Println("  ✅ Ran 'go mod tidy' successfully")
	return nil
}

func fixOutdatedDependencies(repo *git.Repository, cfg *config.Config, dryRun bool) (int, error) {
	fmt.Println("📈 Checking for outdated dependencies...")

	outdatedIssues, err := getOutdatedDependencyIssues(repo, cfg)
	if err != nil {
		return 0, err
	}

	if len(outdatedIssues) == 0 {
		fmt.Println("  ✅ No outdated dependencies found")
		return 0, nil
	}

	fmt.Printf("  📦 Found %d outdated dependencies\n", len(outdatedIssues))

	if dryRun {
		return showOutdatedUpdates(outdatedIssues), nil
	}

	fixedCount := updateOutdatedDependencies(outdatedIssues, repo.GetPath())

	if fixedCount > 0 {
		runPostUpdateCleanup(repo.GetPath())
	}

	return fixedCount, nil
}

func getOutdatedDependencyIssues(repo *git.Repository, cfg *config.Config) ([]report.Issue, error) {
	dependencyAnalyzer := analyzer.NewDependencyAnalyzer(&cfg.Dependencies, repo.GetPath())

	issues, err := dependencyAnalyzer.Analyze()
	if err != nil {
		return nil, fmt.Errorf("failed to analyze dependencies: %w", err)
	}

	var outdatedIssues []report.Issue
	for _, issue := range issues {
		if issue.Rule == "outdated-dependencies" {
			outdatedIssues = append(outdatedIssues, issue)
		}
	}

	return outdatedIssues, nil
}

func showOutdatedUpdates(outdatedIssues []report.Issue) int {
	for _, issue := range outdatedIssues {
		packageName := extractPackageNameFromDescription(issue.Description)
		latestVersion := extractLatestVersionFromDescription(issue.Description)
		fmt.Printf("    ℹ️  Would update: %s to %s\n", packageName, latestVersion)
	}
	return len(outdatedIssues)
}

func updateOutdatedDependencies(outdatedIssues []report.Issue, repoPath string) int {
	var fixedCount int
	for _, issue := range outdatedIssues {
		packageName := extractPackageNameFromDescription(issue.Description)
		latestVersion := extractLatestVersionFromDescription(issue.Description)

		fmt.Printf("    ⬆️  Updating: %s to %s\n", packageName, latestVersion)

		if updateSinglePackage(packageName, latestVersion, repoPath) {
			fixedCount++
		}
	}
	return fixedCount
}

func updateSinglePackage(packageName, latestVersion, repoPath string) bool {
	updateCmd := fmt.Sprintf("%s@%s", packageName, latestVersion)
	cmd := exec.Command("go", "get", updateCmd)
	cmd.Dir = repoPath

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("    ❌ Failed to update %s: %v\n", packageName, err)
		fmt.Printf("       Output: %s\n", string(output))
		return false
	}

	return true
}

func runPostUpdateCleanup(repoPath string) {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = repoPath

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("⚠️  Warning: 'go mod tidy' after updates failed: %v\n", err)
		fmt.Printf("   Output: %s\n", string(output))
	} else {
		fmt.Println("  ✅ Ran 'go mod tidy' after updates")
	}
}

func extractPackageNameFromDescription(description string) string {
	// Extract package name from description like "Package github.com/spf13/cobra is declared..."
	if strings.Contains(description, "Package ") {
		parts := strings.Split(description, " ")
		for i, part := range parts {
			if part == "Package" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return "unknown"
}

func extractLatestVersionFromDescription(description string) string {
	// Extract latest version from description like "...latest: v1.2.3)"
	if strings.Contains(description, "latest: ") {
		parts := strings.Split(description, "latest: ")
		if len(parts) > 1 {
			version := strings.TrimSuffix(parts[1], ")")
			return strings.TrimSpace(version)
		}
	}
	return "latest"
}
