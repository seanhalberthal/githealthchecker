package analyzer

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/git"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// WorkflowRepository interface for testing
type WorkflowRepository interface {
	GetBranches() ([]string, error)
	GetCurrentBranch() (string, error)
	GetCommitHistory(count int) ([]*object.Commit, error)
}

type WorkflowAnalyzer struct {
	config *config.WorkflowConfig
	repo   WorkflowRepository
}

func NewWorkflowAnalyzer(cfg *config.WorkflowConfig, repository *git.Repository) *WorkflowAnalyzer {
	return &WorkflowAnalyzer{
		config: cfg,
		repo:   repository,
	}
}

// NewWorkflowAnalyzerWithRepo creates a WorkflowAnalyzer with a custom repository interface (for testing)
func NewWorkflowAnalyzerWithRepo(cfg *config.WorkflowConfig, repository WorkflowRepository) *WorkflowAnalyzer {
	return &WorkflowAnalyzer{
		config: cfg,
		repo:   repository,
	}
}

func (a *WorkflowAnalyzer) Analyze() ([]report.Issue, error) {
	var issues []report.Issue

	branchIssues, err := a.checkStaleBranches()
	if err != nil {
		return nil, fmt.Errorf("failed to check stale branches: %w", err)
	}
	issues = append(issues, branchIssues...)

	commitIssues, err := a.checkCommitMessages()
	if err != nil {
		return nil, fmt.Errorf("failed to check commit messages: %w", err)
	}
	issues = append(issues, commitIssues...)

	return issues, nil
}

func (a *WorkflowAnalyzer) checkStaleBranches() ([]report.Issue, error) {
	var issues []report.Issue

	branches, err := a.repo.GetBranches()
	if err != nil {
		return nil, err
	}

	currentBranch, err := a.repo.GetCurrentBranch()
	if err != nil {
		currentBranch = "unknown"
	}

	for _, branch := range branches {
		if a.isProtectedBranch(branch) || branch == currentBranch {
			continue
		}

		// For now, we'll mark all non-protected branches as potentially stale
		// In a real implementation, we'd check the last commit date
		issue := report.Issue{
			ID:          fmt.Sprintf("stale-branch-%s", strings.ReplaceAll(branch, "/", "-")),
			Title:       "Potentially stale branch detected",
			Description: fmt.Sprintf("Branch '%s' may be stale and could be cleaned up", branch),
			Category:    report.CategoryWorkflow,
			Severity:    report.SeverityLow,
			Rule:        "stale-branch-check",
			Fix:         fmt.Sprintf("Review branch '%s' and delete if no longer needed", branch),
			CreatedAt:   time.Now(),
		}
		issues = append(issues, issue)
	}

	return issues, nil
}

func (a *WorkflowAnalyzer) checkCommitMessages() ([]report.Issue, error) {
	var issues []report.Issue

	if !a.config.RequireConventionalCommits {
		return issues, nil
	}

	commits, err := a.repo.GetCommitHistory(10) // Check the last 10 commits
	if err != nil {
		return nil, err
	}

	conventionalCommitPattern := regexp.MustCompile(`^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .+`)

	for _, commit := range commits {
		message := strings.Split(commit.Message, "\n")[0] // Get the first line only

		if len(message) > a.config.MaxCommitMessageLength {
			issue := report.Issue{
				ID:          fmt.Sprintf("long-commit-message-%s", commit.Hash.String()[:8]),
				Title:       "Commit message too long",
				Description: fmt.Sprintf("Commit message is %d characters, exceeding maximum of %d", len(message), a.config.MaxCommitMessageLength),
				Category:    report.CategoryWorkflow,
				Severity:    report.SeverityLow,
				Rule:        "max-commit-message-length",
				Fix:         "Keep commit messages concise and under the character limit",
				CreatedAt:   time.Now(),
			}
			issues = append(issues, issue)
		}

		if !conventionalCommitPattern.MatchString(message) {
			issue := report.Issue{
				ID:          fmt.Sprintf("non-conventional-commit-%s", commit.Hash.String()[:8]),
				Title:       "Non-conventional commit message",
				Description: fmt.Sprintf("Commit message '%s' does not follow conventional commit format", truncateMessage(message, 50)),
				Category:    report.CategoryWorkflow,
				Severity:    report.SeverityLow,
				Rule:        "conventional-commits",
				Fix:         "Use conventional commit format: type(scope): description",
				CreatedAt:   time.Now(),
			}
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

func (a *WorkflowAnalyzer) isProtectedBranch(branch string) bool {
	for _, protected := range a.config.ProtectedBranches {
		if branch == protected {
			return true
		}
	}
	return false
}

func truncateMessage(message string, maxLen int) string {
	if len(message) <= maxLen {
		return message
	}
	return message[:maxLen-3] + "..."
}
