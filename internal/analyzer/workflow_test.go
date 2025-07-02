package analyzer

import (
	"testing"

	"github.com/githealthchecker/git-health-checker/internal/config"
	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Mock repository for testing
type mockRepository struct {
	branches      []string
	currentBranch string
	commits       []*object.Commit
}

func (m *mockRepository) GetBranches() ([]string, error) {
	return m.branches, nil
}

func (m *mockRepository) GetCurrentBranch() (string, error) {
	return m.currentBranch, nil
}

func (m *mockRepository) GetCommitHistory(count int) ([]*object.Commit, error) {
	if count > len(m.commits) {
		return m.commits, nil
	}
	return m.commits[:count], nil
}

func (m *mockRepository) GetPath() string                   { return "/mock/path" }
func (m *mockRepository) GetCurrentCommit() (string, error) { return "abc123", nil }
func (m *mockRepository) GetLargeFiles() ([]string, error)  { return nil, nil }

func TestWorkflowAnalyzer_Analyze(t *testing.T) {
	// Create a mock repository with test data
	hash1 := plumbing.NewHash("1234567890abcdef1234567890abcdef12345678")
	hash2 := plumbing.NewHash("abcdef1234567890abcdef1234567890abcdef12")
	hash3 := plumbing.NewHash("fedcba0987654321fedcba0987654321fedcba09")

	mockRepo := &mockRepository{
		branches:      []string{"main", "feature/test", "hotfix/urgent", "old-branch"},
		currentBranch: "main",
		commits: []*object.Commit{
			{
				Hash:    hash1,
				Message: "feat: add new feature",
			},
			{
				Hash:    hash2,
				Message: "This is a very long commit message that exceeds the maximum allowed length for conventional commits and should be flagged",
			},
			{
				Hash:    hash3,
				Message: "updated some stuff", // Non-conventional format
			},
		},
	}

	// Create a workflow config
	cfg := &config.WorkflowConfig{
		RequireConventionalCommits: true,
		MaxCommitMessageLength:     72,
		ProtectedBranches:          []string{"main", "master"},
	}

	// Create analyzer with mock repo using the test constructor
	workflowAnalyzer := NewWorkflowAnalyzerWithRepo(cfg, mockRepo)

	// Run analysis
	issues, err := workflowAnalyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Should find issues for stale branches and commit messages
	if len(issues) == 0 {
		t.Error("Expected to find workflow issues, but none were found")
	}

	// Check that all issues are workflow category
	staleBranchIssues := 0
	commitMessageIssues := 0

	for _, issue := range issues {
		if issue.Category != report.CategoryWorkflow {
			t.Errorf("Expected workflow category, got %s", issue.Category)
		}

		switch issue.Rule {
		case "stale-branch-check":
			staleBranchIssues++
		case "max-commit-message-length", "conventional-commits":
			commitMessageIssues++
		}
	}

	// Should find stale branch issues (excluding protected main branch)
	if staleBranchIssues == 0 {
		t.Error("Expected to find stale branch issues")
	}

	// Should find commit message issues if conventional commits are required
	if commitMessageIssues == 0 {
		t.Error("Expected to find commit message issues")
	}
}

func TestWorkflowAnalyzer_CheckStaleBranches(t *testing.T) {
	mockRepo := &mockRepository{
		branches:      []string{"main", "feature/old", "hotfix/urgent"},
		currentBranch: "main",
	}

	cfg := &config.WorkflowConfig{
		ProtectedBranches: []string{"main", "master"},
	}

	workflowAnalyzer := NewWorkflowAnalyzerWithRepo(cfg, mockRepo)

	issues, err := workflowAnalyzer.checkStaleBranches()
	if err != nil {
		t.Fatalf("checkStaleBranches failed: %v", err)
	}

	// Should find 2 stale branches (excluding protected main)
	expectedStale := 2
	if len(issues) != expectedStale {
		t.Errorf("Expected %d stale branch issues, got %d", expectedStale, len(issues))
	}

	// Verify issue properties
	for _, issue := range issues {
		if issue.Rule != "stale-branch-check" {
			t.Errorf("Expected rule 'stale-branch-check', got '%s'", issue.Rule)
		}
		if issue.Severity != report.SeverityLow {
			t.Errorf("Expected low severity, got %s", issue.Severity)
		}
	}
}

func TestWorkflowAnalyzer_CheckCommitMessages(t *testing.T) {
	tests := []struct {
		name                       string
		requireConventionalCommits bool
		maxLength                  int
		commits                    []*object.Commit
		expectedIssues             int
	}{
		{
			name:                       "conventional commits disabled",
			requireConventionalCommits: false,
			maxLength:                  72,
			commits: []*object.Commit{
				{Message: "some random commit message"},
			},
			expectedIssues: 0,
		},
		{
			name:                       "valid conventional commits",
			requireConventionalCommits: true,
			maxLength:                  72,
			commits: []*object.Commit{
				{Message: "feat: add new feature"},
				{Message: "fix(auth): resolve login issue"},
				{Message: "docs: update README"},
			},
			expectedIssues: 0,
		},
		{
			name:                       "invalid conventional commits",
			requireConventionalCommits: true,
			maxLength:                  72,
			commits: []*object.Commit{
				{Message: "add new feature"}, // Missing type
				{Message: "updated stuff"},   // Non-conventional
			},
			expectedIssues: 2,
		},
		{
			name:                       "long commit messages",
			requireConventionalCommits: true,
			maxLength:                  50,
			commits: []*object.Commit{
				{Message: "feat: add a very long feature description that exceeds the maximum allowed length"},
			},
			expectedIssues: 1, // One for length
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockRepo := &mockRepository{
				commits: test.commits,
			}

			cfg := &config.WorkflowConfig{
				RequireConventionalCommits: test.requireConventionalCommits,
				MaxCommitMessageLength:     test.maxLength,
			}

			workflowAnalyzer := NewWorkflowAnalyzerWithRepo(cfg, mockRepo)

			issues, err := workflowAnalyzer.checkCommitMessages()
			if err != nil {
				t.Fatalf("checkCommitMessages failed: %v", err)
			}

			if len(issues) != test.expectedIssues {
				t.Errorf("Expected %d issues, got %d", test.expectedIssues, len(issues))
			}
		})
	}
}

func TestWorkflowAnalyzer_IsProtectedBranch(t *testing.T) {
	cfg := &config.WorkflowConfig{
		ProtectedBranches: []string{"main", "master", "develop"},
	}

	analyzer := &WorkflowAnalyzer{config: cfg}

	tests := []struct {
		branch   string
		expected bool
	}{
		{"main", true},
		{"master", true},
		{"develop", true},
		{"feature/test", false},
		{"hotfix/urgent", false},
		{"", false},
	}

	for _, test := range tests {
		result := analyzer.isProtectedBranch(test.branch)
		if result != test.expected {
			t.Errorf("For branch '%s', expected %v, got %v",
				test.branch, test.expected, result)
		}
	}
}

func TestTruncateMessage(t *testing.T) {
	tests := []struct {
		message  string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a longer message", 10, "this is..."},
		{"exact length", 12, "exact length"},
		{"", 5, ""},
	}

	for _, test := range tests {
		result := truncateMessage(test.message, test.maxLen)
		if result != test.expected {
			t.Errorf("For message '%s' with maxLen %d, expected '%s', got '%s'",
				test.message, test.maxLen, test.expected, result)
		}
	}
}
