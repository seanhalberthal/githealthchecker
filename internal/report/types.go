package report

import "time"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Category string

const (
	CategorySecurity     Category = "security"
	CategoryPerformance  Category = "performance"
	CategoryQuality      Category = "quality"
	CategoryMaintenance  Category = "maintenance"
	CategoryWorkflow     Category = "workflow"
	CategoryDependencies Category = "dependencies"
)

type Issue struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Category    Category  `json:"category"`
	Severity    Severity  `json:"severity"`
	File        string    `json:"file,omitempty"`
	Line        int       `json:"line,omitempty"`
	Column      int       `json:"column,omitempty"`
	Rule        string    `json:"rule,omitempty"`
	Fix         string    `json:"fix,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Summary struct {
	TotalIssues      int              `json:"total_issues"`
	IssuesBySeverity map[Severity]int `json:"issues_by_severity"`
	IssuesByCategory map[Category]int `json:"issues_by_category"`
	Score            int              `json:"score"`
	Grade            string           `json:"grade"`
}

type CodeStats struct {
	TotalLines        int                `json:"total_lines"`
	TotalFiles        int                `json:"total_files"`
	LanguageBreakdown map[string]int     `json:"language_breakdown"`
	LanguagePercent   map[string]float64 `json:"language_percent"`
}

type Report struct {
	Repository string    `json:"repository"`
	Branch     string    `json:"branch"`
	CommitHash string    `json:"commit_hash"`
	Timestamp  time.Time `json:"timestamp"`
	Summary    Summary   `json:"summary"`
	CodeStats  CodeStats `json:"code_stats"`
	Issues     []Issue   `json:"issues"`
	Duration   string    `json:"duration"`
	Version    string    `json:"version"`
}
