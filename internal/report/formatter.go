package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

type langStat struct {
	name    string
	lines   int
	percent float64
}

type Formatter interface {
	Format(report *Report) (string, error)
}

type TableFormatter struct {
	colorize bool
}

func NewTableFormatter(colorize bool) *TableFormatter {
	return &TableFormatter{colorize: colorize}
}

func (f *TableFormatter) Format(report *Report) (string, error) {
	var output strings.Builder

	if f.colorize {
		color.Set(color.FgCyan, color.Bold)
	}
	output.WriteString(fmt.Sprintf("Git Health Report - %s\n", report.Repository))
	output.WriteString(fmt.Sprintf("Branch: %s | Commit: %s\n", report.Branch, report.CommitHash[:8]))
	output.WriteString(fmt.Sprintf("Scan completed at: %s (took %s)\n\n",
		report.Timestamp.Format("2006-01-02 15:04:05"), report.Duration))

	if f.colorize {
		color.Unset()
	}

	f.writeSummary(&output, &report.Summary)
	f.writeCodeStats(&output, &report.CodeStats)

	if len(report.Issues) > 0 {
		output.WriteString("\nIssues Found:\n")
		f.writeIssuesTable(&output, report.Issues)
	} else {
		output.WriteString("\n")
		if f.colorize {
			color.Set(color.FgGreen, color.Bold)
		}
		output.WriteString("✅ No issues found! Repository is healthy.\n")
		if f.colorize {
			color.Unset()
		}
	}

	return output.String(), nil
}

func (f *TableFormatter) writeSummary(output *strings.Builder, summary *Summary) {
	f.writeSummaryHeader(output)
	f.writeSummaryStats(output, summary)

	if summary.TotalIssues > 0 {
		f.writeSeverityCounts(output, summary)
	}
}

func (f *TableFormatter) writeSummaryHeader(output *strings.Builder) {
	if f.colorize {
		color.Set(color.FgYellow, color.Bold)
	}
	output.WriteString("Summary:\n")
	if f.colorize {
		color.Unset()
	}
}

func (f *TableFormatter) writeSummaryStats(output *strings.Builder, summary *Summary) {
	output.WriteString(fmt.Sprintf("  Total Issues: %d\n", summary.TotalIssues))
	output.WriteString(fmt.Sprintf("  Health Score: %d/100 (Grade: %s)\n", summary.Score, summary.Grade))
}

func (f *TableFormatter) writeSeverityCounts(output *strings.Builder, summary *Summary) {
	for severity, count := range summary.IssuesBySeverity {
		if count > 0 {
			f.writeSeverityCount(output, severity, count)
		}
	}
}

func (f *TableFormatter) writeSeverityCount(output *strings.Builder, severity Severity, count int) {
	severityColor := f.getSeverityColor(severity)
	if f.colorize && severityColor != nil {
		coloredText := severityColor.Sprint(fmt.Sprintf("    %s: %d\n", titleCase(string(severity)), count))
		output.WriteString(coloredText)
	} else {
		output.WriteString(fmt.Sprintf("    %s: %d\n", titleCase(string(severity)), count))
	}
}

func (f *TableFormatter) writeCodeStats(output *strings.Builder, stats *CodeStats) {
	if stats.TotalLines == 0 {
		return // Skip if no code stats available
	}

	output.WriteString("\n")
	if f.colorize {
		color.Set(color.FgCyan, color.Bold)
	}
	output.WriteString("Code Statistics:\n")
	if f.colorize {
		color.Unset()
	}

	output.WriteString(fmt.Sprintf("  Total Lines: %s\n", formatNumber(stats.TotalLines)))
	output.WriteString(fmt.Sprintf("  Total Files: %s\n", formatNumber(stats.TotalFiles)))

	if len(stats.LanguageBreakdown) > 0 {
		output.WriteString("  Languages:\n")
		f.writeLanguageBreakdown(output, stats)
	}
}

func (f *TableFormatter) writeLanguageBreakdown(output *strings.Builder, stats *CodeStats) {
	// Sort languages by percentage (descending)
	var languages []langStat
	for lang, lines := range stats.LanguageBreakdown {
		percent := stats.LanguagePercent[lang]
		languages = append(languages, langStat{
			name:    lang,
			lines:   lines,
			percent: percent,
		})
	}

	// Simple bubble sort by percentage (descending)
	for i := 0; i < len(languages); i++ {
		for j := 0; j < len(languages)-1-i; j++ {
			if languages[j].percent < languages[j+1].percent {
				languages[j], languages[j+1] = languages[j+1], languages[j]
			}
		}
	}

	// Display top languages (limit to top 8 for readability)
	maxDisplay := 8
	if len(languages) < maxDisplay {
		maxDisplay = len(languages)
	}

	for i := 0; i < maxDisplay; i++ {
		lang := languages[i]
		output.WriteString(fmt.Sprintf("    %s: %s lines (%.1f%%)\n",
			lang.name, formatNumber(lang.lines), lang.percent))
	}

	if len(languages) > maxDisplay {
		others := len(languages) - maxDisplay
		output.WriteString(fmt.Sprintf("    ... and %d more\n", others))
	}
}

func (f *TableFormatter) writeIssuesTable(output *strings.Builder, issues []Issue) {
	for i, issue := range issues {
		if i > 0 {
			output.WriteString("\n")
		}

		// Format severity with color
		severity := strings.ToUpper(string(issue.Severity))
		if f.colorize {
			severityColor := f.getSeverityColor(issue.Severity)
			if severityColor != nil {
				severity = severityColor.Sprint(severity)
			}
		}

		// Format file location
		file := issue.File
		if issue.Line > 0 {
			file = fmt.Sprintf("%s:%d", file, issue.Line)
		}

		// Write issue in a readable format
		output.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", severity, file, issue.Category))
		output.WriteString(fmt.Sprintf("    Issue: %s\n", issue.Description))
		output.WriteString(fmt.Sprintf("    Fix:   %s\n", issue.Fix))
	}
}

func (f *TableFormatter) getSeverityColor(severity Severity) *color.Color {
	switch severity {
	case SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case SeverityHigh:
		return color.New(color.FgRed)
	case SeverityMedium:
		return color.New(color.FgYellow)
	case SeverityLow:
		return color.New(color.FgBlue)
	default:
		return nil
	}
}

func (f *TableFormatter) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (f *JSONFormatter) Format(report *Report) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to JSON: %w", err)
	}
	return string(data), nil
}

type MarkdownFormatter struct{}

func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

func (f *MarkdownFormatter) Format(report *Report) (string, error) {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("# Git Health Report - %s\n\n", report.Repository))
	output.WriteString(fmt.Sprintf("**Branch:** %s | **Commit:** %s\n\n", report.Branch, report.CommitHash[:8]))
	output.WriteString(fmt.Sprintf("**Scan completed:** %s (took %s)\n\n",
		report.Timestamp.Format("2006-01-02 15:04:05"), report.Duration))

	output.WriteString("## Summary\n\n")
	output.WriteString(fmt.Sprintf("- **Total Issues:** %d\n", report.Summary.TotalIssues))
	output.WriteString(fmt.Sprintf("- **Health Score:** %d/100 (Grade: %s)\n\n", report.Summary.Score, report.Summary.Grade))

	f.writeCodeStatsMarkdown(&output, &report.CodeStats)

	if report.Summary.TotalIssues > 0 {
		output.WriteString("### Issues by Severity\n\n")
		for severity, count := range report.Summary.IssuesBySeverity {
			if count > 0 {
				output.WriteString(fmt.Sprintf("- **%s:** %d\n", titleCase(string(severity)), count))
			}
		}
		output.WriteString("\n")
	}

	if len(report.Issues) > 0 {
		output.WriteString("## Issues Found\n\n")
		f.writeIssuesMarkdown(&output, report.Issues)
	} else {
		output.WriteString("## ✅ No Issues Found\n\nRepository is healthy!\n")
	}

	return output.String(), nil
}

func (f *MarkdownFormatter) writeIssuesMarkdown(output *strings.Builder, issues []Issue) {
	categorizedIssues := make(map[Category][]Issue)
	for _, issue := range issues {
		categorizedIssues[issue.Category] = append(categorizedIssues[issue.Category], issue)
	}

	for category, categoryIssues := range categorizedIssues {
		output.WriteString(fmt.Sprintf("### %s Issues\n\n", titleCase(string(category))))

		for _, issue := range categoryIssues {
			severityBadge := f.getSeverityBadge(issue.Severity)
			output.WriteString(fmt.Sprintf("#### %s %s\n\n", severityBadge, issue.Title))
			output.WriteString(fmt.Sprintf("**Description:** %s\n\n", issue.Description))

			if issue.File != "" {
				fileLocation := issue.File
				if issue.Line > 0 {
					fileLocation = fmt.Sprintf("%s:%d", issue.File, issue.Line)
				}
				output.WriteString(fmt.Sprintf("**Location:** `%s`\n\n", fileLocation))
			}

			if issue.Fix != "" {
				output.WriteString(fmt.Sprintf("**Suggested Fix:** %s\n\n", issue.Fix))
			}

			output.WriteString("---\n\n")
		}
	}
}

func (f *MarkdownFormatter) getSeverityBadge(severity Severity) string {
	switch severity {
	case SeverityCritical:
		return "🔴 **CRITICAL**"
	case SeverityHigh:
		return "🟠 **HIGH**"
	case SeverityMedium:
		return "🟡 **MEDIUM**"
	case SeverityLow:
		return "🔵 **LOW**"
	default:
		return "⚪ **UNKNOWN**"
	}
}

func (f *MarkdownFormatter) writeCodeStatsMarkdown(output *strings.Builder, stats *CodeStats) {
	if stats.TotalLines == 0 {
		return
	}

	f.writeMarkdownStatsHeader(output, stats)
	f.writeMarkdownLanguageBreakdown(output, stats)
}

func (f *MarkdownFormatter) writeMarkdownStatsHeader(output *strings.Builder, stats *CodeStats) {
	output.WriteString("## Code Statistics\n\n")
	output.WriteString(fmt.Sprintf("- **Total Lines:** %s\n", formatNumber(stats.TotalLines)))
	output.WriteString(fmt.Sprintf("- **Total Files:** %s\n\n", formatNumber(stats.TotalFiles)))
}

func (f *MarkdownFormatter) writeMarkdownLanguageBreakdown(output *strings.Builder, stats *CodeStats) {
	if len(stats.LanguageBreakdown) == 0 {
		return
	}

	output.WriteString("### Language Breakdown\n\n")

	languages := f.sortLanguagesByPercentage(stats)
	for _, lang := range languages {
		output.WriteString(fmt.Sprintf("- **%s:** %s lines (%.1f%%)\n",
			lang.name, formatNumber(lang.lines), lang.percent))
	}
	output.WriteString("\n")
}

func (f *MarkdownFormatter) sortLanguagesByPercentage(stats *CodeStats) []langStat {
	var languages []langStat
	for lang, lines := range stats.LanguageBreakdown {
		percent := stats.LanguagePercent[lang]
		languages = append(languages, langStat{
			name:    lang,
			lines:   lines,
			percent: percent,
		})
	}

	// Sort by percentage (descending)
	for i := 0; i < len(languages); i++ {
		for j := 0; j < len(languages)-1-i; j++ {
			if languages[j].percent < languages[j+1].percent {
				languages[j], languages[j+1] = languages[j+1], languages[j]
			}
		}
	}

	return languages
}

func GetFormatter(format string) Formatter {
	switch strings.ToLower(format) {
	case "json":
		return NewJSONFormatter()
	case "markdown", "md":
		return NewMarkdownFormatter()
	case "table":
		fallthrough
	default:
		return NewTableFormatter(isTerminal())
	}
}

func titleCase(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return fileInfo.Mode()&os.ModeCharDevice != 0
}

func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}

	str := fmt.Sprintf("%d", n)
	result := ""

	for i, char := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(char)
	}

	return result
}
