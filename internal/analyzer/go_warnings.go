package analyzer

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/githealthchecker/git-health-checker/internal/report"
)

type GoWarningsAnalyzer struct {
	repoPath string
}

func NewGoWarningsAnalyzer(repoPath string) *GoWarningsAnalyzer {
	return &GoWarningsAnalyzer{
		repoPath: repoPath,
	}
}

func (a *GoWarningsAnalyzer) Analyze() ([]report.Issue, error) {
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = a.repoPath
	output, err := cmd.CombinedOutput()

	// go vet returns non-zero when issues found, that's normal
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("go vet failed: %w", err)
	}

	return a.parseOutput(string(output)), nil
}

func (a *GoWarningsAnalyzer) parseOutput(output string) []report.Issue {
	if output == "" {
		return nil
	}

	var issues []report.Issue
	pattern := regexp.MustCompile(`^(.+):(\d+):(\d+):\s*(.+)$`)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := pattern.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}

		file := strings.TrimPrefix(matches[1], "./")
		lineNum := 0
		_, err := fmt.Sscanf(matches[2], "%d", &lineNum)
		if err != nil {
			return nil
		}
		message := matches[4]

		issues = append(issues, report.Issue{
			ID:          fmt.Sprintf("go-vet-%s-%d", strings.ReplaceAll(file, "/", "-"), lineNum),
			Title:       "Go vet warning",
			Description: message,
			Category:    report.CategoryQuality,
			Severity:    a.getSeverity(message),
			File:        file,
			Line:        lineNum,
			Rule:        "go-vet-check",
			Fix:         a.getFix(message),
			CreatedAt:   time.Now(),
		})
	}

	return issues
}

func (a *GoWarningsAnalyzer) getSeverity(message string) report.Severity {
	msg := strings.ToLower(message)
	if strings.Contains(msg, "unused") {
		return report.SeverityLow
	}
	return report.SeverityMedium
}

func (a *GoWarningsAnalyzer) getFix(message string) string {
	msg := strings.ToLower(message)
	if strings.Contains(msg, "unused variable") {
		return "Remove the unused variable"
	}
	if strings.Contains(msg, "unused import") {
		return "Remove the unused import"
	}
	return "Address the go vet warning"
}
