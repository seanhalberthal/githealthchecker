package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/githealthchecker/git-health-checker/internal/report"
	"github.com/githealthchecker/git-health-checker/internal/scanner"
)

type CodeStatsAnalyzer struct {
	fileScanner *scanner.FileScanner
}

func NewCodeStatsAnalyzer(fileScanner *scanner.FileScanner) *CodeStatsAnalyzer {
	return &CodeStatsAnalyzer{
		fileScanner: fileScanner,
	}
}

func (c *CodeStatsAnalyzer) Analyze() (report.CodeStats, error) {
	stats := report.CodeStats{
		TotalLines:        0,
		TotalFiles:        0,
		LanguageBreakdown: make(map[string]int),
		LanguagePercent:   make(map[string]float64),
	}

	files, err := c.fileScanner.ScanFiles()
	if err != nil {
		return stats, err
	}

	c.processFiles(files, &stats)
	c.calculatePercentages(&stats)

	return stats, nil
}

func (c *CodeStatsAnalyzer) processFiles(files []scanner.FileInfo, stats *report.CodeStats) {
	for _, file := range files {
		if c.shouldSkipFile(file.RelativePath) {
			continue
		}

		language := c.detectLanguage(file.RelativePath)
		if language == "" {
			continue
		}

		lineCount := c.getLineCount(file)
		if lineCount > 0 {
			stats.TotalFiles++
			stats.TotalLines += lineCount
			stats.LanguageBreakdown[language] += lineCount
		}
	}
}

func (c *CodeStatsAnalyzer) getLineCount(file scanner.FileInfo) int {
	if file.LineCount > 0 {
		return file.LineCount
	}

	if !file.IsText {
		return 0
	}

	lineCount, err := c.countLinesInFile(file.Path)
	if err != nil {
		return 0
	}

	return lineCount
}

func (c *CodeStatsAnalyzer) calculatePercentages(stats *report.CodeStats) {
	if stats.TotalLines == 0 {
		return
	}

	for language, lineCount := range stats.LanguageBreakdown {
		percentage := float64(lineCount) / float64(stats.TotalLines) * 100
		stats.LanguagePercent[language] = percentage
	}
}

func (c *CodeStatsAnalyzer) shouldSkipFile(filePath string) bool {
	fileName := strings.ToLower(filepath.Base(filePath))

	// Skip hidden files and directories
	if strings.HasPrefix(fileName, ".") {
		return true
	}

	// Skip common directories
	pathParts := strings.Split(filePath, string(filepath.Separator))
	for _, part := range pathParts {
		lowerPart := strings.ToLower(part)
		if lowerPart == "node_modules" || lowerPart == "vendor" ||
			lowerPart == ".git" || lowerPart == "dist" ||
			lowerPart == "build" || lowerPart == "target" {
			return true
		}
	}

	// Skip binary and non-source files
	if c.isBinaryFile(filePath) {
		return true
	}

	return false
}

func (c *CodeStatsAnalyzer) isBinaryFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	binaryExts := []string{
		".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj",
		".jar", ".war", ".ear", ".class",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
		".bin", ".dat", ".db", ".sqlite",
	}

	for _, binaryExt := range binaryExts {
		if ext == binaryExt {
			return true
		}
	}

	return false
}

func (c *CodeStatsAnalyzer) detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	languageMap := map[string]string{
		".go":         "Go",
		".js":         "JavaScript",
		".ts":         "TypeScript",
		".jsx":        "JavaScript",
		".tsx":        "TypeScript",
		".py":         "Python",
		".java":       "Java",
		".c":          "C",
		".cpp":        "C++",
		".cxx":        "C++",
		".cc":         "C++",
		".h":          "C/C++",
		".hpp":        "C++",
		".cs":         "C#",
		".php":        "PHP",
		".rb":         "Ruby",
		".rs":         "Rust",
		".swift":      "Swift",
		".kt":         "Kotlin",
		".scala":      "Scala",
		".sh":         "Shell",
		".bash":       "Shell",
		".zsh":        "Shell",
		".fish":       "Shell",
		".ps1":        "PowerShell",
		".sql":        "SQL",
		".html":       "HTML",
		".htm":        "HTML",
		".css":        "CSS",
		".scss":       "SCSS",
		".sass":       "Sass",
		".less":       "Less",
		".vue":        "Vue",
		".xml":        "XML",
		".json":       "JSON",
		".yaml":       "YAML",
		".yml":        "YAML",
		".toml":       "TOML",
		".ini":        "INI",
		".conf":       "Config",
		".cfg":        "Config",
		".dockerfile": "Dockerfile",
		".r":          "R",
		".m":          "Objective-C",
		".mm":         "Objective-C++",
		".pl":         "Perl",
		".lua":        "Lua",
		".vim":        "Vim",
		".tex":        "LaTeX",
		".md":         "Markdown",
		".markdown":   "Markdown",
		".txt":        "Text",
	}

	if language, exists := languageMap[ext]; exists {
		return language
	}

	// Check for special files without extensions
	fileName := strings.ToLower(filepath.Base(filePath))
	switch fileName {
	case "dockerfile":
		return "Dockerfile"
	case "makefile":
		return "Makefile"
	case "rakefile":
		return "Ruby"
	case "gemfile":
		return "Ruby"
	case "package.json":
		return "JSON"
	case "go.mod", "go.sum":
		return "Go"
	}

	return ""
}

func (c *CodeStatsAnalyzer) countLinesInFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	newScanner := bufio.NewScanner(file)
	lineCount := 0

	for newScanner.Scan() {
		line := strings.TrimSpace(newScanner.Text())
		// Count non-empty lines
		if line != "" {
			lineCount++
		}
	}

	return lineCount, newScanner.Err()
}
