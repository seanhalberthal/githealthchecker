package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const fileCloseErrorMsg = "Error closing file %s: %v\n"

type FileScanner struct {
	rootPath   string
	gitIgnores []string
	patterns   map[string]*regexp.Regexp
}

type FileInfo struct {
	Path         string
	RelativePath string
	Size         int64
	Extension    string
	IsText       bool
	LineCount    int
}

func NewFileScanner(rootPath string) (*FileScanner, error) {
	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	scanner := &FileScanner{
		rootPath: absPath,
		patterns: make(map[string]*regexp.Regexp),
	}

	if err := scanner.loadGitIgnores(); err != nil {
		return nil, fmt.Errorf("failed to load .gitignore: %w", err)
	}

	return scanner, nil
}

func (fs *FileScanner) loadGitIgnores() error {
	gitIgnorePath := filepath.Join(fs.rootPath, ".gitignore")
	file, err := os.Open(gitIgnorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing .gitignore file: %v\n", err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			fs.gitIgnores = append(fs.gitIgnores, line)
		}
	}

	return scanner.Err()
}

func (fs *FileScanner) ScanFiles() ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.Walk(fs.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fs.shouldSkipPath(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		fileInfo, err := fs.createFileInfo(path, info)
		if err != nil {
			return err
		}

		if fileInfo != nil {
			files = append(files, *fileInfo)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan files: %w", err)
	}

	return files, nil
}

func (fs *FileScanner) shouldSkipPath(path string) bool {
	return strings.Contains(path, ".git")
}

func (fs *FileScanner) createFileInfo(path string, info os.FileInfo) (*FileInfo, error) {
	relPath, err := filepath.Rel(fs.rootPath, path)
	if err != nil {
		return nil, err
	}

	if fs.shouldIgnore(relPath) {
		return nil, nil
	}

	fileInfo := FileInfo{
		Path:         path,
		RelativePath: relPath,
		Size:         info.Size(),
		Extension:    strings.ToLower(filepath.Ext(path)),
		IsText:       fs.isTextFile(path),
	}

	if fileInfo.IsText {
		lineCount, err := fs.countLines(path)
		if err == nil {
			fileInfo.LineCount = lineCount
		}
	}

	return &fileInfo, nil
}

func (fs *FileScanner) shouldIgnore(path string) bool {
	for _, pattern := range fs.gitIgnores {
		// Handle directory patterns ending with /
		if strings.HasSuffix(pattern, "/") {
			dirPattern := strings.TrimSuffix(pattern, "/")
			if matched, _ := filepath.Match(dirPattern, path); matched {
				return true
			}
			if matched, _ := filepath.Match(dirPattern, filepath.Base(path)); matched {
				return true
			}
		}

		// Standard pattern matching
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

func (fs *FileScanner) isTextFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(fileCloseErrorMsg, path, err)
		}
	}(file)

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		return false
	}

	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			return false
		}
	}

	return true
}

func (fs *FileScanner) countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(fileCloseErrorMsg, path, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}

	return count, scanner.Err()
}

func (fs *FileScanner) SearchInFiles(pattern string, extensions []string) ([]Match, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	var matches []Match

	err = filepath.Walk(fs.rootPath, func(path string, info os.FileInfo, err error) error {
		return fs.processSearchPath(path, info, err, regex, extensions, &matches)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to search in files: %w", err)
	}

	return matches, nil
}

func (fs *FileScanner) processSearchPath(path string, info os.FileInfo, err error, regex *regexp.Regexp, extensions []string, matches *[]Match) error {
	if err != nil {
		return err
	}

	if fs.shouldSkipPath(path) {
		if info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}

	if info.IsDir() {
		return nil
	}

	shouldProcess, err := fs.shouldProcessFileForSearch(path, extensions)
	if err != nil {
		return err
	}
	if !shouldProcess {
		return nil
	}

	fileMatches, err := fs.searchInFile(path, regex)
	if err != nil {
		return err
	}

	*matches = append(*matches, fileMatches...)
	return nil
}

func (fs *FileScanner) shouldProcessFileForSearch(path string, extensions []string) (bool, error) {
	relPath, err := filepath.Rel(fs.rootPath, path)
	if err != nil {
		return false, err
	}

	if fs.shouldIgnore(relPath) {
		return false, nil
	}

	if !fs.hasValidExtension(path, extensions) {
		return false, nil
	}

	if !fs.isTextFile(path) {
		return false, nil
	}

	return true, nil
}

func (fs *FileScanner) hasValidExtension(path string, extensions []string) bool {
	if len(extensions) == 0 {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	for _, validExt := range extensions {
		if ext == strings.ToLower(validExt) {
			return true
		}
	}
	return false
}

func (fs *FileScanner) searchInFile(path string, regex *regexp.Regexp) ([]Match, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(fileCloseErrorMsg, path, err)
		}
	}(file)

	var matches []Match
	scanner := bufio.NewScanner(file)
	lineNum := 1

	relPath, _ := filepath.Rel(fs.rootPath, path)

	for scanner.Scan() {
		line := scanner.Text()
		if regex.MatchString(line) {
			matches = append(matches, Match{
				File:    relPath,
				Line:    lineNum,
				Content: line,
				Pattern: regex.String(),
			})
		}
		lineNum++
	}

	return matches, scanner.Err()
}

type Match struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Content string `json:"content"`
	Pattern string `json:"pattern"`
}

func (fs *FileScanner) GetFilesByExtension(extensions []string) ([]FileInfo, error) {
	files, err := fs.ScanFiles()
	if err != nil {
		return nil, err
	}

	var filtered []FileInfo
	for _, file := range files {
		for _, ext := range extensions {
			if file.Extension == strings.ToLower(ext) {
				filtered = append(filtered, file)
				break
			}
		}
	}

	return filtered, nil
}

func (fs *FileScanner) GetLargeFiles(minSizeBytes int64) ([]FileInfo, error) {
	files, err := fs.ScanFiles()
	if err != nil {
		return nil, err
	}

	var largeFiles []FileInfo
	for _, file := range files {
		if file.Size >= minSizeBytes {
			largeFiles = append(largeFiles, file)
		}
	}

	return largeFiles, nil
}
