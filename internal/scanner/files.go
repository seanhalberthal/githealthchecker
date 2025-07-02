package scanner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const fileCloseErrorMsg = "Error closing file %s: %v\n"

type FileScanner struct {
	rootPath     string
	gitIgnores   []string
	patterns     map[string]*regexp.Regexp
	cache        *FileCache
	maxCacheSize int64 // Max file size to cache content (default 1MB)
}

type FileInfo struct {
	Path         string
	RelativePath string
	Size         int64
	Extension    string
	IsText       bool
	LineCount    int
}

// UnifiedFileInfo contains all file information collected in single traversal
type UnifiedFileInfo struct {
	Path         string
	RelativePath string
	Size         int64
	Extension    string
	IsText       bool
	LineCount    int
	Content      []byte // Cached content for small files (<1MB)
	FirstBytes   []byte // First 512 bytes for binary detection
	ModTime      int64  // Modification time
}

// FileCache provides thread-safe access to cached file information
type FileCache struct {
	mu    sync.RWMutex
	files map[string]*UnifiedFileInfo
}

func NewFileScanner(rootPath string) (*FileScanner, error) {
	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	scanner := &FileScanner{
		rootPath:     absPath,
		patterns:     make(map[string]*regexp.Regexp),
		cache:        &FileCache{files: make(map[string]*UnifiedFileInfo)},
		maxCacheSize: 1024 * 1024, // 1MB default
	}

	if err := scanner.loadGitIgnores(); err != nil {
		return nil, fmt.Errorf("failed to load .gitignore: %w", err)
	}

	return scanner, nil
}

// ScanAllFiles performs a single traversal collecting all file information
func (fs *FileScanner) ScanAllFiles() (map[string]*UnifiedFileInfo, error) {
	fs.cache.mu.Lock()
	defer fs.cache.mu.Unlock()

	// Clear existing cache
	fs.cache.files = make(map[string]*UnifiedFileInfo)

	err := filepath.Walk(fs.rootPath, func(path string, info os.FileInfo, err error) error {
		return fs.processUnifiedPath(path, info, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan files: %w", err)
	}

	return fs.cache.files, nil
}

// processUnifiedPath processes each file/directory in the unified scan
func (fs *FileScanner) processUnifiedPath(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if shouldSkip := fs.shouldSkipDirectory(path, info); shouldSkip != nil {
		return shouldSkip
	}

	if info.IsDir() {
		return nil
	}

	return fs.processFile(path, info)
}

// shouldSkipDirectory checks if a directory should be skipped
func (fs *FileScanner) shouldSkipDirectory(path string, info os.FileInfo) error {
	if fs.shouldSkipPath(path) {
		if info.IsDir() {
			return filepath.SkipDir
		}
		return filepath.SkipDir
	}
	return nil
}

// processFile processes a single file and adds it to cache
func (fs *FileScanner) processFile(path string, info os.FileInfo) error {
	relPath, err := filepath.Rel(fs.rootPath, path)
	if err != nil {
		return err
	}

	if fs.shouldIgnore(relPath) {
		return nil
	}

	uniFileInfo := fs.createFileInfo(path, relPath, info)
	fs.analyzeFileContent(uniFileInfo)
	fs.cache.files[relPath] = uniFileInfo
	return nil
}

// createFileInfo creates basic file information
func (fs *FileScanner) createFileInfo(path, relPath string, info os.FileInfo) *UnifiedFileInfo {
	return &UnifiedFileInfo{
		Path:         path,
		RelativePath: relPath,
		Size:         info.Size(),
		Extension:    strings.ToLower(filepath.Ext(path)),
		ModTime:      info.ModTime().Unix(),
	}
}

// analyzeFileContent analyzes file content and populates cache
func (fs *FileScanner) analyzeFileContent(fileInfo *UnifiedFileInfo) {
	// Read first bytes for binary detection
	if err := fs.readFirstBytes(fileInfo); err != nil {
		fileInfo.IsText = false
		return
	}

	fileInfo.IsText = fs.isTextFromBytes(fileInfo.FirstBytes)
	if !fileInfo.IsText {
		return
	}

	fs.handleTextFileContent(fileInfo)
	fs.calculateLineCount(fileInfo)
}

// handleTextFileContent caches content for small text files
func (fs *FileScanner) handleTextFileContent(fileInfo *UnifiedFileInfo) {
	if fileInfo.Size <= fs.maxCacheSize {
		err := fs.cacheFileContent(fileInfo)
		if err != nil {
			return
		} // Ignore errors, non-critical
	}
}

// calculateLineCount calculates line count from cache or file
func (fs *FileScanner) calculateLineCount(fileInfo *UnifiedFileInfo) {
	if len(fileInfo.Content) > 0 {
		fileInfo.LineCount = fs.countLinesFromBytes(fileInfo.Content)
	} else {
		if lineCount, err := fs.countLines(fileInfo.Path); err == nil {
			fileInfo.LineCount = lineCount
		}
	}
}

// readFirstBytes reads the first 512 bytes for binary detection
func (fs *FileScanner) readFirstBytes(fileInfo *UnifiedFileInfo) error {
	file, err := os.Open(fileInfo.Path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(fileCloseErrorMsg, fileInfo.Path, err)
		}
	}(file)

	fileInfo.FirstBytes = make([]byte, 512)
	n, err := file.Read(fileInfo.FirstBytes)
	if err != nil && err != io.EOF {
		return err
	}
	fileInfo.FirstBytes = fileInfo.FirstBytes[:n]
	return nil
}

// cacheFileContent caches the entire file content for small files
func (fs *FileScanner) cacheFileContent(fileInfo *UnifiedFileInfo) error {
	file, err := os.Open(fileInfo.Path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf(fileCloseErrorMsg, fileInfo.Path, err)
		}
	}(file)

	fileInfo.Content, err = io.ReadAll(file)
	return err
}

// isTextFromBytes determines if file is text based on byte content
func (fs *FileScanner) isTextFromBytes(bytes []byte) bool {
	for i := 0; i < len(bytes); i++ {
		if bytes[i] == 0 {
			return false
		}
	}
	return true
}

// countLinesFromBytes counts lines from cached byte content
func (fs *FileScanner) countLinesFromBytes(content []byte) int {
	count := 0
	for _, b := range content {
		if b == '\n' {
			count++
		}
	}
	// Add 1 if file doesn't end with newline but has content
	if len(content) > 0 && content[len(content)-1] != '\n' {
		count++
	}
	return count
}

// countLinesStreaming counts lines in large files using streaming
func (fs *FileScanner) countLinesStreaming(path string) (int, error) {
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

	return fs.streamingLineCount(file)
}

// streamingLineCount performs the actual streaming line count
func (fs *FileScanner) streamingLineCount(file *os.File) (int, error) {
	const bufferSize = 64 * 1024 // 64KB buffer
	buffer := make([]byte, bufferSize)
	count := 0
	lastCharWasNewline := false

	for {
		n, err := file.Read(buffer)
		if n == 0 {
			break
		}

		count, lastCharWasNewline = fs.countLinesInBuffer(buffer[:n], count, lastCharWasNewline)

		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
	}

	return fs.adjustFinalLineCount(count, lastCharWasNewline), nil
}

// countLinesInBuffer counts newlines in a buffer chunk
func (fs *FileScanner) countLinesInBuffer(buffer []byte, currentCount int, lastWasNewline bool) (int, bool) {
	count := currentCount
	lastCharWasNewline := lastWasNewline

	for _, b := range buffer {
		if b == '\n' {
			count++
			lastCharWasNewline = true
		} else {
			lastCharWasNewline = false
		}
	}

	return count, lastCharWasNewline
}

// adjustFinalLineCount adds 1 if file doesn't end with newline
func (fs *FileScanner) adjustFinalLineCount(count int, lastCharWasNewline bool) int {
	if !lastCharWasNewline && count >= 0 {
		count++
	}
	return count
}

// searchInFileStreaming searches for patterns in large files using streaming
func (fs *FileScanner) searchInFileStreaming(path string, regex *regexp.Regexp) ([]Match, error) {
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

	// Use a larger buffer for better performance on large files
	buf := make([]byte, 0, 256*1024) // 256KB buffer
	scanner.Buffer(buf, 1024*1024)   // 1MB max token size

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

// GetCachedFiles returns cached file information (thread-safe)
func (fs *FileScanner) GetCachedFiles() map[string]*UnifiedFileInfo {
	fs.cache.mu.RLock()
	defer fs.cache.mu.RUnlock()

	// Return copy to prevent modification
	cp := make(map[string]*UnifiedFileInfo)
	for k, v := range fs.cache.files {
		cp[k] = v
	}
	return cp
}

// GetCachedFile returns a specific cached file (thread-safe)
func (fs *FileScanner) GetCachedFile(relativePath string) (*UnifiedFileInfo, bool) {
	fs.cache.mu.RLock()
	defer fs.cache.mu.RUnlock()

	file, exists := fs.cache.files[relativePath]
	return file, exists
}

// FilterCachedFiles returns cached files matching the filter function
func (fs *FileScanner) FilterCachedFiles(filter func(*UnifiedFileInfo) bool) []*UnifiedFileInfo {
	fs.cache.mu.RLock()
	defer fs.cache.mu.RUnlock()

	var filtered []*UnifiedFileInfo
	for _, file := range fs.cache.files {
		if filter(file) {
			filtered = append(filtered, file)
		}
	}
	return filtered
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

// ScanFiles provides backward compatibility - converts cached files to legacy format
func (fs *FileScanner) ScanFiles() ([]FileInfo, error) {
	cachedFiles := fs.GetCachedFiles()
	if len(cachedFiles) == 0 {
		// Perform scan if cache is empty
		if _, err := fs.ScanAllFiles(); err != nil {
			return nil, err
		}
		cachedFiles = fs.GetCachedFiles()
	}

	var files []FileInfo
	for _, file := range cachedFiles {
		files = append(files, FileInfo{
			Path:         file.Path,
			RelativePath: file.RelativePath,
			Size:         file.Size,
			Extension:    file.Extension,
			IsText:       file.IsText,
			LineCount:    file.LineCount,
		})
	}

	return files, nil
}

func (fs *FileScanner) shouldSkipPath(path string) bool {
	return strings.Contains(path, ".git")
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

func (fs *FileScanner) countLines(path string) (int, error) {
	// Check file size to decide whether to use streaming
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	// Use streaming for files larger than 1MB
	if info.Size() > 1024*1024 {
		return fs.countLinesStreaming(path)
	}

	// Use regular method for smaller files
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

	if skipResult := fs.handleSearchSkipConditions(path, info); skipResult != nil {
		return skipResult
	}

	return fs.processSearchFile(path, regex, extensions, matches)
}

// handleSearchSkipConditions checks if path should be skipped during search
func (fs *FileScanner) handleSearchSkipConditions(path string, info os.FileInfo) error {
	if fs.shouldSkipPath(path) {
		if info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}

	if info.IsDir() {
		return nil
	}

	return nil
}

// processSearchFile processes a file for search matches
func (fs *FileScanner) processSearchFile(path string, regex *regexp.Regexp, extensions []string, matches *[]Match) error {
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

	// Check if file is text by reading first bytes
	file, err := os.Open(path)
	if err != nil {
		return false, nil
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
		return false, nil
	}

	// Check for null bytes (binary indicator)
	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			return false, nil
		}
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
	// Check file size to decide whether to use streaming
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Use streaming for files larger than 1MB
	if info.Size() > 1024*1024 {
		return fs.searchInFileStreaming(path, regex)
	}

	// Use regular method for smaller files
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

// GetFilesByExtension returns files with specified extensions (optimized with cache)
func (fs *FileScanner) GetFilesByExtension(extensions []string) ([]FileInfo, error) {
	// Try to use cached data first
	cachedFiles := fs.GetCachedFiles()
	if len(cachedFiles) > 0 {
		return fs.filterByExtensionFromCache(cachedFiles, extensions), nil
	}

	// Fallback to original method
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

// filterByExtensionFromCache filters cached files by extension
func (fs *FileScanner) filterByExtensionFromCache(cachedFiles map[string]*UnifiedFileInfo, extensions []string) []FileInfo {
	var filtered []FileInfo
	for _, file := range cachedFiles {
		for _, ext := range extensions {
			if file.Extension == strings.ToLower(ext) {
				filtered = append(filtered, FileInfo{
					Path:         file.Path,
					RelativePath: file.RelativePath,
					Size:         file.Size,
					Extension:    file.Extension,
					IsText:       file.IsText,
					LineCount:    file.LineCount,
				})
				break
			}
		}
	}
	return filtered
}

// GetLargeFiles returns files larger than specified size (optimized with cache)
func (fs *FileScanner) GetLargeFiles(minSizeBytes int64) ([]FileInfo, error) {
	// Try to use cached data first
	cachedFiles := fs.GetCachedFiles()
	if len(cachedFiles) > 0 {
		return fs.filterLargeFilesFromCache(cachedFiles, minSizeBytes), nil
	}

	// Fallback to original method
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

// filterLargeFilesFromCache filters cached files by size
func (fs *FileScanner) filterLargeFilesFromCache(cachedFiles map[string]*UnifiedFileInfo, minSizeBytes int64) []FileInfo {
	var largeFiles []FileInfo
	for _, file := range cachedFiles {
		if file.Size >= minSizeBytes {
			largeFiles = append(largeFiles, FileInfo{
				Path:         file.Path,
				RelativePath: file.RelativePath,
				Size:         file.Size,
				Extension:    file.Extension,
				IsText:       file.IsText,
				LineCount:    file.LineCount,
			})
		}
	}
	return largeFiles
}
