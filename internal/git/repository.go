package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const reachedMaxCountError = "reached max count"

const failedToGetHeadError = "failed to get HEAD:"

type Repository struct {
	repo     *gogit.Repository
	workTree *gogit.Worktree
	path     string
	cache    *Cache
}

// GitCache provides caching for expensive Git operations
type Cache struct {
	mu            sync.RWMutex
	branches      []string
	remotes       []string
	headRef       *plumbing.Reference
	commitHistory []*object.Commit
	batchedData   *BatchedGitData
	cacheValid    bool
}

// BatchedGitData contains results from batched Git operations
type BatchedGitData struct {
	Branches      []string
	Remotes       []string
	CurrentBranch string
	CurrentCommit string
	Status        gogit.Status
}

func OpenRepository(path string) (*Repository, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	repo, err := gogit.PlainOpen(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open git repository at %s: %w", absPath, err)
	}

	workTree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to get worktree: %w", err)
	}

	return &Repository{
		repo:     repo,
		workTree: workTree,
		path:     absPath,
		cache:    &Cache{},
	}, nil
}

func IsGitRepository(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	gitDir := filepath.Join(absPath, ".git")
	if info, err := os.Stat(gitDir); err == nil {
		return info.IsDir()
	}

	_, err = gogit.PlainOpen(absPath)
	return err == nil
}

func (r *Repository) GetPath() string {
	return r.path
}

func (r *Repository) GetCurrentBranch() (string, error) {
	// Try to use batched data first
	batchedData, err := r.BatchGitOperations()
	if err == nil && batchedData.CurrentBranch != "" {
		return batchedData.CurrentBranch, nil
	}

	// Fallback to direct access
	head, err := r.repo.Head()
	if err != nil {
		return "", fmt.Errorf(failedToGetHeadError+" %w", err)
	}

	if head.Name().IsBranch() {
		return head.Name().Short(), nil
	}

	return "HEAD", nil
}

func (r *Repository) GetCurrentCommit() (string, error) {
	// Try to use batched data first
	batchedData, err := r.BatchGitOperations()
	if err == nil && batchedData.CurrentCommit != "" {
		return batchedData.CurrentCommit, nil
	}

	// Fallback to direct access
	head, err := r.repo.Head()
	if err != nil {
		return "", fmt.Errorf(failedToGetHeadError+" %w", err)
	}

	return head.Hash().String(), nil
}

func (r *Repository) GetCommitHistory(maxCount int) ([]*object.Commit, error) {
	head, err := r.repo.Head()
	if err != nil {
		return nil, fmt.Errorf(failedToGetHeadError+" %w", err)
	}

	commitIter, err := r.repo.Log(&gogit.LogOptions{
		From: head.Hash(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit log: %w", err)
	}
	defer commitIter.Close()

	var commits []*object.Commit
	count := 0

	err = commitIter.ForEach(func(commit *object.Commit) error {
		if maxCount > 0 && count >= maxCount {
			return fmt.Errorf(reachedMaxCountError)
		}
		commits = append(commits, commit)
		count++
		return nil
	})

	if err != nil && !strings.Contains(err.Error(), reachedMaxCountError) {
		return nil, fmt.Errorf("failed to iterate commits: %w", err)
	}

	return commits, nil
}

func (r *Repository) GetBranches() ([]string, error) {
	// Try to use batched data first
	batchedData, err := r.BatchGitOperations()
	if err == nil && len(batchedData.Branches) > 0 {
		return batchedData.Branches, nil
	}

	// Fallback to direct access
	return r.getBranchesInternal()
}

func (r *Repository) GetRemotes() ([]string, error) {
	// Try to use batched data first
	batchedData, err := r.BatchGitOperations()
	if err == nil && len(batchedData.Remotes) > 0 {
		return batchedData.Remotes, nil
	}

	// Fallback to direct access
	return r.getRemotesInternal()
}

func (r *Repository) GetStatus() (gogit.Status, error) {
	// Try to use batched data first
	batchedData, err := r.BatchGitOperations()
	if err == nil && batchedData.Status != nil {
		return batchedData.Status, nil
	}

	// Fallback to direct access
	status, err := r.workTree.Status()
	if err != nil {
		return nil, fmt.Errorf("failed to get repository status: %w", err)
	}

	return status, nil
}

func (r *Repository) GetFileHistory(filePath string, maxCount int) ([]*object.Commit, error) {
	head, err := r.repo.Head()
	if err != nil {
		return nil, fmt.Errorf(failedToGetHeadError+" %w", err)
	}

	commitIter, err := r.repo.Log(&gogit.LogOptions{
		From:     head.Hash(),
		FileName: &filePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get file history: %w", err)
	}
	defer commitIter.Close()

	var commits []*object.Commit
	count := 0

	err = commitIter.ForEach(func(commit *object.Commit) error {
		if maxCount > 0 && count >= maxCount {
			return fmt.Errorf(reachedMaxCountError)
		}
		commits = append(commits, commit)
		count++
		return nil
	})

	if err != nil && !strings.Contains(err.Error(), reachedMaxCountError) {
		return nil, fmt.Errorf("failed to iterate file commits: %w", err)
	}

	return commits, nil
}

// BatchGitOperations performs multiple Git operations in one call for efficiency
func (r *Repository) BatchGitOperations() (*BatchedGitData, error) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()

	// Return cached data if valid
	if r.cache.cacheValid && r.cache.batchedData != nil {
		return r.cache.batchedData, nil
	}

	batchedData := &BatchedGitData{}

	// Get HEAD reference once
	head, err := r.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}
	r.cache.headRef = head

	// Get current branch
	if head.Name().IsBranch() {
		batchedData.CurrentBranch = head.Name().Short()
	} else {
		batchedData.CurrentBranch = "HEAD"
	}

	// Get current commit
	batchedData.CurrentCommit = head.Hash().String()

	// Get branches
	branches, err := r.getBranchesInternal()
	if err == nil {
		batchedData.Branches = branches
		r.cache.branches = branches
	}

	// Get remotes
	remotes, err := r.getRemotesInternal()
	if err == nil {
		batchedData.Remotes = remotes
		r.cache.remotes = remotes
	}

	// Get status
	status, err := r.workTree.Status()
	if err == nil {
		batchedData.Status = status
	}

	// Cache the results
	r.cache.batchedData = batchedData
	r.cache.cacheValid = true

	return batchedData, nil
}

// getBranchesInternal is the internal implementation without caching logic
func (r *Repository) getBranchesInternal() ([]string, error) {
	branches, err := r.repo.Branches()
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}
	defer branches.Close()

	var branchNames []string
	err = branches.ForEach(func(ref *plumbing.Reference) error {
		branchNames = append(branchNames, ref.Name().Short())
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to iterate branches: %w", err)
	}

	return branchNames, nil
}

// getRemotesInternal is the internal implementation without caching logic
func (r *Repository) getRemotesInternal() ([]string, error) {
	remotes, err := r.repo.Remotes()
	if err != nil {
		return nil, fmt.Errorf("failed to get remotes: %w", err)
	}

	var remoteNames []string
	for _, remote := range remotes {
		remoteNames = append(remoteNames, remote.Config().Name)
	}

	return remoteNames, nil
}

// InvalidateCache invalidates the Git cache
func (r *Repository) InvalidateCache() {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	r.cache.cacheValid = false
	r.cache.batchedData = nil
}

func (r *Repository) GetLargeFiles(minSizeBytes int64) ([]string, error) {
	var largeFiles []string

	err := filepath.Walk(r.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.Contains(path, ".git") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if !info.IsDir() && info.Size() >= minSizeBytes {
			relPath, err := filepath.Rel(r.path, path)
			if err != nil {
				return err
			}
			largeFiles = append(largeFiles, relPath)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk repository files: %w", err)
	}

	return largeFiles, nil
}
