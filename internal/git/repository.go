package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func (r *Repository) GetRemotes() ([]string, error) {
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

func (r *Repository) GetStatus() (gogit.Status, error) {
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
