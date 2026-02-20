// internal/provider/provider.go
package provider

import (
	"context"

	"github.com/dsablic/codemium/internal/model"
)

// ListOpts configures which repositories to retrieve from a provider.
type ListOpts struct {
	Workspace       string
	Organization    string
	User            string
	Projects        []string
	Repos           []string
	Exclude         []string
	IncludeArchived bool
	IncludeForks    bool
}

// Provider is the interface that both Bitbucket and GitHub implement
// for listing repositories.
type Provider interface {
	ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error)
}

// CommitInfo represents a commit returned from a provider API.
type CommitInfo struct {
	Hash    string
	Author  string
	Message string
}

// CommitLister extends Provider with commit history capabilities.
type CommitLister interface {
	ListCommits(ctx context.Context, repo model.Repo, limit int) ([]CommitInfo, error)
	CommitStats(ctx context.Context, repo model.Repo, hash string) (additions, deletions int64, err error)
}
