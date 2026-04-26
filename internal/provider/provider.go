// internal/provider/provider.go
package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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

// Provider is the interface that Bitbucket, GitHub, and GitLab implement
// for listing repositories.
type Provider interface {
	ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error)
}

// CommitInfo represents a commit returned from a provider API.
type CommitInfo struct {
	Hash    string
	Author  string
	Message string
	Date    time.Time
}

// CommitLister extends Provider with commit history capabilities.
type CommitLister interface {
	ListCommits(ctx context.Context, repo model.Repo, limit int) ([]CommitInfo, error)
	CommitStats(ctx context.Context, repo model.Repo, hash string) (additions, deletions int64, err error)
}

// FileChange represents a file modified in a commit.
type FileChange struct {
	Path      string
	Additions int64
	Deletions int64
}

// ChurnLister extends Provider with per-file commit stats.
type ChurnLister interface {
	CommitLister
	CommitFileStats(ctx context.Context, repo model.Repo, hash string) ([]FileChange, error)
}

// statusError creates a descriptive error from a non-OK HTTP response,
// including up to 512 bytes of the response body for debugging.
func statusError(prefix string, resp *http.Response) error {
	snippet := make([]byte, 512)
	n, _ := io.ReadFull(resp.Body, snippet)
	body := strings.TrimSpace(string(snippet[:n]))
	if body != "" {
		return fmt.Errorf("%s returned status %d: %s", prefix, resp.StatusCode, body)
	}
	return fmt.Errorf("%s returned status %d", prefix, resp.StatusCode)
}
