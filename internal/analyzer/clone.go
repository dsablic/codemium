// internal/analyzer/clone.go
package analyzer

import (
	"context"
	"fmt"
	"os"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Cloner performs shallow git clones into temporary directories.
type Cloner struct {
	token    string
	username string
}

// NewCloner creates a Cloner. If token is non-empty it will be used for
// HTTP basic-auth. If username is empty, "x-token-auth" is used (works
// for OAuth tokens on GitHub and Bitbucket). For Bitbucket App Passwords,
// pass the actual Bitbucket username.
func NewCloner(token, username string) *Cloner {
	return &Cloner{token: token, username: username}
}

// Clone shallow-clones the repository at cloneURL into a temporary directory.
// It returns the directory path, a cleanup function that removes the directory,
// and any error. The caller must call cleanup when done with the directory.
func (c *Cloner) Clone(ctx context.Context, cloneURL string) (dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "codemium-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanupFn := func() {
		os.RemoveAll(tmpDir)
	}

	opts := &git.CloneOptions{
		URL:          cloneURL,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
	}

	if c.token != "" {
		username := c.username
		if username == "" {
			username = "x-token-auth"
		}
		opts.Auth = &http.BasicAuth{
			Username: username,
			Password: c.token,
		}
	}

	_, err = git.PlainCloneContext(ctx, tmpDir, false, opts)
	if err != nil {
		cleanupFn()
		return "", nil, fmt.Errorf("git clone: %w", err)
	}

	return tmpDir, cleanupFn, nil
}
