// internal/analyzer/clone.go
package analyzer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// noop is a cleanup function that does nothing, used for durable clones.
var noop = func() {}

// Cloner performs shallow git clones into temporary directories.
type Cloner struct {
	token    string
	username string
	client   *http.Client
}

// NewCloner creates a Cloner. If token is non-empty it will be used for
// HTTP basic-auth. If username is empty, "x-token-auth" is used (works
// for OAuth tokens on GitHub and Bitbucket). For Bitbucket API tokens,
// pass the Atlassian email as username.
func NewCloner(token, username string) *Cloner {
	return &Cloner{token: token, username: username, client: &http.Client{}}
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
		opts.Auth = &githttp.BasicAuth{
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

// CloneTo shallow-clones the repository at cloneURL into destDir. If destDir
// already exists and contains entries the clone is skipped. The returned
// cleanup function is always a no-op because the directory is meant to be
// durable (persist across runs).
func (c *Cloner) CloneTo(ctx context.Context, cloneURL, destDir string) (string, func(), error) {
	// If destDir already exists and has entries, skip cloning.
	if entries, err := os.ReadDir(destDir); err == nil && len(entries) > 0 {
		return destDir, noop, nil
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("create dest dir: %w", err)
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
		opts.Auth = &githttp.BasicAuth{
			Username: username,
			Password: c.token,
		}
	}

	_, err := git.PlainCloneContext(ctx, destDir, false, opts)
	if err != nil {
		return "", nil, fmt.Errorf("git clone: %w", err)
	}

	return destDir, noop, nil
}

// CloneFull clones the repository at cloneURL with full history into a
// temporary directory. It returns the go-git Repository handle, the directory
// path, a cleanup function, and any error.
func (c *Cloner) CloneFull(ctx context.Context, cloneURL string) (repo *git.Repository, dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "codemium-*")
	if err != nil {
		return nil, "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanupFn := func() {
		os.RemoveAll(tmpDir)
	}

	opts := &git.CloneOptions{
		URL:  cloneURL,
		Tags: git.NoTags,
	}

	if c.token != "" {
		username := c.username
		if username == "" {
			username = "x-token-auth"
		}
		opts.Auth = &githttp.BasicAuth{
			Username: username,
			Password: c.token,
		}
	}

	r, err := git.PlainCloneContext(ctx, tmpDir, false, opts)
	if err != nil {
		cleanupFn()
		return nil, "", nil, fmt.Errorf("git clone: %w", err)
	}

	return r, tmpDir, cleanupFn, nil
}

// Checkout checks out the given commit hash in the repository worktree,
// forcefully replacing any existing working tree contents.
func Checkout(repo *git.Repository, dir string, hash plumbing.Hash) error {
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("get worktree: %w", err)
	}

	err = wt.Checkout(&git.CheckoutOptions{
		Hash:  hash,
		Force: true,
	})
	if err != nil {
		return fmt.Errorf("checkout %s: %w", hash, err)
	}

	return nil
}

// Download fetches a tarball from downloadURL, extracts it to a temporary
// directory, and returns the path. This is used when git clone is not
// available (e.g. Bitbucket scoped API tokens).
func (c *Cloner) Download(ctx context.Context, downloadURL string) (dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "codemium-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanupFn := func() {
		os.RemoveAll(tmpDir)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		cleanupFn()
		return "", nil, err
	}
	if c.token != "" && c.username != "" {
		req.SetBasicAuth(c.username, c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		cleanupFn()
		return "", nil, fmt.Errorf("download tarball: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cleanupFn()
		return "", nil, fmt.Errorf("download tarball: HTTP %d", resp.StatusCode)
	}

	if err := extractTarGz(resp.Body, tmpDir); err != nil {
		cleanupFn()
		return "", nil, fmt.Errorf("extract tarball: %w", err)
	}

	return tmpDir, cleanupFn, nil
}

// DownloadTo fetches a tarball from downloadURL and extracts it to destDir.
// If destDir already exists and contains entries the download is skipped.
// The returned cleanup function is always a no-op because the directory is
// meant to be durable (persist across runs).
func (c *Cloner) DownloadTo(ctx context.Context, downloadURL, destDir string) (string, func(), error) {
	// If destDir already exists and has entries, skip downloading.
	if entries, err := os.ReadDir(destDir); err == nil && len(entries) > 0 {
		return destDir, noop, nil
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("create dest dir: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", nil, err
	}
	if c.token != "" && c.username != "" {
		req.SetBasicAuth(c.username, c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("download tarball: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("download tarball: HTTP %d", resp.StatusCode)
	}

	if err := extractTarGz(resp.Body, destDir); err != nil {
		return "", nil, fmt.Errorf("extract tarball: %w", err)
	}

	return destDir, noop, nil
}

// maxFileSize is the maximum allowed size for a single file extracted from a
// tarball (256 MB). This prevents decompression bombs from consuming all memory.
const maxFileSize = 256 << 20

// extractTarGz decompresses a gzipped tar archive from r into destDir.
// Bitbucket tarballs have a top-level prefix directory; files are extracted
// directly into destDir with that prefix stripped.
func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	prefix := ""

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Detect and strip the top-level prefix directory
		if prefix == "" {
			parts := strings.SplitN(hdr.Name, "/", 2)
			if len(parts) == 2 {
				prefix = parts[0] + "/"
			}
		}

		name := strings.TrimPrefix(hdr.Name, prefix)
		if name == "" || name == "." {
			continue
		}

		target := filepath.Join(destDir, filepath.FromSlash(name))

		// Guard against zip slip
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			if hdr.Size > maxFileSize {
				continue // skip files that exceed the size limit
			}
			os.MkdirAll(filepath.Dir(target), 0o755)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxFileSize)); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}

	return nil
}
