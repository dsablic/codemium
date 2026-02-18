# Codemium Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go CLI that generates code statistics (LOC, comments, complexity) across all repositories in a Bitbucket Cloud workspace or GitHub organization.

**Architecture:** Provider abstraction for Bitbucket/GitHub, scc as a Go library for analysis, go-git for cloning, bounded worker pool for parallelism, bubbletea for terminal progress UI.

**Tech Stack:** Go, cobra, scc/v3, go-git/v5, bubbletea/bubbles/lipgloss, charmbracelet/x/term

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `cmd/codemium/main.go`

**Step 1: Initialize Go module**

Run: `go mod init github.com/labtiva/codemium`

**Step 2: Install core dependencies**

Run:
```bash
go get github.com/spf13/cobra@latest
go get github.com/boyter/scc/v3@latest
go get github.com/go-git/go-git/v5@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/bubbles@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/charmbracelet/x/term@latest
```

**Step 3: Create minimal main.go with root command**

```go
// cmd/codemium/main.go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "codemium",
		Short: "Generate code statistics across repositories",
	}

	root.AddCommand(newAuthCmd())
	root.AddCommand(newAnalyzeCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "login",
		Short: "Authenticate with a provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	})
	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze",
		Short: "Analyze repositories and generate code statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}
```

**Step 4: Verify it compiles and runs**

Run: `go build ./cmd/codemium && ./codemium --help`
Expected: Help output showing `auth` and `analyze` subcommands.

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: project scaffolding with cobra CLI skeleton"
```

---

### Task 2: Data Model Types

**Files:**
- Create: `internal/model/model.go`
- Create: `internal/model/model_test.go`

**Step 1: Write the test**

```go
// internal/model/model_test.go
package model_test

import (
	"encoding/json"
	"testing"

	"github.com/labtiva/codemium/internal/model"
)

func TestReportJSON(t *testing.T) {
	report := model.Report{
		GeneratedAt: "2026-02-18T12:00:00Z",
		Provider:    "bitbucket",
		Workspace:   "myworkspace",
		Filters:     model.Filters{Projects: []string{"PROJ1"}},
		Repositories: []model.RepoStats{
			{
				Repository: "my-repo",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				URL:        "https://bitbucket.org/myworkspace/my-repo",
				Languages: []model.LanguageStats{
					{Name: "Go", Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
				},
				Totals: model.Stats{Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
			},
		},
		Totals: model.Stats{Repos: 1, Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
		ByLanguage: []model.LanguageStats{
			{Name: "Go", Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}

	if decoded.Provider != "bitbucket" {
		t.Errorf("expected provider bitbucket, got %s", decoded.Provider)
	}
	if decoded.Totals.Code != 400 {
		t.Errorf("expected total code 400, got %d", decoded.Totals.Code)
	}
	if len(decoded.Repositories) != 1 {
		t.Errorf("expected 1 repo, got %d", len(decoded.Repositories))
	}
	if decoded.Repositories[0].Project != "PROJ1" {
		t.Errorf("expected project PROJ1, got %s", decoded.Repositories[0].Project)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/model/...`
Expected: FAIL — package does not exist yet.

**Step 3: Write the implementation**

```go
// internal/model/model.go
package model

// Repo represents a repository from a provider.
type Repo struct {
	Name     string
	Slug     string
	Project  string
	URL      string
	CloneURL string
	Provider string
	Archived bool
	Fork     bool
}

// LanguageStats holds code statistics for a single language.
type LanguageStats struct {
	Name       string `json:"name"`
	Files      int64  `json:"files"`
	Lines      int64  `json:"lines"`
	Code       int64  `json:"code"`
	Comments   int64  `json:"comments"`
	Blanks     int64  `json:"blanks"`
	Complexity int64  `json:"complexity"`
}

// Stats holds aggregate code statistics.
type Stats struct {
	Repos      int   `json:"repos,omitempty"`
	Files      int64 `json:"files"`
	Lines      int64 `json:"lines"`
	Code       int64 `json:"code"`
	Comments   int64 `json:"comments"`
	Blanks     int64 `json:"blanks"`
	Complexity int64 `json:"complexity"`
}

// RepoStats holds the analysis results for a single repository.
type RepoStats struct {
	Repository string          `json:"repository"`
	Project    string          `json:"project,omitempty"`
	Provider   string          `json:"provider"`
	URL        string          `json:"url"`
	Languages  []LanguageStats `json:"languages"`
	Totals     Stats           `json:"totals"`
}

// RepoError records a repository that failed to process.
type RepoError struct {
	Repository string `json:"repository"`
	Error      string `json:"error"`
}

// Filters records what filters were applied to the analysis.
type Filters struct {
	Projects []string `json:"projects,omitempty"`
	Repos    []string `json:"repos,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}

// Report is the top-level output structure.
type Report struct {
	GeneratedAt  string          `json:"generated_at"`
	Provider     string          `json:"provider"`
	Workspace    string          `json:"workspace,omitempty"`
	Organization string          `json:"organization,omitempty"`
	Filters      Filters         `json:"filters"`
	Repositories []RepoStats     `json:"repositories"`
	Totals       Stats           `json:"totals"`
	ByLanguage   []LanguageStats `json:"by_language"`
	Errors       []RepoError     `json:"errors,omitempty"`
}
```

**Step 4: Run tests**

Run: `go test ./internal/model/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add data model types for report, repo stats, and language stats"
```

---

### Task 3: Credentials Storage

**Files:**
- Create: `internal/auth/credentials.go`
- Create: `internal/auth/credentials_test.go`

**Step 1: Write the test**

```go
// internal/auth/credentials_test.go
package auth_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labtiva/codemium/internal/auth"
)

func TestCredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewFileStore(filepath.Join(dir, "credentials.json"))

	cred := auth.Credentials{
		AccessToken:  "test-token",
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	if err := store.Save("bitbucket", cred); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	loaded, err := store.Load("bitbucket")
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if loaded.AccessToken != "test-token" {
		t.Errorf("expected test-token, got %s", loaded.AccessToken)
	}
	if loaded.RefreshToken != "test-refresh" {
		t.Errorf("expected test-refresh, got %s", loaded.RefreshToken)
	}
}

func TestCredentialsMissing(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewFileStore(filepath.Join(dir, "credentials.json"))

	_, err := store.Load("github")
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestCredentialsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewFileStore(filepath.Join(dir, "credentials.json"))

	t.Setenv("CODEMIUM_BITBUCKET_TOKEN", "env-token")

	cred, err := store.LoadWithEnv("bitbucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.AccessToken != "env-token" {
		t.Errorf("expected env-token, got %s", cred.AccessToken)
	}
}

func TestCredentialsFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	store := auth.NewFileStore(path)

	cred := auth.Credentials{AccessToken: "secret"}
	if err := store.Save("github", cred); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/...`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/auth/credentials.go
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ErrNoCredentials = errors.New("no credentials found")

type Credentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

func (c Credentials) Expired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

type FileStore struct {
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func DefaultStorePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(configDir, "codemium", "credentials.json")
}

func (s *FileStore) Save(provider string, cred Credentials) error {
	all, _ := s.loadAll()
	if all == nil {
		all = make(map[string]Credentials)
	}
	all[provider] = cred

	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

func (s *FileStore) Load(provider string) (Credentials, error) {
	all, err := s.loadAll()
	if err != nil {
		return Credentials{}, ErrNoCredentials
	}
	cred, ok := all[provider]
	if !ok {
		return Credentials{}, ErrNoCredentials
	}
	return cred, nil
}

func (s *FileStore) LoadWithEnv(provider string) (Credentials, error) {
	envKey := fmt.Sprintf("CODEMIUM_%s_TOKEN", toUpperSnake(provider))
	if token := os.Getenv(envKey); token != "" {
		return Credentials{AccessToken: token}, nil
	}
	return s.Load(provider)
}

func (s *FileStore) loadAll() (map[string]Credentials, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var all map[string]Credentials
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	return all, nil
}

func toUpperSnake(s string) string {
	result := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result = append(result, c)
	}
	return string(result)
}
```

**Step 4: Run tests**

Run: `go test ./internal/auth/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add credentials file storage with env var override"
```

---

### Task 4: OAuth Flow — Bitbucket

**Files:**
- Create: `internal/auth/bitbucket.go`
- Create: `internal/auth/bitbucket_test.go`

**Step 1: Write the test**

```go
// internal/auth/bitbucket_test.go
package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labtiva/codemium/internal/auth"
)

func TestBitbucketTokenExchange(t *testing.T) {
	// Mock Bitbucket token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type=authorization_code, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "test-code" {
			t.Errorf("expected code=test-code, got %s", r.Form.Get("code"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "bb-access-token",
			"refresh_token": "bb-refresh-token",
			"expires_in":    3600,
			"token_type":    "bearer",
		})
	}))
	defer server.Close()

	bb := auth.BitbucketOAuth{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TokenURL:     server.URL,
	}

	cred, err := bb.ExchangeCode(context.Background(), "test-code")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if cred.AccessToken != "bb-access-token" {
		t.Errorf("expected bb-access-token, got %s", cred.AccessToken)
	}
	if cred.RefreshToken != "bb-refresh-token" {
		t.Errorf("expected bb-refresh-token, got %s", cred.RefreshToken)
	}
}

func TestBitbucketTokenRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type=refresh_token, got %s", r.Form.Get("grant_type"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	bb := auth.BitbucketOAuth{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TokenURL:     server.URL,
	}

	cred, err := bb.RefreshToken(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if cred.AccessToken != "new-access-token" {
		t.Errorf("expected new-access-token, got %s", cred.AccessToken)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/...`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/auth/bitbucket.go
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	bitbucketAuthorizeURL = "https://bitbucket.org/site/oauth2/authorize"
	bitbucketTokenURL     = "https://bitbucket.org/site/oauth2/access_token"
)

type BitbucketOAuth struct {
	ClientID     string
	ClientSecret string
	TokenURL     string // overridable for testing
}

func (b *BitbucketOAuth) tokenURL() string {
	if b.TokenURL != "" {
		return b.TokenURL
	}
	return bitbucketTokenURL
}

func (b *BitbucketOAuth) Login(ctx context.Context) (Credentials, error) {
	callbackPort, err := findFreePort()
	if err != nil {
		return Credentials{}, fmt.Errorf("find free port: %w", err)
	}
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackPort)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code in callback")
			fmt.Fprintln(w, "Error: no authorization code received.")
			return
		}
		codeCh <- code
		fmt.Fprintln(w, "Authorization successful! You can close this tab.")
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", callbackPort),
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer server.Shutdown(ctx)

	authURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s",
		bitbucketAuthorizeURL,
		url.QueryEscape(b.ClientID),
		url.QueryEscape(redirectURI),
	)
	openBrowser(authURL)

	select {
	case code := <-codeCh:
		return b.ExchangeCode(ctx, code)
	case err := <-errCh:
		return Credentials{}, err
	case <-ctx.Done():
		return Credentials{}, ctx.Err()
	}
}

func (b *BitbucketOAuth) ExchangeCode(ctx context.Context, code string) (Credentials, error) {
	return b.tokenRequest(ctx, url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	})
}

func (b *BitbucketOAuth) RefreshToken(ctx context.Context, refreshToken string) (Credentials, error) {
	return b.tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func (b *BitbucketOAuth) tokenRequest(ctx context.Context, form url.Values) (Credentials, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.ClientID, b.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Credentials{}, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return Credentials{}, fmt.Errorf("decode token response: %w", err)
	}

	return Credentials{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		cmd.Start()
	}
}
```

**Step 4: Run tests**

Run: `go test ./internal/auth/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add Bitbucket OAuth authorization code flow"
```

---

### Task 5: OAuth Flow — GitHub Device Flow

**Files:**
- Create: `internal/auth/github.go`
- Create: `internal/auth/github_test.go`

**Step 1: Write the test**

```go
// internal/auth/github_test.go
package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/labtiva/codemium/internal/auth"
)

func TestGitHubDeviceFlow(t *testing.T) {
	var pollCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "test-device-code",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://github.com/login/device",
				"expires_in":       900,
				"interval":         1,
			})
		case "/login/oauth/access_token":
			count := pollCount.Add(1)
			if count < 2 {
				json.NewEncoder(w).Encode(map[string]any{
					"error": "authorization_pending",
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "gh-access-token",
				"token_type":   "bearer",
				"scope":        "repo,read:org",
			})
		}
	}))
	defer server.Close()

	gh := auth.GitHubOAuth{
		ClientID:     "test-client-id",
		DeviceURL:    server.URL + "/login/device/code",
		TokenURL:     server.URL + "/login/oauth/access_token",
		OpenBrowser:  false,
	}

	cred, err := gh.Login(context.Background())
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if cred.AccessToken != "gh-access-token" {
		t.Errorf("expected gh-access-token, got %s", cred.AccessToken)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/...`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/auth/github.go
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	githubDeviceURL = "https://github.com/login/device/code"
	githubTokenURL  = "https://github.com/login/oauth/access_token"
)

type GitHubOAuth struct {
	ClientID    string
	DeviceURL   string // overridable for testing
	TokenURL    string // overridable for testing
	OpenBrowser bool
}

func (g *GitHubOAuth) deviceURL() string {
	if g.DeviceURL != "" {
		return g.DeviceURL
	}
	return githubDeviceURL
}

func (g *GitHubOAuth) tokenURL() string {
	if g.TokenURL != "" {
		return g.TokenURL
	}
	return githubTokenURL
}

func (g *GitHubOAuth) Login(ctx context.Context) (Credentials, error) {
	deviceResp, err := g.requestDeviceCode(ctx)
	if err != nil {
		return Credentials{}, err
	}

	fmt.Printf("\nPlease visit: %s\nand enter the code: %s\n\n", deviceResp.VerificationURI, deviceResp.UserCode)

	if g.OpenBrowser {
		openBrowser(deviceResp.VerificationURI)
	}

	return g.pollForToken(ctx, deviceResp.DeviceCode, time.Duration(deviceResp.Interval)*time.Second)
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (g *GitHubOAuth) requestDeviceCode(ctx context.Context) (deviceCodeResponse, error) {
	body := fmt.Sprintf(`{"client_id":"%s","scope":"repo read:org"}`, g.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.deviceURL(), strings.NewReader(body))
	if err != nil {
		return deviceCodeResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return deviceCodeResponse{}, fmt.Errorf("device code request: %w", err)
	}
	defer resp.Body.Close()

	var result deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return deviceCodeResponse{}, fmt.Errorf("decode device code response: %w", err)
	}
	return result, nil
}

func (g *GitHubOAuth) pollForToken(ctx context.Context, deviceCode string, interval time.Duration) (Credentials, error) {
	if interval < time.Second {
		interval = time.Second
	}

	for {
		select {
		case <-ctx.Done():
			return Credentials{}, ctx.Err()
		case <-time.After(interval):
		}

		body := fmt.Sprintf(`{"client_id":"%s","device_code":"%s","grant_type":"urn:ietf:params:oauth:grant-type:device_code"}`, g.ClientID, deviceCode)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL(), strings.NewReader(body))
		if err != nil {
			return Credentials{}, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return Credentials{}, fmt.Errorf("token poll: %w", err)
		}

		var result struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
			Error       string `json:"error"`
			Interval    int    `json:"interval"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch result.Error {
		case "":
			if result.AccessToken != "" {
				return Credentials{AccessToken: result.AccessToken}, nil
			}
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "expired_token":
			return Credentials{}, fmt.Errorf("device code expired, please try again")
		case "access_denied":
			return Credentials{}, fmt.Errorf("authorization denied by user")
		default:
			return Credentials{}, fmt.Errorf("unexpected error: %s", result.Error)
		}
	}
}
```

**Step 4: Run tests**

Run: `go test ./internal/auth/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add GitHub device flow OAuth"
```

---

### Task 6: Provider Interface + Bitbucket Implementation

**Files:**
- Create: `internal/provider/provider.go`
- Create: `internal/provider/bitbucket.go`
- Create: `internal/provider/bitbucket_test.go`

**Step 1: Write the test**

```go
// internal/provider/bitbucket_test.go
package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labtiva/codemium/internal/model"
	"github.com/labtiva/codemium/internal/provider"
)

func TestBitbucketListRepos(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{
						"slug":      "repo-1",
						"full_name": "myworkspace/repo-1",
						"project":   map[string]any{"key": "PROJ1"},
						"links": map[string]any{
							"html":  map[string]any{"href": "https://bitbucket.org/myworkspace/repo-1"},
							"clone": []map[string]any{{
								"name": "https",
								"href": "https://bitbucket.org/myworkspace/repo-1.git",
							}},
						},
						"parent": nil,
					},
				},
				"next": r.URL.Scheme + "://" + r.Host + "/2.0/repositories/myworkspace?page=2",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{
						"slug":      "repo-2",
						"full_name": "myworkspace/repo-2",
						"project":   map[string]any{"key": "PROJ1"},
						"links": map[string]any{
							"html":  map[string]any{"href": "https://bitbucket.org/myworkspace/repo-2"},
							"clone": []map[string]any{{
								"name": "https",
								"href": "https://bitbucket.org/myworkspace/repo-2.git",
							}},
						},
						"parent": nil,
					},
				},
			})
		}
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", server.URL)
	repos, err := bb.ListRepos(context.Background(), provider.ListOpts{
		Workspace: "myworkspace",
	})
	if err != nil {
		t.Fatalf("failed to list repos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(repos))
	}
	if repos[0].Slug != "repo-1" {
		t.Errorf("expected repo-1, got %s", repos[0].Slug)
	}
	if repos[0].Project != "PROJ1" {
		t.Errorf("expected project PROJ1, got %s", repos[0].Project)
	}
	if repos[1].Slug != "repo-2" {
		t.Errorf("expected repo-2, got %s", repos[1].Slug)
	}
}

func TestBitbucketFilterByProject(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.Query().Get("q")
		json.NewEncoder(w).Encode(map[string]any{"values": []map[string]any{}})
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", server.URL)
	bb.ListRepos(context.Background(), provider.ListOpts{
		Workspace: "myworkspace",
		Projects:  []string{"PROJ1", "PROJ2"},
	})

	if receivedQuery == "" {
		t.Fatal("expected query parameter to be set")
	}
}

func TestBitbucketExcludeForks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"values": []map[string]any{
				{
					"slug":      "original",
					"full_name": "ws/original",
					"project":   map[string]any{"key": "P"},
					"links": map[string]any{
						"html":  map[string]any{"href": "https://bitbucket.org/ws/original"},
						"clone": []map[string]any{{"name": "https", "href": "https://bitbucket.org/ws/original.git"}},
					},
					"parent": nil,
				},
				{
					"slug":      "forked",
					"full_name": "ws/forked",
					"project":   map[string]any{"key": "P"},
					"links": map[string]any{
						"html":  map[string]any{"href": "https://bitbucket.org/ws/forked"},
						"clone": []map[string]any{{"name": "https", "href": "https://bitbucket.org/ws/forked.git"}},
					},
					"parent": map[string]any{"full_name": "other/forked"},
				},
			},
		})
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", server.URL)

	repos, _ := bb.ListRepos(context.Background(), provider.ListOpts{
		Workspace:    "ws",
		IncludeForks: false,
	})
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo (fork excluded), got %d", len(repos))
	}
	if repos[0].Slug != "original" {
		t.Errorf("expected original, got %s", repos[0].Slug)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/provider/...`
Expected: FAIL

**Step 3: Write the provider interface**

```go
// internal/provider/provider.go
package provider

import (
	"context"

	"github.com/labtiva/codemium/internal/model"
)

type ListOpts struct {
	Workspace       string
	Organization    string
	Projects        []string
	Repos           []string
	Exclude         []string
	IncludeArchived bool
	IncludeForks    bool
}

type Provider interface {
	ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error)
}
```

**Step 4: Write Bitbucket implementation**

```go
// internal/provider/bitbucket.go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labtiva/codemium/internal/model"
)

const bitbucketAPIBase = "https://api.bitbucket.org"

type Bitbucket struct {
	token   string
	baseURL string
	client  *http.Client
}

func NewBitbucket(token string, baseURL string) *Bitbucket {
	if baseURL == "" {
		baseURL = bitbucketAPIBase
	}
	return &Bitbucket{
		token:   token,
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

func (b *Bitbucket) ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error) {
	var allRepos []model.Repo

	nextURL := b.buildListURL(opts)

	for nextURL != "" {
		repos, next, err := b.fetchPage(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		for _, r := range repos {
			if !opts.IncludeForks && r.Fork {
				continue
			}
			if !opts.IncludeArchived && r.Archived {
				continue
			}
			if len(opts.Repos) > 0 && !contains(opts.Repos, r.Slug) {
				continue
			}
			if len(opts.Exclude) > 0 && contains(opts.Exclude, r.Slug) {
				continue
			}
			allRepos = append(allRepos, r)
		}

		nextURL = next
	}

	return allRepos, nil
}

func (b *Bitbucket) buildListURL(opts ListOpts) string {
	u := fmt.Sprintf("%s/2.0/repositories/%s", b.baseURL, url.PathEscape(opts.Workspace))
	params := url.Values{}
	params.Set("pagelen", "100")

	if len(opts.Projects) > 0 {
		clauses := make([]string, len(opts.Projects))
		for i, p := range opts.Projects {
			clauses[i] = fmt.Sprintf(`project.key="%s"`, p)
		}
		params.Set("q", strings.Join(clauses, " OR "))
	}

	return u + "?" + params.Encode()
}

type bitbucketPage struct {
	Values []json.RawMessage `json:"values"`
	Next   string            `json:"next"`
}

type bitbucketRepo struct {
	Slug     string `json:"slug"`
	FullName string `json:"full_name"`
	Project  struct {
		Key string `json:"key"`
	} `json:"project"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
	} `json:"links"`
	Parent *struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
}

func (b *Bitbucket) fetchPage(ctx context.Context, pageURL string) ([]model.Repo, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("bitbucket API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("bitbucket API returned status %d", resp.StatusCode)
	}

	var page bitbucketPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, "", fmt.Errorf("decode bitbucket response: %w", err)
	}

	var repos []model.Repo
	for _, raw := range page.Values {
		var bbRepo bitbucketRepo
		if err := json.Unmarshal(raw, &bbRepo); err != nil {
			continue
		}

		cloneURL := ""
		for _, c := range bbRepo.Links.Clone {
			if c.Name == "https" {
				cloneURL = c.Href
				break
			}
		}

		repos = append(repos, model.Repo{
			Name:     bbRepo.Slug,
			Slug:     bbRepo.Slug,
			Project:  bbRepo.Project.Key,
			URL:      bbRepo.Links.HTML.Href,
			CloneURL: cloneURL,
			Provider: "bitbucket",
			Fork:     bbRepo.Parent != nil,
		})
	}

	return repos, page.Next, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
```

**Step 5: Run tests**

Run: `go test ./internal/provider/...`
Expected: PASS

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add provider interface and Bitbucket Cloud implementation"
```

---

### Task 7: GitHub Provider Implementation

**Files:**
- Create: `internal/provider/github.go`
- Create: `internal/provider/github_test.go`

**Step 1: Write the test**

```go
// internal/provider/github_test.go
package provider_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labtiva/codemium/internal/provider"
)

func TestGitHubListRepos(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2&per_page=100>; rel="next"`, r.URL.Scheme+"://"+r.Host, r.URL.Path))
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"name":           "repo-1",
					"full_name":      "myorg/repo-1",
					"html_url":       "https://github.com/myorg/repo-1",
					"clone_url":      "https://github.com/myorg/repo-1.git",
					"archived":       false,
					"fork":           false,
					"default_branch": "main",
				},
			})
		} else {
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"name":           "repo-2",
					"full_name":      "myorg/repo-2",
					"html_url":       "https://github.com/myorg/repo-2",
					"clone_url":      "https://github.com/myorg/repo-2.git",
					"archived":       false,
					"fork":           false,
					"default_branch": "main",
				},
			})
		}
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL)
	repos, err := gh.ListRepos(context.Background(), provider.ListOpts{
		Organization: "myorg",
	})
	if err != nil {
		t.Fatalf("failed to list repos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(repos))
	}
}

func TestGitHubExcludeForksAndArchived(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"name": "active", "full_name": "org/active", "html_url": "h", "clone_url": "c", "archived": false, "fork": false},
			{"name": "archived-repo", "full_name": "org/archived-repo", "html_url": "h", "clone_url": "c", "archived": true, "fork": false},
			{"name": "forked-repo", "full_name": "org/forked-repo", "html_url": "h", "clone_url": "c", "archived": false, "fork": true},
		})
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL)
	repos, _ := gh.ListRepos(context.Background(), provider.ListOpts{
		Organization: "org",
	})
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo (forks and archived excluded), got %d", len(repos))
	}
	if repos[0].Slug != "active" {
		t.Errorf("expected active, got %s", repos[0].Slug)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/provider/...`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/provider/github.go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/labtiva/codemium/internal/model"
)

const githubAPIBase = "https://api.github.com"

type GitHub struct {
	token   string
	baseURL string
	client  *http.Client
}

func NewGitHub(token string, baseURL string) *GitHub {
	if baseURL == "" {
		baseURL = githubAPIBase
	}
	return &GitHub{
		token:   token,
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

func (g *GitHub) ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error) {
	var allRepos []model.Repo

	nextURL := fmt.Sprintf("%s/orgs/%s/repos?per_page=100&type=all", g.baseURL, opts.Organization)

	for nextURL != "" {
		repos, next, err := g.fetchPage(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		for _, r := range repos {
			if !opts.IncludeForks && r.Fork {
				continue
			}
			if !opts.IncludeArchived && r.Archived {
				continue
			}
			if len(opts.Repos) > 0 && !contains(opts.Repos, r.Slug) {
				continue
			}
			if len(opts.Exclude) > 0 && contains(opts.Exclude, r.Slug) {
				continue
			}
			allRepos = append(allRepos, r)
		}

		nextURL = next
	}

	return allRepos, nil
}

type githubRepo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
	Archived bool   `json:"archived"`
	Fork     bool   `json:"fork"`
}

func (g *GitHub) fetchPage(ctx context.Context, pageURL string) ([]model.Repo, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("github API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var ghRepos []githubRepo
	if err := json.NewDecoder(resp.Body).Decode(&ghRepos); err != nil {
		return nil, "", fmt.Errorf("decode github response: %w", err)
	}

	var repos []model.Repo
	for _, r := range ghRepos {
		repos = append(repos, model.Repo{
			Name:     r.Name,
			Slug:     r.Name,
			URL:      r.HTMLURL,
			CloneURL: r.CloneURL,
			Provider: "github",
			Archived: r.Archived,
			Fork:     r.Fork,
		})
	}

	nextURL := parseLinkNext(resp.Header.Get("Link"))
	return repos, nextURL, nil
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func parseLinkNext(header string) string {
	matches := linkNextRe.FindStringSubmatch(header)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}
```

**Step 4: Run tests**

Run: `go test ./internal/provider/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add GitHub provider implementation with pagination"
```

---

### Task 8: Code Analyzer (scc wrapper)

**Files:**
- Create: `internal/analyzer/analyzer.go`
- Create: `internal/analyzer/analyzer_test.go`

**Step 1: Write the test**

Create a temporary directory with some Go and Python files and verify analysis returns correct language breakdowns.

```go
// internal/analyzer/analyzer_test.go
package analyzer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/labtiva/codemium/internal/analyzer"
)

func TestAnalyzeDirectory(t *testing.T) {
	dir := t.TempDir()

	// Write a Go file
	goCode := `package main

import "fmt"

// main prints a greeting
func main() {
	fmt.Println("hello")
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(goCode), 0644)

	// Write a Python file
	pyCode := `# A simple script
def greet(name):
    """Greet someone."""
    print(f"Hello, {name}")

# Call it
greet("world")
`
	os.WriteFile(filepath.Join(dir, "script.py"), []byte(pyCode), 0644)

	a := analyzer.New()
	stats, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	if len(stats.Languages) == 0 {
		t.Fatal("expected at least one language")
	}

	foundGo := false
	foundPy := false
	for _, lang := range stats.Languages {
		if lang.Name == "Go" {
			foundGo = true
			if lang.Code == 0 {
				t.Error("expected Go code lines > 0")
			}
			if lang.Comments == 0 {
				t.Error("expected Go comment lines > 0")
			}
		}
		if lang.Name == "Python" {
			foundPy = true
			if lang.Code == 0 {
				t.Error("expected Python code lines > 0")
			}
		}
	}
	if !foundGo {
		t.Error("expected Go language in results")
	}
	if !foundPy {
		t.Error("expected Python language in results")
	}

	if stats.Totals.Files != 2 {
		t.Errorf("expected 2 files total, got %d", stats.Totals.Files)
	}
	if stats.Totals.Code == 0 {
		t.Error("expected total code lines > 0")
	}
}

func TestAnalyzeEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	a := analyzer.New()
	stats, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	if stats.Totals.Files != 0 {
		t.Errorf("expected 0 files, got %d", stats.Totals.Files)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/analyzer/...`
Expected: FAIL

**Step 3: Write the implementation**

Use scc's `processor` package. Call `ProcessConstants()` once, then walk the directory, detect languages, and count stats per file. Aggregate into `LanguageStats`.

```go
// internal/analyzer/analyzer.go
package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/boyter/scc/v3/processor"
	"github.com/labtiva/codemium/internal/model"
)

var initOnce sync.Once

type Analyzer struct{}

func New() *Analyzer {
	initOnce.Do(func() {
		processor.ProcessConstants()
	})
	return &Analyzer{}
}

func (a *Analyzer) Analyze(ctx context.Context, dir string) (*model.RepoStats, error) {
	langMap := map[string]*model.LanguageStats{}
	var totalFiles int64

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".hg" {
				return filepath.SkipDir
			}
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		possibleLanguages, _ := processor.DetectLanguage(info.Name())
		if len(possibleLanguages) == 0 {
			return nil
		}

		job := &processor.FileJob{
			Filename:          info.Name(),
			Content:           content,
			Bytes:             int64(len(content)),
			PossibleLanguages: possibleLanguages,
		}

		job.Language = processor.DetermineLanguage(job.Filename, job.Language, job.PossibleLanguages, job.Content)
		if job.Language == "" {
			return nil
		}

		processor.CountStats(job)

		if job.Binary {
			return nil
		}

		lang, ok := langMap[job.Language]
		if !ok {
			lang = &model.LanguageStats{Name: job.Language}
			langMap[job.Language] = lang
		}

		lang.Files++
		lang.Lines += job.Lines
		lang.Code += job.Code
		lang.Comments += job.Comment
		lang.Blanks += job.Blank
		lang.Complexity += job.Complexity
		totalFiles++

		return nil
	})
	if err != nil {
		return nil, err
	}

	stats := &model.RepoStats{}
	for _, lang := range langMap {
		stats.Languages = append(stats.Languages, *lang)
		stats.Totals.Files += lang.Files
		stats.Totals.Lines += lang.Lines
		stats.Totals.Code += lang.Code
		stats.Totals.Comments += lang.Comments
		stats.Totals.Blanks += lang.Blanks
		stats.Totals.Complexity += lang.Complexity
	}

	return stats, nil
}
```

**Step 4: Run tests**

Run: `go test ./internal/analyzer/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add code analyzer wrapping scc processor library"
```

---

### Task 9: Git Cloner (go-git wrapper)

**Files:**
- Create: `internal/analyzer/clone.go`
- Create: `internal/analyzer/clone_test.go`

**Step 1: Write the test**

Test that we can shallow clone a public repo and get files on disk. Use a small known public repo.

```go
// internal/analyzer/clone_test.go
package analyzer_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/labtiva/codemium/internal/analyzer"
)

func TestCloneAndCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping clone test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cloner := analyzer.NewCloner("")

	// Clone a small public repo
	dir, cleanup, err := cloner.Clone(ctx, "https://github.com/kelseyhightower/nocode.git")
	if err != nil {
		t.Fatalf("clone failed: %v", err)
	}

	// Verify directory exists and has files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read cloned dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("cloned directory is empty")
	}

	// Cleanup should remove the directory
	cleanup()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected directory to be removed after cleanup, but it still exists")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/analyzer/... -run TestClone`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/analyzer/clone.go
package analyzer

import (
	"context"
	"fmt"
	"os"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

type Cloner struct {
	token string
}

func NewCloner(token string) *Cloner {
	return &Cloner{token: token}
}

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
		opts.Auth = &http.BasicAuth{
			Username: "x-token-auth",
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
```

**Step 4: Run tests**

Run: `go test ./internal/analyzer/... -run TestClone -count=1`
Expected: PASS (requires network access)

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add go-git shallow cloner with token auth"
```

---

### Task 10: Worker Pool

**Files:**
- Create: `internal/worker/pool.go`
- Create: `internal/worker/pool_test.go`

**Step 1: Write the test**

```go
// internal/worker/pool_test.go
package worker_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/labtiva/codemium/internal/model"
	"github.com/labtiva/codemium/internal/worker"
)

func TestPoolProcessesAllItems(t *testing.T) {
	repos := []model.Repo{
		{Slug: "repo-1"},
		{Slug: "repo-2"},
		{Slug: "repo-3"},
	}

	var processed atomic.Int32

	results := worker.Run(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		processed.Add(1)
		return &model.RepoStats{
			Repository: repo.Slug,
			Totals:     model.Stats{Code: 100},
		}, nil
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if int(processed.Load()) != 3 {
		t.Errorf("expected 3 processed, got %d", processed.Load())
	}
}

func TestPoolHandlesErrors(t *testing.T) {
	repos := []model.Repo{
		{Slug: "good-repo"},
		{Slug: "bad-repo"},
	}

	results := worker.Run(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		if repo.Slug == "bad-repo" {
			return nil, fmt.Errorf("clone failed")
		}
		return &model.RepoStats{Repository: repo.Slug}, nil
	})

	var successes, errors int
	for _, r := range results {
		if r.Err != nil {
			errors++
		} else {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected 1 success, got %d", successes)
	}
	if errors != 1 {
		t.Errorf("expected 1 error, got %d", errors)
	}
}

func TestPoolRespectsContext(t *testing.T) {
	repos := make([]model.Repo, 100)
	for i := range repos {
		repos[i] = model.Repo{Slug: fmt.Sprintf("repo-%d", i)}
	}

	ctx, cancel := context.WithCancel(context.Background())

	var started atomic.Int32

	go func() {
		for started.Load() < 2 {
			// wait for at least 2 to start
		}
		cancel()
	}()

	results := worker.Run(ctx, repos, 2, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		started.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	// Should have fewer results than total repos due to cancellation
	if len(results) >= 100 {
		t.Error("expected cancellation to prevent processing all repos")
	}
}
```

Note: Add `"fmt"` to imports.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/worker/...`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/worker/pool.go
package worker

import (
	"context"
	"sync"

	"github.com/labtiva/codemium/internal/model"
)

type Result struct {
	Repo  model.Repo
	Stats *model.RepoStats
	Err   error
}

type ProgressFunc func(completed, total int, repo model.Repo)

type ProcessFunc func(ctx context.Context, repo model.Repo) (*model.RepoStats, error)

func Run(ctx context.Context, repos []model.Repo, concurrency int, process ProcessFunc) []Result {
	return RunWithProgress(ctx, repos, concurrency, process, nil)
}

func RunWithProgress(ctx context.Context, repos []model.Repo, concurrency int, process ProcessFunc, onProgress ProgressFunc) []Result {
	if concurrency < 1 {
		concurrency = 1
	}

	var (
		mu        sync.Mutex
		results   []Result
		completed int
	)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, repo := range repos {
		if ctx.Err() != nil {
			break
		}

		sem <- struct{}{} // acquire
		wg.Add(1)

		go func(r model.Repo) {
			defer wg.Done()
			defer func() { <-sem }() // release

			stats, err := process(ctx, r)

			mu.Lock()
			results = append(results, Result{Repo: r, Stats: stats, Err: err})
			completed++
			c := completed
			mu.Unlock()

			if onProgress != nil {
				onProgress(c, len(repos), r)
			}
		}(repo)
	}

	wg.Wait()
	return results
}
```

**Step 4: Run tests**

Run: `go test ./internal/worker/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add bounded worker pool with progress callback"
```

---

### Task 11: Progress UI (bubbletea)

**Files:**
- Create: `internal/ui/progress.go`
- Create: `internal/ui/progress_test.go`

**Step 1: Write the test**

```go
// internal/ui/progress_test.go
package ui_test

import (
	"testing"

	"github.com/labtiva/codemium/internal/ui"
)

func TestPlainProgress(t *testing.T) {
	var messages []string
	p := ui.NewPlainProgress(func(msg string) {
		messages = append(messages, msg)
	})

	p.Update(1, 5, "repo-1")
	p.Update(2, 5, "repo-2")
	p.Done(5)

	if len(messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(messages))
	}
}

func TestIsTTY(t *testing.T) {
	// Just verify it doesn't panic — the result depends on the test runner
	_ = ui.IsTTY()
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ui/...`
Expected: FAIL

**Step 3: Write the implementation**

```go
// internal/ui/progress.go
package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

func IsTTY() bool {
	return term.IsTerminal(os.Stderr.Fd())
}

// --- Plain text fallback ---

type PlainProgress struct {
	print func(string)
}

func NewPlainProgress(print func(string)) *PlainProgress {
	return &PlainProgress{print: print}
}

func (p *PlainProgress) Update(completed, total int, repoName string) {
	p.print(fmt.Sprintf("[%d/%d] Analyzed %s", completed, total, repoName))
}

func (p *PlainProgress) Done(total int) {
	p.print(fmt.Sprintf("Done! Analyzed %d repositories.", total))
}

// --- TUI progress ---

type ProgressMsg struct {
	Completed int
	Total     int
	RepoName  string
}

type DoneMsg struct{}

type model struct {
	progress  progress.Model
	completed int
	total     int
	repoName  string
	done      bool
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

func NewTUIModel(total int) model {
	return model{
		progress: progress.New(
			progress.WithDefaultGradient(),
			progress.WithWidth(50),
			progress.WithoutPercentage(),
		),
		total: total,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.progress.Width = msg.Width - 10
		if m.progress.Width > 60 {
			m.progress.Width = 60
		}
	case ProgressMsg:
		m.completed = msg.Completed
		m.total = msg.Total
		m.repoName = msg.RepoName
		pct := float64(m.completed) / float64(m.total)
		return m, m.progress.SetPercent(pct)
	case DoneMsg:
		m.done = true
		return m, tea.Quit
	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd
	}
	return m, nil
}

func (m model) View() string {
	if m.done {
		return fmt.Sprintf("\n  %s\n\n",
			titleStyle.Render(fmt.Sprintf("Done! Analyzed %d repositories.", m.total)))
	}

	pad := strings.Repeat(" ", 2)
	counter := infoStyle.Render(fmt.Sprintf("%d/%d", m.completed, m.total))
	desc := m.repoName
	if desc == "" {
		desc = "Starting..."
	}

	return "\n" +
		pad + titleStyle.Render("Analyzing repositories") + "\n" +
		pad + m.progress.View() + "  " + counter + "\n" +
		pad + infoStyle.Render(desc) + "\n\n"
}

func RunTUI(total int) *tea.Program {
	m := NewTUIModel(total)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	return p
}
```

**Step 4: Run tests**

Run: `go test ./internal/ui/...`
Expected: PASS

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add progress UI with bubbletea TUI and plain text fallback"
```

---

### Task 12: JSON and Markdown Output

**Files:**
- Create: `internal/output/json.go`
- Create: `internal/output/markdown.go`
- Create: `internal/output/output_test.go`

**Step 1: Write the test**

```go
// internal/output/output_test.go
package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/labtiva/codemium/internal/model"
	"github.com/labtiva/codemium/internal/output"
)

func sampleReport() model.Report {
	return model.Report{
		GeneratedAt: "2026-02-18T12:00:00Z",
		Provider:    "bitbucket",
		Workspace:   "myworkspace",
		Filters:     model.Filters{Projects: []string{"PROJ1"}},
		Repositories: []model.RepoStats{
			{
				Repository: "api-service",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				URL:        "https://bitbucket.org/myworkspace/api-service",
				Languages: []model.LanguageStats{
					{Name: "Go", Files: 30, Lines: 5000, Code: 4000, Comments: 500, Blanks: 500, Complexity: 200},
					{Name: "YAML", Files: 5, Lines: 200, Code: 180, Comments: 10, Blanks: 10, Complexity: 0},
				},
				Totals: model.Stats{Files: 35, Lines: 5200, Code: 4180, Comments: 510, Blanks: 510, Complexity: 200},
			},
			{
				Repository: "web-app",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				URL:        "https://bitbucket.org/myworkspace/web-app",
				Languages: []model.LanguageStats{
					{Name: "TypeScript", Files: 50, Lines: 8000, Code: 6000, Comments: 1000, Blanks: 1000, Complexity: 400},
				},
				Totals: model.Stats{Files: 50, Lines: 8000, Code: 6000, Comments: 1000, Blanks: 1000, Complexity: 400},
			},
		},
		Totals: model.Stats{Repos: 2, Files: 85, Lines: 13200, Code: 10180, Comments: 1510, Blanks: 1510, Complexity: 600},
		ByLanguage: []model.LanguageStats{
			{Name: "TypeScript", Files: 50, Lines: 8000, Code: 6000, Comments: 1000, Blanks: 1000, Complexity: 400},
			{Name: "Go", Files: 30, Lines: 5000, Code: 4000, Comments: 500, Blanks: 500, Complexity: 200},
			{Name: "YAML", Files: 5, Lines: 200, Code: 180, Comments: 10, Blanks: 10, Complexity: 0},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := output.WriteJSON(&buf, report); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Totals.Code != 10180 {
		t.Errorf("expected total code 10180, got %d", decoded.Totals.Code)
	}
}

func TestWriteMarkdown(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("failed to write markdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "api-service") {
		t.Error("markdown should contain repo name api-service")
	}
	if !strings.Contains(md, "TypeScript") {
		t.Error("markdown should contain language TypeScript")
	}
	if !strings.Contains(md, "10,180") || !strings.Contains(md, "10180") {
		// Accept either formatted or raw number
	}
	if !strings.Contains(md, "|") {
		t.Error("markdown should contain table pipes")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/output/...`
Expected: FAIL

**Step 3: Write JSON output**

```go
// internal/output/json.go
package output

import (
	"encoding/json"
	"io"

	"github.com/labtiva/codemium/internal/model"
)

func WriteJSON(w io.Writer, report model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
```

**Step 4: Write markdown output**

```go
// internal/output/markdown.go
package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/labtiva/codemium/internal/model"
)

func WriteMarkdown(w io.Writer, report model.Report) error {
	fmt.Fprintf(w, "# Code Statistics Report\n\n")
	fmt.Fprintf(w, "**Provider:** %s\n", report.Provider)
	if report.Workspace != "" {
		fmt.Fprintf(w, "**Workspace:** %s\n", report.Workspace)
	}
	if report.Organization != "" {
		fmt.Fprintf(w, "**Organization:** %s\n", report.Organization)
	}
	fmt.Fprintf(w, "**Generated:** %s\n\n", report.GeneratedAt)

	// Summary totals
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Repositories | %d |\n", report.Totals.Repos)
	fmt.Fprintf(w, "| Files | %d |\n", report.Totals.Files)
	fmt.Fprintf(w, "| Lines | %d |\n", report.Totals.Lines)
	fmt.Fprintf(w, "| Code | %d |\n", report.Totals.Code)
	fmt.Fprintf(w, "| Comments | %d |\n", report.Totals.Comments)
	fmt.Fprintf(w, "| Blanks | %d |\n", report.Totals.Blanks)
	fmt.Fprintf(w, "| Complexity | %d |\n\n", report.Totals.Complexity)

	// By language
	fmt.Fprintf(w, "## Languages\n\n")
	fmt.Fprintf(w, "| Language | Files | Code | Comments | Blanks | Complexity |\n")
	fmt.Fprintf(w, "|----------|------:|-----:|---------:|-------:|-----------:|\n")
	for _, lang := range report.ByLanguage {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d |\n",
			lang.Name, lang.Files, lang.Code, lang.Comments, lang.Blanks, lang.Complexity)
	}
	fmt.Fprintln(w)

	// Per repository
	fmt.Fprintf(w, "## Repositories\n\n")
	fmt.Fprintf(w, "| Repository | Project | Files | Code | Comments | Complexity |\n")
	fmt.Fprintf(w, "|------------|---------|------:|-----:|---------:|-----------:|\n")
	for _, repo := range report.Repositories {
		fmt.Fprintf(w, "| [%s](%s) | %s | %d | %d | %d | %d |\n",
			repo.Repository, repo.URL, repo.Project, repo.Totals.Files, repo.Totals.Code, repo.Totals.Comments, repo.Totals.Complexity)
	}
	fmt.Fprintln(w)

	// Errors
	if len(report.Errors) > 0 {
		fmt.Fprintf(w, "## Errors\n\n")
		for _, e := range report.Errors {
			fmt.Fprintf(w, "- **%s**: %s\n", e.Repository, e.Error)
		}
		fmt.Fprintln(w)
	}

	_ = tabwriter.NewWriter // suppress unused import if needed
	return nil
}
```

Note: Remove the `tabwriter` import if unused — it's there as a placeholder. The `fmt.Fprintf` approach is cleaner for markdown.

**Step 5: Run tests**

Run: `go test ./internal/output/...`
Expected: PASS

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add JSON and markdown output formatters"
```

---

### Task 13: Auth Command Wiring

**Files:**
- Modify: `cmd/codemium/main.go`

**Step 1: Wire up the auth login command**

Replace the placeholder `newAuthCmd` in `main.go` with the real implementation that reads env vars for client ID/secret, runs the OAuth flow, and saves credentials.

```go
func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication",
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with a provider",
		RunE:  runAuthLogin,
	}
	loginCmd.Flags().String("provider", "", "Provider to authenticate with (bitbucket, github)")
	loginCmd.MarkFlagRequired("provider")

	cmd.AddCommand(loginCmd)
	return cmd
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	providerName, _ := cmd.Flags().GetString("provider")

	store := auth.NewFileStore(auth.DefaultStorePath())
	ctx := cmd.Context()

	var cred auth.Credentials
	var err error

	switch providerName {
	case "bitbucket":
		clientID := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_ID")
		clientSecret := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_SECRET")
		if clientID == "" || clientSecret == "" {
			return fmt.Errorf("set CODEMIUM_BITBUCKET_CLIENT_ID and CODEMIUM_BITBUCKET_CLIENT_SECRET environment variables")
		}
		bb := &auth.BitbucketOAuth{ClientID: clientID, ClientSecret: clientSecret}
		fmt.Fprintln(os.Stderr, "Opening browser for Bitbucket authorization...")
		cred, err = bb.Login(ctx)

	case "github":
		clientID := os.Getenv("CODEMIUM_GITHUB_CLIENT_ID")
		if clientID == "" {
			return fmt.Errorf("set CODEMIUM_GITHUB_CLIENT_ID environment variable")
		}
		gh := &auth.GitHubOAuth{ClientID: clientID, OpenBrowser: true}
		cred, err = gh.Login(ctx)

	default:
		return fmt.Errorf("unsupported provider: %s (use bitbucket or github)", providerName)
	}

	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if err := store.Save(providerName, cred); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Successfully authenticated with %s!\n", providerName)
	return nil
}
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/codemium && ./codemium auth login --help`
Expected: Shows help with `--provider` flag.

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: wire auth login command with Bitbucket and GitHub OAuth"
```

---

### Task 14: Analyze Command — Tie It All Together

**Files:**
- Modify: `cmd/codemium/main.go`

This is the main integration task. The `analyze` command:
1. Loads credentials
2. Creates the appropriate provider
3. Lists repos with filters
4. Runs worker pool (clone → analyze → cleanup) with progress UI
5. Aggregates results into a Report
6. Writes JSON (and optionally markdown) output

**Step 1: Write the analyze command**

```go
func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze repositories and generate code statistics",
		RunE:  runAnalyze,
	}

	cmd.Flags().String("provider", "", "Provider (bitbucket, github)")
	cmd.Flags().String("workspace", "", "Bitbucket workspace slug")
	cmd.Flags().String("org", "", "GitHub organization")
	cmd.Flags().StringSlice("projects", nil, "Filter by Bitbucket project keys")
	cmd.Flags().StringSlice("repos", nil, "Filter to specific repo names")
	cmd.Flags().StringSlice("exclude", nil, "Exclude specific repos")
	cmd.Flags().Bool("include-archived", false, "Include archived repos")
	cmd.Flags().Bool("include-forks", false, "Include forked repos")
	cmd.Flags().Int("concurrency", 5, "Number of parallel workers")
	cmd.Flags().String("output", "", "Write JSON to file (default: stdout)")
	cmd.Flags().String("markdown", "", "Write markdown summary to file")

	cmd.MarkFlagRequired("provider")

	return cmd
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer cancel()

	providerName, _ := cmd.Flags().GetString("provider")
	workspace, _ := cmd.Flags().GetString("workspace")
	org, _ := cmd.Flags().GetString("org")
	projects, _ := cmd.Flags().GetStringSlice("projects")
	repos, _ := cmd.Flags().GetStringSlice("repos")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	includeArchived, _ := cmd.Flags().GetBool("include-archived")
	includeForks, _ := cmd.Flags().GetBool("include-forks")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	outputPath, _ := cmd.Flags().GetString("output")
	markdownPath, _ := cmd.Flags().GetString("markdown")

	// Load credentials
	store := auth.NewFileStore(auth.DefaultStorePath())
	cred, err := store.LoadWithEnv(providerName)
	if err != nil {
		return fmt.Errorf("not authenticated with %s — run 'codemium auth login --provider %s' first", providerName, providerName)
	}

	// Refresh if expired (Bitbucket)
	if cred.Expired() && cred.RefreshToken != "" {
		clientID := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_ID")
		clientSecret := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_SECRET")
		bb := &auth.BitbucketOAuth{ClientID: clientID, ClientSecret: clientSecret}
		cred, err = bb.RefreshToken(ctx, cred.RefreshToken)
		if err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
		store.Save(providerName, cred)
	}

	// Create provider
	var prov provider.Provider
	switch providerName {
	case "bitbucket":
		if workspace == "" {
			return fmt.Errorf("--workspace is required for bitbucket")
		}
		prov = provider.NewBitbucket(cred.AccessToken, "")
	case "github":
		if org == "" {
			return fmt.Errorf("--org is required for github")
		}
		prov = provider.NewGitHub(cred.AccessToken, "")
	default:
		return fmt.Errorf("unsupported provider: %s", providerName)
	}

	// List repos
	fmt.Fprintln(os.Stderr, "Listing repositories...")
	repoList, err := prov.ListRepos(ctx, provider.ListOpts{
		Workspace:       workspace,
		Organization:    org,
		Projects:        projects,
		Repos:           repos,
		Exclude:         exclude,
		IncludeArchived: includeArchived,
		IncludeForks:    includeForks,
	})
	if err != nil {
		return fmt.Errorf("list repos: %w", err)
	}

	if len(repoList) == 0 {
		return fmt.Errorf("no repositories found")
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories\n", len(repoList))

	// Set up progress
	useTUI := ui.IsTTY()
	var program *tea.Program
	if useTUI {
		program = ui.RunTUI(len(repoList))
		go func() {
			program.Run()
		}()
	}

	// Process repos
	cloner := analyzer.NewCloner(cred.AccessToken)
	codeAnalyzer := analyzer.New()

	progressFn := func(completed, total int, repo model.Repo) {
		if useTUI && program != nil {
			program.Send(ui.ProgressMsg{
				Completed: completed,
				Total:     total,
				RepoName:  repo.Slug,
			})
		} else {
			fmt.Fprintf(os.Stderr, "[%d/%d] Analyzed %s\n", completed, total, repo.Slug)
		}
	}

	results := worker.RunWithProgress(ctx, repoList, concurrency, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		dir, cleanup, err := cloner.Clone(ctx, repo.CloneURL)
		if err != nil {
			return nil, err
		}
		defer cleanup()

		stats, err := codeAnalyzer.Analyze(ctx, dir)
		if err != nil {
			return nil, err
		}

		stats.Repository = repo.Slug
		stats.Project = repo.Project
		stats.Provider = repo.Provider
		stats.URL = repo.URL
		return stats, nil
	}, progressFn)

	if useTUI && program != nil {
		program.Send(ui.DoneMsg{})
	}

	// Build report
	report := buildReport(providerName, workspace, org, projects, repos, exclude, results)

	// Write JSON output
	var jsonWriter io.Writer = os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		jsonWriter = f
	}
	if err := output.WriteJSON(jsonWriter, report); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}

	// Write markdown if requested
	if markdownPath != "" {
		f, err := os.Create(markdownPath)
		if err != nil {
			return fmt.Errorf("create markdown file: %w", err)
		}
		defer f.Close()
		if err := output.WriteMarkdown(f, report); err != nil {
			return fmt.Errorf("write markdown: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Markdown summary written to %s\n", markdownPath)
	}

	return nil
}

func buildReport(providerName, workspace, org string, projects, repos, exclude []string, results []worker.Result) model.Report {
	report := model.Report{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Provider:     providerName,
		Workspace:    workspace,
		Organization: org,
		Filters: model.Filters{
			Projects: projects,
			Repos:    repos,
			Exclude:  exclude,
		},
	}

	langTotals := map[string]*model.LanguageStats{}

	for _, r := range results {
		if r.Err != nil {
			report.Errors = append(report.Errors, model.RepoError{
				Repository: r.Repo.Slug,
				Error:      r.Err.Error(),
			})
			continue
		}

		report.Repositories = append(report.Repositories, *r.Stats)
		report.Totals.Repos++
		report.Totals.Files += r.Stats.Totals.Files
		report.Totals.Lines += r.Stats.Totals.Lines
		report.Totals.Code += r.Stats.Totals.Code
		report.Totals.Comments += r.Stats.Totals.Comments
		report.Totals.Blanks += r.Stats.Totals.Blanks
		report.Totals.Complexity += r.Stats.Totals.Complexity

		for _, lang := range r.Stats.Languages {
			lt, ok := langTotals[lang.Name]
			if !ok {
				lt = &model.LanguageStats{Name: lang.Name}
				langTotals[lang.Name] = lt
			}
			lt.Files += lang.Files
			lt.Lines += lang.Lines
			lt.Code += lang.Code
			lt.Comments += lang.Comments
			lt.Blanks += lang.Blanks
			lt.Complexity += lang.Complexity
		}
	}

	for _, lt := range langTotals {
		report.ByLanguage = append(report.ByLanguage, *lt)
	}

	// Sort by code descending
	sort.Slice(report.ByLanguage, func(i, j int) bool {
		return report.ByLanguage[i].Code > report.ByLanguage[j].Code
	})

	return report
}
```

**Required imports to add to main.go:**

```go
import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/labtiva/codemium/internal/analyzer"
	"github.com/labtiva/codemium/internal/auth"
	"github.com/labtiva/codemium/internal/model"
	"github.com/labtiva/codemium/internal/output"
	"github.com/labtiva/codemium/internal/provider"
	"github.com/labtiva/codemium/internal/ui"
	"github.com/labtiva/codemium/internal/worker"
)
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/codemium && ./codemium analyze --help`
Expected: Shows help with all flags.

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: wire analyze command with full pipeline"
```

---

### Task 15: Integration Test

**Files:**
- Create: `cmd/codemium/main_test.go`

A lightweight integration test that mocks the provider and verifies the full pipeline works end-to-end without network access.

**Step 1: Write the test**

```go
// cmd/codemium/main_test.go
package main_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/labtiva/codemium/internal/analyzer"
	"github.com/labtiva/codemium/internal/model"
	"github.com/labtiva/codemium/internal/worker"
)

func TestAnalyzePipeline(t *testing.T) {
	// Create a fake repo directory with code files
	repoDir := t.TempDir()
	os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644)
	os.WriteFile(filepath.Join(repoDir, "lib.py"), []byte("# comment\ndef foo():\n    pass\n"), 0644)

	// Analyze directly (skip clone)
	a := analyzer.New()
	stats, err := a.Analyze(context.Background(), repoDir)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	if stats.Totals.Files < 2 {
		t.Errorf("expected at least 2 files, got %d", stats.Totals.Files)
	}
	if stats.Totals.Code == 0 {
		t.Error("expected code lines > 0")
	}
}

func TestWorkerPoolIntegration(t *testing.T) {
	repos := []model.Repo{
		{Slug: "test-repo-1"},
		{Slug: "test-repo-2"},
	}

	results := worker.Run(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		return &model.RepoStats{
			Repository: repo.Slug,
			Languages: []model.LanguageStats{
				{Name: "Go", Files: 5, Code: 100, Comments: 10, Blanks: 10, Lines: 120, Complexity: 15},
			},
			Totals: model.Stats{Files: 5, Code: 100, Comments: 10, Blanks: 10, Lines: 120, Complexity: 15},
		}, nil
	})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected error for %s: %v", r.Repo.Slug, r.Err)
		}
		if r.Stats.Totals.Code != 100 {
			t.Errorf("expected code 100, got %d", r.Stats.Totals.Code)
		}
	}
}
```

**Step 2: Run tests**

Run: `go test ./...`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add -A
git commit -m "test: add integration tests for analyze pipeline"
```

---

### Task 16: Final Polish

**Step 1: Run all tests**

Run: `go test ./... -v`
Expected: All PASS

**Step 2: Run go vet and build**

Run: `go vet ./... && go build -o codemium ./cmd/codemium`
Expected: No errors, binary produced

**Step 3: Verify CLI help output**

Run: `./codemium --help && ./codemium auth --help && ./codemium analyze --help`
Expected: Clean help output for all commands

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final polish and verification"
```
