// internal/provider/github_test.go
package provider_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/provider"
)

func TestGitHubListRepos(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2&per_page=100>; rel="next"`, "http://"+r.Host, r.URL.Path))
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

	gh := provider.NewGitHub("test-token", server.URL, nil)
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

func TestGitHubListReposUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/repos" {
			t.Errorf("expected path /user/repos, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{"name": "personal-repo", "full_name": "myuser/personal-repo", "html_url": "https://github.com/myuser/personal-repo", "clone_url": "https://github.com/myuser/personal-repo.git", "archived": false, "fork": false},
		})
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	repos, err := gh.ListRepos(context.Background(), provider.ListOpts{
		User: "myuser",
	})
	if err != nil {
		t.Fatalf("failed to list repos: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
	if repos[0].Slug != "personal-repo" {
		t.Errorf("expected personal-repo, got %s", repos[0].Slug)
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

	gh := provider.NewGitHub("test-token", server.URL, nil)
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

func TestGitHubListCommits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/myorg/repo-1/commits") && !strings.Contains(r.URL.Path, "/repos/myorg/repo-1/commits/") {
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"sha": "abc123",
					"commit": map[string]any{
						"author":  map[string]any{"name": "Dev", "email": "dev@example.com", "date": "2025-06-15T10:30:00Z"},
						"message": "feat: add feature\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
					},
				},
				{
					"sha": "def456",
					"commit": map[string]any{
						"author":  map[string]any{"name": "Dev", "email": "dev@example.com", "date": "2025-06-14T09:00:00Z"},
						"message": "fix: bug",
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	commits, err := gh.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://github.com/myorg/repo-1",
	}, 100)
	if err != nil {
		t.Fatalf("ListCommits: %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}
	if commits[0].Hash != "abc123" {
		t.Errorf("expected hash abc123, got %s", commits[0].Hash)
	}
	if !strings.Contains(commits[0].Message, "Co-Authored-By") {
		t.Error("expected full commit message with trailers")
	}
	if commits[0].Date.IsZero() {
		t.Error("expected commit date to be parsed")
	}
	if commits[0].Date.Year() != 2025 || commits[0].Date.Month() != 6 || commits[0].Date.Day() != 15 {
		t.Errorf("expected date 2025-06-15, got %s", commits[0].Date)
	}
}

func TestGitHubCommitStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/myorg/repo-1/commits/abc123" {
			json.NewEncoder(w).Encode(map[string]any{
				"sha": "abc123",
				"stats": map[string]any{
					"additions": 150,
					"deletions": 30,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	additions, deletions, err := gh.CommitStats(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://github.com/myorg/repo-1",
	}, "abc123")
	if err != nil {
		t.Fatalf("CommitStats: %v", err)
	}
	if additions != 150 {
		t.Errorf("expected 150 additions, got %d", additions)
	}
	if deletions != 30 {
		t.Errorf("expected 30 deletions, got %d", deletions)
	}
}

func TestGitHubCommitFileStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/myorg/repo-1/commits/abc123" {
			json.NewEncoder(w).Encode(map[string]any{
				"sha": "abc123",
				"stats": map[string]any{"additions": 150, "deletions": 30},
				"files": []map[string]any{
					{"filename": "main.go", "additions": 100, "deletions": 20},
					{"filename": "util.go", "additions": 50, "deletions": 10},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	files, err := gh.CommitFileStats(context.Background(), model.Repo{
		Slug: "repo-1", URL: "https://github.com/myorg/repo-1",
	}, "abc123")
	if err != nil {
		t.Fatalf("CommitFileStats: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if files[0].Path != "main.go" || files[0].Additions != 100 {
		t.Errorf("unexpected first file: %+v", files[0])
	}
}

func TestGitHubListCommitsLimit(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		commits := make([]map[string]any, 100)
		for i := range commits {
			commits[i] = map[string]any{
				"sha":    fmt.Sprintf("hash-%d-%d", page, i),
				"commit": map[string]any{"author": map[string]any{"name": "Dev", "email": "d@e.com"}, "message": "msg"},
			}
		}
		if page == 1 {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=2&per_page=100>; rel="next"`, "http://"+r.Host, r.URL.Path))
		}
		json.NewEncoder(w).Encode(commits)
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	commits, err := gh.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://github.com/myorg/repo-1",
	}, 150)
	if err != nil {
		t.Fatalf("ListCommits: %v", err)
	}
	if len(commits) != 150 {
		t.Errorf("expected 150 commits (limited), got %d", len(commits))
	}
}

func TestGitHubListCommitsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	_, err := gh.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://github.com/myorg/repo-1",
	}, 100)
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status 403, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("error should include response body snippet, got: %v", err)
	}
}

func TestGitHubCommitStatsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	_, _, err := gh.CommitStats(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://github.com/myorg/repo-1",
	}, "deadbeef")
	if err == nil {
		t.Fatal("expected error on 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status 404, got: %v", err)
	}
}

func TestGitHubListReposNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	_, err := gh.ListRepos(context.Background(), provider.ListOpts{Organization: "myorg"})
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status 500, got: %v", err)
	}
	if !strings.Contains(err.Error(), "internal error") {
		t.Errorf("error should include body snippet, got: %v", err)
	}
}

func TestGitHubDefaultBranch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"name":           "repo-1",
				"full_name":      "org/repo-1",
				"html_url":       "https://github.com/org/repo-1",
				"clone_url":      "https://github.com/org/repo-1.git",
				"default_branch": "develop",
				"archived":       false,
				"fork":           false,
			},
		})
	}))
	defer server.Close()

	gh := provider.NewGitHub("test-token", server.URL, nil)
	repos, err := gh.ListRepos(context.Background(), provider.ListOpts{Organization: "org"})
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
	if repos[0].DefaultBranch != "develop" {
		t.Errorf("expected default branch 'develop', got %q", repos[0].DefaultBranch)
	}
}
