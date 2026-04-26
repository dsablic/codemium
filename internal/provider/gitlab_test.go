// internal/provider/gitlab_test.go
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

func TestGitLabListRepos(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("X-Next-Page", "2")
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":                  1,
					"path":                "repo-1",
					"path_with_namespace": "mygroup/repo-1",
					"name":                "Repo 1",
					"web_url":             "https://gitlab.com/mygroup/repo-1",
					"http_url_to_repo":    "https://gitlab.com/mygroup/repo-1.git",
					"default_branch":      "main",
					"archived":            false,
					"forked_from_project": nil,
					"namespace":           map[string]any{"full_path": "mygroup"},
				},
			})
		} else {
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":                  2,
					"path":                "repo-2",
					"path_with_namespace": "mygroup/repo-2",
					"name":                "Repo 2",
					"web_url":             "https://gitlab.com/mygroup/repo-2",
					"http_url_to_repo":    "https://gitlab.com/mygroup/repo-2.git",
					"default_branch":      "develop",
					"archived":            false,
					"forked_from_project": nil,
					"namespace":           map[string]any{"full_path": "mygroup"},
				},
			})
		}
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	repos, err := gl.ListRepos(context.Background(), provider.ListOpts{
		Organization: "mygroup",
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
	if repos[1].Slug != "repo-2" {
		t.Errorf("expected repo-2, got %s", repos[1].Slug)
	}
	if repos[0].Provider != "gitlab" {
		t.Errorf("expected provider gitlab, got %s", repos[0].Provider)
	}
	if repos[0].Project != "mygroup" {
		t.Errorf("expected project mygroup, got %s", repos[0].Project)
	}
}

func TestGitLabExcludeForksAndArchived(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"id": 1, "path": "active", "path_with_namespace": "g/active",
				"name": "Active", "web_url": "h", "http_url_to_repo": "c",
				"default_branch": "main", "archived": false, "forked_from_project": nil,
				"namespace": map[string]any{"full_path": "g"},
			},
			{
				"id": 2, "path": "archived-repo", "path_with_namespace": "g/archived-repo",
				"name": "Archived", "web_url": "h", "http_url_to_repo": "c",
				"default_branch": "main", "archived": true, "forked_from_project": nil,
				"namespace": map[string]any{"full_path": "g"},
			},
			{
				"id": 3, "path": "forked-repo", "path_with_namespace": "g/forked-repo",
				"name": "Forked", "web_url": "h", "http_url_to_repo": "c",
				"default_branch": "main", "archived": false,
				"forked_from_project": map[string]any{"id": 99},
				"namespace":           map[string]any{"full_path": "g"},
			},
		})
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	repos, _ := gl.ListRepos(context.Background(), provider.ListOpts{
		Organization:    "g",
		IncludeArchived: true, // server-side filter disabled so we test client-side fork filter
	})
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos (forks excluded), got %d", len(repos))
	}
}

func TestGitLabIncludeSlugFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 1, "path": "repo-a", "path_with_namespace": "g/repo-a", "name": "A", "web_url": "h", "http_url_to_repo": "c", "default_branch": "main", "archived": false, "forked_from_project": nil, "namespace": map[string]any{"full_path": "g"}},
			{"id": 2, "path": "repo-b", "path_with_namespace": "g/repo-b", "name": "B", "web_url": "h", "http_url_to_repo": "c", "default_branch": "main", "archived": false, "forked_from_project": nil, "namespace": map[string]any{"full_path": "g"}},
		})
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	repos, _ := gl.ListRepos(context.Background(), provider.ListOpts{
		Organization: "g",
		Repos:        []string{"repo-a"},
	})
	if len(repos) != 1 || repos[0].Slug != "repo-a" {
		t.Fatalf("expected only repo-a, got %v", repos)
	}
}

func TestGitLabExcludeSlugFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 1, "path": "repo-a", "path_with_namespace": "g/repo-a", "name": "A", "web_url": "h", "http_url_to_repo": "c", "default_branch": "main", "archived": false, "forked_from_project": nil, "namespace": map[string]any{"full_path": "g"}},
			{"id": 2, "path": "repo-b", "path_with_namespace": "g/repo-b", "name": "B", "web_url": "h", "http_url_to_repo": "c", "default_branch": "main", "archived": false, "forked_from_project": nil, "namespace": map[string]any{"full_path": "g"}},
		})
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	repos, _ := gl.ListRepos(context.Background(), provider.ListOpts{
		Organization: "g",
		Exclude:      []string{"repo-b"},
	})
	if len(repos) != 1 || repos[0].Slug != "repo-a" {
		t.Fatalf("expected only repo-a, got %v", repos)
	}
}

func TestGitLabAuthHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer my-pat" {
			t.Errorf("expected Authorization header 'Bearer my-pat', got %q", got)
		}
		json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer server.Close()

	gl := provider.NewGitLab("my-pat", server.URL, nil)
	gl.ListRepos(context.Background(), provider.ListOpts{Organization: "g"})
}

func TestGitLabSelfHosted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v4/groups/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	_, err := gl.ListRepos(context.Background(), provider.ListOpts{Organization: "mygroup"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGitLabListCommits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repository/commits") && !strings.Contains(r.URL.Path, "/repository/commits/") {
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":             "abc123",
					"author_name":    "Dev",
					"author_email":   "dev@example.com",
					"committed_date": "2025-06-15T10:30:00.000Z",
					"message":        "feat: add feature\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
				},
				{
					"id":             "def456",
					"author_name":    "Dev",
					"author_email":   "dev@example.com",
					"committed_date": "2025-06-14T09:00:00.000Z",
					"message":        "fix: bug",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	commits, err := gl.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  server.URL + "/mygroup/repo-1",
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

func TestGitLabCommitStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/repository/commits/abc123") {
			json.NewEncoder(w).Encode(map[string]any{
				"id": "abc123",
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

	gl := provider.NewGitLab("test-token", server.URL, nil)
	additions, deletions, err := gl.CommitStats(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  server.URL + "/mygroup/repo-1",
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

func TestGitLabTokenRefreshOn401(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		auth := r.Header.Get("Authorization")
		if auth == "Bearer expired-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if auth == "Bearer fresh-token" {
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id": 1, "path": "repo-1", "path_with_namespace": "g/repo-1",
					"name": "Repo 1", "web_url": "h", "http_url_to_repo": "c",
					"default_branch": "main", "archived": false,
					"forked_from_project": nil,
					"namespace":           map[string]any{"full_path": "g"},
				},
			})
			return
		}
		t.Errorf("unexpected auth header: %s", auth)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	refreshCalls := 0
	refreshFn := func() (string, bool) {
		refreshCalls++
		return "fresh-token", true
	}

	gl := provider.NewGitLabWithRefresh("expired-token", server.URL, nil, refreshFn)
	repos, err := gl.ListRepos(context.Background(), provider.ListOpts{Organization: "g"})
	if err != nil {
		t.Fatalf("expected successful retry, got error: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
	if refreshCalls != 1 {
		t.Errorf("expected 1 refresh call, got %d", refreshCalls)
	}
	if calls != 2 {
		t.Errorf("expected 2 server calls (401 + retry), got %d", calls)
	}
}

func TestGitLabTokenRefreshNotCalledWithoutCallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	gl := provider.NewGitLab("expired-token", server.URL, nil)
	_, err := gl.ListRepos(context.Background(), provider.ListOpts{Organization: "g"})
	if err == nil {
		t.Fatal("expected error on 401 without refresh callback")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 in error, got: %v", err)
	}
}

func TestGitLabTokenRefreshFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	refreshFn := func() (string, bool) {
		return "", false
	}

	gl := provider.NewGitLabWithRefresh("expired-token", server.URL, nil, refreshFn)
	_, err := gl.ListRepos(context.Background(), provider.ListOpts{Organization: "g"})
	if err == nil {
		t.Fatal("expected error when refresh fails")
	}
}

func TestGitLabListCommitsLimit(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		commits := make([]map[string]any, 100)
		for i := range commits {
			commits[i] = map[string]any{
				"id":           fmt.Sprintf("hash-%d-%d", page, i),
				"author_name":  "Dev",
				"author_email": "d@e.com",
				"message":      "msg",
			}
		}
		if page == 1 {
			w.Header().Set("X-Next-Page", "2")
		}
		json.NewEncoder(w).Encode(commits)
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	commits, err := gl.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  server.URL + "/mygroup/repo-1",
	}, 150)
	if err != nil {
		t.Fatalf("ListCommits: %v", err)
	}
	if len(commits) != 150 {
		t.Errorf("expected 150 commits (limited), got %d", len(commits))
	}
}

func TestGitLabListReposNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"403 Forbidden"}`))
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	_, err := gl.ListRepos(context.Background(), provider.ListOpts{Organization: "mygroup"})
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status 403, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("error should include body snippet, got: %v", err)
	}
}

func TestGitLabListCommitsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 Project Not Found"}`))
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	_, err := gl.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  server.URL + "/mygroup/repo-1",
	}, 100)
	if err == nil {
		t.Fatal("expected error on 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status 404, got: %v", err)
	}
}

func TestGitLabCommitStatsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	gl := provider.NewGitLab("test-token", server.URL, nil)
	_, _, err := gl.CommitStats(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  server.URL + "/mygroup/repo-1",
	}, "abc123")
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status 500, got: %v", err)
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("error should include body snippet, got: %v", err)
	}
}
