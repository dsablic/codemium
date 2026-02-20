// internal/provider/github_test.go
package provider_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

	gh := provider.NewGitHub("test-token", server.URL)
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
