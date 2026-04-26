// internal/provider/bitbucket_test.go
package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/provider"
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
							"html": map[string]any{"href": "https://bitbucket.org/myworkspace/repo-1"},
							"clone": []map[string]any{{
								"name": "https",
								"href": "https://bitbucket.org/myworkspace/repo-1.git",
							}},
						},
						"parent": nil,
					},
				},
				"next": "http://" + r.Host + "/2.0/repositories/myworkspace?page=2",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{
						"slug":      "repo-2",
						"full_name": "myworkspace/repo-2",
						"project":   map[string]any{"key": "PROJ1"},
						"links": map[string]any{
							"html": map[string]any{"href": "https://bitbucket.org/myworkspace/repo-2"},
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

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
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

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
	bb.ListRepos(context.Background(), provider.ListOpts{
		Workspace: "myworkspace",
		Projects:  []string{"PROJ1", "PROJ2"},
	})

	if receivedQuery == "" {
		t.Fatal("expected query parameter to be set")
	}
}

func TestBitbucketBasicAuth(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{"values": []map[string]any{}})
	}))
	defer server.Close()

	bb := provider.NewBitbucket("app-pass", "myuser", server.URL, nil)
	bb.ListRepos(context.Background(), provider.ListOpts{Workspace: "ws"})

	if gotAuth == "" {
		t.Fatal("expected Authorization header")
	}
	if gotAuth == "Bearer app-pass" {
		t.Error("expected Basic auth, got Bearer")
	}
	// Basic auth header should start with "Basic "
	if len(gotAuth) < 6 || gotAuth[:6] != "Basic " {
		t.Errorf("expected Basic auth header, got %s", gotAuth)
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

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)

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

func TestBitbucketListCommits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/commits") {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{
						"hash":    "abc123",
						"date":    "2025-06-15T10:30:00+00:00",
						"message": "feat: add feature\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
						"author": map[string]any{
							"raw": "Dev <dev@example.com>",
						},
					},
					{
						"hash":    "def456",
						"date":    "2025-06-14T09:00:00+00:00",
						"message": "fix: bug",
						"author": map[string]any{
							"raw": "Dev <dev@example.com>",
						},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
	commits, err := bb.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://bitbucket.org/myworkspace/repo-1",
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
	if commits[0].Date.IsZero() {
		t.Error("expected commit date to be parsed")
	}
	if commits[0].Date.Year() != 2025 || commits[0].Date.Month() != 6 || commits[0].Date.Day() != 15 {
		t.Errorf("expected date 2025-06-15, got %s", commits[0].Date)
	}
}

func TestBitbucketCommitStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/diffstat/abc123") {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{"lines_added": 100, "lines_removed": 20},
					{"lines_added": 50, "lines_removed": 10},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
	additions, deletions, err := bb.CommitStats(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://bitbucket.org/myworkspace/repo-1",
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

func TestBitbucketCommitStatsPagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/diffstat/abc123") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		page++
		if page == 1 {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{"lines_added": 100, "lines_removed": 20},
				},
				"next": "http://" + r.Host + "/2.0/repositories/ws/repo/diffstat/abc123?page=2",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{"lines_added": 50, "lines_removed": 10},
				},
			})
		}
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
	additions, deletions, err := bb.CommitStats(context.Background(), model.Repo{
		Slug: "repo",
		URL:  "https://bitbucket.org/ws/repo",
	}, "abc123")
	if err != nil {
		t.Fatalf("CommitStats: %v", err)
	}
	if additions != 150 {
		t.Errorf("expected 150 additions (across 2 pages), got %d", additions)
	}
	if deletions != 30 {
		t.Errorf("expected 30 deletions (across 2 pages), got %d", deletions)
	}
	if page != 2 {
		t.Errorf("expected 2 pages fetched, got %d", page)
	}
}

func TestBitbucketListReposNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"Access denied"}}`))
	}))
	defer server.Close()

	bb := provider.NewBitbucket("bad-token", "", server.URL, nil)
	_, err := bb.ListRepos(context.Background(), provider.ListOpts{Workspace: "ws"})
	if err == nil {
		t.Fatal("expected error on 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status 401, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Access denied") {
		t.Errorf("error should include body snippet, got: %v", err)
	}
}

func TestBitbucketListCommitsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"message":"Forbidden"}}`))
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
	_, err := bb.ListCommits(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://bitbucket.org/ws/repo-1",
	}, 100)
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status 403, got: %v", err)
	}
}

func TestBitbucketCommitStatsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	bb := provider.NewBitbucket("test-token", "", server.URL, nil)
	_, _, err := bb.CommitStats(context.Background(), model.Repo{
		Slug: "repo-1",
		URL:  "https://bitbucket.org/ws/repo-1",
	}, "deadbeef")
	if err == nil {
		t.Fatal("expected error on 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status 404, got: %v", err)
	}
}
