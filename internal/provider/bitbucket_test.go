// internal/provider/bitbucket_test.go
package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
