package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsablic/codemium/internal/analyzer"
	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/worker"
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

func TestBuildReport(t *testing.T) {
	results := []worker.Result{
		{
			Repo: model.Repo{Slug: "repo-1", Project: "PROJ1"},
			Stats: &model.RepoStats{
				Repository: "repo-1",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				Languages: []model.LanguageStats{
					{Name: "Go", Files: 10, Code: 500, Comments: 50, Blanks: 50, Lines: 600, Complexity: 30},
				},
				Totals: model.Stats{Files: 10, Code: 500, Comments: 50, Blanks: 50, Lines: 600, Complexity: 30},
			},
		},
		{
			Repo: model.Repo{Slug: "repo-2", Project: "PROJ1"},
			Stats: &model.RepoStats{
				Repository: "repo-2",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				Languages: []model.LanguageStats{
					{Name: "Go", Files: 5, Code: 200, Comments: 20, Blanks: 20, Lines: 240, Complexity: 10},
					{Name: "Python", Files: 3, Code: 100, Comments: 10, Blanks: 10, Lines: 120, Complexity: 5},
				},
				Totals: model.Stats{Files: 8, Code: 300, Comments: 30, Blanks: 30, Lines: 360, Complexity: 15},
			},
		},
		{
			Repo: model.Repo{Slug: "bad-repo"},
			Err:  fmt.Errorf("clone failed"),
		},
	}

	report := buildReport("bitbucket", "myworkspace", "", []string{"PROJ1"}, nil, nil, results)

	if report.Totals.Repos != 2 {
		t.Errorf("expected 2 repos, got %d", report.Totals.Repos)
	}
	if report.Totals.Code != 800 {
		t.Errorf("expected 800 total code, got %d", report.Totals.Code)
	}
	if len(report.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(report.Errors))
	}
	if len(report.ByLanguage) != 2 {
		t.Errorf("expected 2 languages, got %d", len(report.ByLanguage))
	}
	// Go should be first (more code)
	if report.ByLanguage[0].Name != "Go" {
		t.Errorf("expected Go first (sorted by code desc), got %s", report.ByLanguage[0].Name)
	}
	if report.ByLanguage[0].Code != 700 {
		t.Errorf("expected Go total code 700, got %d", report.ByLanguage[0].Code)
	}
}
