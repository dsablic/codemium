package aiestimate_test

import (
	"context"
	"testing"

	"github.com/dsablic/codemium/internal/aiestimate"
	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/provider"
)

type mockCommitLister struct {
	commits []provider.CommitInfo
	stats   map[string][2]int64 // hash -> {additions, deletions}
}

func (m *mockCommitLister) ListCommits(ctx context.Context, repo model.Repo, limit int) ([]provider.CommitInfo, error) {
	if limit > 0 && limit < len(m.commits) {
		return m.commits[:limit], nil
	}
	return m.commits, nil
}

func (m *mockCommitLister) CommitStats(ctx context.Context, repo model.Repo, hash string) (int64, int64, error) {
	s := m.stats[hash]
	return s[0], s[1], nil
}

func TestEstimateBasic(t *testing.T) {
	mock := &mockCommitLister{
		commits: []provider.CommitInfo{
			{Hash: "abc", Author: "Dev <dev@e.com>", Message: "feat: thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>"},
			{Hash: "def", Author: "Dev <dev@e.com>", Message: "fix: manual fix"},
			{Hash: "ghi", Author: "dependabot[bot] <bot@github.com>", Message: "chore: bump deps"},
		},
		stats: map[string][2]int64{
			"abc": {100, 10},
			"ghi": {50, 5},
		},
	}

	repo := model.Repo{Slug: "test-repo", URL: "https://github.com/org/test-repo"}
	estimate, err := aiestimate.Estimate(context.Background(), mock, repo, 500)
	if err != nil {
		t.Fatalf("Estimate: %v", err)
	}

	if estimate.TotalCommits != 3 {
		t.Errorf("expected 3 total commits, got %d", estimate.TotalCommits)
	}
	if estimate.AICommits != 2 {
		t.Errorf("expected 2 AI commits, got %d", estimate.AICommits)
	}
	if estimate.AIAdditions != 150 {
		t.Errorf("expected 150 AI additions, got %d", estimate.AIAdditions)
	}
	if len(estimate.Details) != 2 {
		t.Errorf("expected 2 details, got %d", len(estimate.Details))
	}
}

func TestEstimateNoAICommits(t *testing.T) {
	mock := &mockCommitLister{
		commits: []provider.CommitInfo{
			{Hash: "abc", Author: "Dev <dev@e.com>", Message: "feat: manual work"},
		},
		stats: map[string][2]int64{},
	}

	repo := model.Repo{Slug: "test-repo", URL: "https://github.com/org/test-repo"}
	estimate, err := aiestimate.Estimate(context.Background(), mock, repo, 500)
	if err != nil {
		t.Fatalf("Estimate: %v", err)
	}

	if estimate.AICommits != 0 {
		t.Errorf("expected 0 AI commits, got %d", estimate.AICommits)
	}
	if estimate.CommitPercent != 0 {
		t.Errorf("expected 0%% commit percent, got %f", estimate.CommitPercent)
	}
}

func TestEstimatePercentCalculation(t *testing.T) {
	mock := &mockCommitLister{
		commits: []provider.CommitInfo{
			{Hash: "a", Author: "Dev <d@e.com>", Message: "feat\n\nCo-Authored-By: Claude <c@a.com>"},
			{Hash: "b", Author: "Dev <d@e.com>", Message: "fix"},
			{Hash: "c", Author: "Dev <d@e.com>", Message: "docs"},
			{Hash: "d", Author: "Dev <d@e.com>", Message: "test"},
		},
		stats: map[string][2]int64{
			"a": {200, 50},
		},
	}

	repo := model.Repo{Slug: "r", URL: "https://github.com/o/r"}
	est, err := aiestimate.Estimate(context.Background(), mock, repo, 500)
	if err != nil {
		t.Fatalf("Estimate: %v", err)
	}

	if est.CommitPercent != 25.0 {
		t.Errorf("expected 25.0%% commit percent, got %f", est.CommitPercent)
	}
}

func TestEstimateFirstLineMessage(t *testing.T) {
	mock := &mockCommitLister{
		commits: []provider.CommitInfo{
			{Hash: "a", Author: "Dev <d@e.com>", Message: "feat: multi-line\n\nBody here\n\nCo-Authored-By: Claude <c@a.com>"},
		},
		stats: map[string][2]int64{
			"a": {10, 5},
		},
	}

	repo := model.Repo{Slug: "r", URL: "https://github.com/o/r"}
	est, err := aiestimate.Estimate(context.Background(), mock, repo, 500)
	if err != nil {
		t.Fatalf("Estimate: %v", err)
	}

	if len(est.Details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(est.Details))
	}
	if est.Details[0].Message != "feat: multi-line" {
		t.Errorf("expected first line only, got %q", est.Details[0].Message)
	}
}
