// internal/worker/pool_test.go
package worker_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/worker"
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
