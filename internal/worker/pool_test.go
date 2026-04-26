// internal/worker/pool_test.go
package worker_test

import (
	"context"
	"fmt"
	"strings"
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

func TestRunTrendsProcessesAll(t *testing.T) {
	repos := []model.Repo{
		{Slug: "repo-1"},
		{Slug: "repo-2"},
	}

	results := worker.RunTrends(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (map[string]*model.RepoStats, error) {
		return map[string]*model.RepoStats{
			"2025-01": {Repository: repo.Slug, Totals: model.Stats{Code: 100}},
			"2025-02": {Repository: repo.Slug, Totals: model.Stats{Code: 200}},
		}, nil
	}, nil)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected error for %s: %v", r.Repo.Slug, r.Err)
		}
		if len(r.Snapshots) != 2 {
			t.Errorf("expected 2 snapshots for %s, got %d", r.Repo.Slug, len(r.Snapshots))
		}
	}
}

func TestRunTrendsHandlesErrors(t *testing.T) {
	repos := []model.Repo{
		{Slug: "good"},
		{Slug: "bad"},
	}

	results := worker.RunTrends(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (map[string]*model.RepoStats, error) {
		if repo.Slug == "bad" {
			return nil, fmt.Errorf("trends failed")
		}
		return map[string]*model.RepoStats{"2025-01": {Repository: repo.Slug}}, nil
	}, nil)

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

func TestProgressCallback(t *testing.T) {
	repos := []model.Repo{
		{Slug: "repo-1"},
		{Slug: "repo-2"},
		{Slug: "repo-3"},
	}

	var progressCalls atomic.Int32

	worker.RunWithProgress(context.Background(), repos, 1, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		return &model.RepoStats{Repository: repo.Slug}, nil
	}, func(completed, total int, repo model.Repo) {
		progressCalls.Add(1)
		if total != 3 {
			t.Errorf("expected total=3, got %d", total)
		}
	})

	if int(progressCalls.Load()) != 3 {
		t.Errorf("expected 3 progress callbacks, got %d", progressCalls.Load())
	}
}

func TestTrendsProgressCallback(t *testing.T) {
	repos := []model.Repo{
		{Slug: "repo-1"},
		{Slug: "repo-2"},
	}

	var progressCalls atomic.Int32

	worker.RunTrends(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (map[string]*model.RepoStats, error) {
		return map[string]*model.RepoStats{"2025-01": {}}, nil
	}, func(completed, total int, repo model.Repo) {
		progressCalls.Add(1)
		if total != 2 {
			t.Errorf("expected total=2, got %d", total)
		}
	})

	if int(progressCalls.Load()) != 2 {
		t.Errorf("expected 2 progress callbacks, got %d", progressCalls.Load())
	}
}

func TestConcurrencyBound(t *testing.T) {
	repos := make([]model.Repo, 20)
	for i := range repos {
		repos[i] = model.Repo{Slug: fmt.Sprintf("repo-%d", i)}
	}

	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32

	done := make(chan struct{})

	results := worker.RunWithProgress(context.Background(), repos, 3, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		cur := concurrent.Add(1)
		// Track max concurrent workers
		for {
			prev := maxConcurrent.Load()
			if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
				break
			}
		}
		// Brief yield to let other goroutines start if they're going to
		select {
		case <-done:
		default:
		}
		concurrent.Add(-1)
		return &model.RepoStats{Repository: repo.Slug}, nil
	}, nil)
	close(done)

	if len(results) != 20 {
		t.Fatalf("expected 20 results, got %d", len(results))
	}
	if maxConcurrent.Load() > 3 {
		t.Errorf("expected max concurrency <= 3, got %d", maxConcurrent.Load())
	}
}

func TestPoolRecoversPanic(t *testing.T) {
	repos := []model.Repo{
		{Slug: "good-repo"},
		{Slug: "panic-repo"},
	}

	results := worker.Run(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		if repo.Slug == "panic-repo" {
			panic("unexpected panic in process")
		}
		return &model.RepoStats{Repository: repo.Slug}, nil
	})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var successes, panics int
	for _, r := range results {
		if r.Err != nil {
			panics++
			if !strings.Contains(r.Err.Error(), "panic") {
				t.Errorf("expected panic error, got: %v", r.Err)
			}
		} else {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected 1 success, got %d", successes)
	}
	if panics != 1 {
		t.Errorf("expected 1 panic recovery, got %d", panics)
	}
}

func TestRunTrendsRecoversPanic(t *testing.T) {
	repos := []model.Repo{
		{Slug: "good-repo"},
		{Slug: "panic-repo"},
	}

	results := worker.RunTrends(context.Background(), repos, 2, func(ctx context.Context, repo model.Repo) (map[string]*model.RepoStats, error) {
		if repo.Slug == "panic-repo" {
			panic("trends panic")
		}
		return map[string]*model.RepoStats{"2025-01": {}}, nil
	}, nil)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var panics int
	for _, r := range results {
		if r.Err != nil && strings.Contains(r.Err.Error(), "panic") {
			panics++
		}
	}
	if panics != 1 {
		t.Errorf("expected 1 panic recovery, got %d", panics)
	}
}
