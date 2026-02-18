// internal/worker/pool.go
package worker

import (
	"context"
	"sync"

	"github.com/labtiva/codemium/internal/model"
)

// Result holds the outcome of processing a single repository.
type Result struct {
	Repo  model.Repo
	Stats *model.RepoStats
	Err   error
}

// ProgressFunc is called after each repository is processed.
type ProgressFunc func(completed, total int, repo model.Repo)

// ProcessFunc processes a single repository and returns its stats.
type ProcessFunc func(ctx context.Context, repo model.Repo) (*model.RepoStats, error)

// Run processes repos concurrently using a bounded worker pool.
func Run(ctx context.Context, repos []model.Repo, concurrency int, process ProcessFunc) []Result {
	return RunWithProgress(ctx, repos, concurrency, process, nil)
}

// RunWithProgress processes repos concurrently with an optional progress callback.
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
