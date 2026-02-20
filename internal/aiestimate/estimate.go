package aiestimate

import (
	"context"

	"github.com/dsablic/codemium/internal/aidetect"
	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/provider"
)

// Estimate computes AI attribution metrics for a single repo.
func Estimate(ctx context.Context, cl provider.CommitLister, repo model.Repo, commitLimit int) (*model.AIEstimate, error) {
	commits, err := cl.ListCommits(ctx, repo, commitLimit)
	if err != nil {
		return nil, err
	}

	est := &model.AIEstimate{
		TotalCommits: int64(len(commits)),
	}

	type flaggedCommit struct {
		info    provider.CommitInfo
		signals []model.AISignal
	}

	var flagged []flaggedCommit
	for _, c := range commits {
		signals := aidetect.Detect(c.Author, c.Message)
		if len(signals) > 0 {
			flagged = append(flagged, flaggedCommit{info: c, signals: signals})
		}
	}

	est.AICommits = int64(len(flagged))

	if est.TotalCommits > 0 {
		est.CommitPercent = float64(est.AICommits) / float64(est.TotalCommits) * 100
	}

	// Fetch stats only for AI-flagged commits
	for _, fc := range flagged {
		additions, deletions, err := cl.CommitStats(ctx, repo, fc.info.Hash)
		if err != nil {
			continue // partial failure — skip this commit's stats
		}

		est.AIAdditions += additions

		// Extract first line of commit message
		firstLine := fc.info.Message
		for j, ch := range fc.info.Message {
			if ch == '\n' {
				firstLine = fc.info.Message[:j]
				break
			}
		}

		est.Details = append(est.Details, model.AICommit{
			Hash:      fc.info.Hash,
			Author:    fc.info.Author,
			Message:   firstLine,
			Signals:   fc.signals,
			Additions: additions,
			Deletions: deletions,
		})
	}

	return est, nil
}
