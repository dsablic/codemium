// internal/analyzer/analyzer.go
package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/boyter/scc/v3/processor"
	"github.com/dsablic/codemium/internal/model"
)

var initOnce sync.Once

// Analyzer wraps scc's processor package to analyze source code directories.
type Analyzer struct{}

// New creates a new Analyzer instance. It ensures that scc's ProcessConstants
// is called exactly once, even when multiple goroutines create analyzers concurrently.
func New() *Analyzer {
	initOnce.Do(func() {
		processor.ProcessConstants()
	})
	return &Analyzer{}
}

// Analyze walks the given directory, detects languages, and returns aggregated
// code statistics per language.
func (a *Analyzer) Analyze(ctx context.Context, dir string) (*model.RepoStats, error) {
	langMap := map[string]*model.LanguageStats{}
	var totalFiles int64

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".hg" {
				return filepath.SkipDir
			}
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		possibleLanguages, _ := processor.DetectLanguage(info.Name())
		if len(possibleLanguages) == 0 {
			return nil
		}

		job := &processor.FileJob{
			Filename:          info.Name(),
			Content:           content,
			Bytes:             int64(len(content)),
			PossibleLanguages: possibleLanguages,
		}

		job.Language = processor.DetermineLanguage(job.Filename, job.Language, job.PossibleLanguages, job.Content)
		if job.Language == "" {
			return nil
		}

		processor.CountStats(job)

		if job.Binary {
			return nil
		}

		lang, ok := langMap[job.Language]
		if !ok {
			lang = &model.LanguageStats{Name: job.Language}
			langMap[job.Language] = lang
		}

		lang.Files++
		lang.Lines += job.Lines
		lang.Code += job.Code
		lang.Comments += job.Comment
		lang.Blanks += job.Blank
		lang.Complexity += job.Complexity
		totalFiles++

		return nil
	})
	if err != nil {
		return nil, err
	}

	stats := &model.RepoStats{}
	for _, lang := range langMap {
		stats.Languages = append(stats.Languages, *lang)
		stats.Totals.Files += lang.Files
		stats.Totals.Lines += lang.Lines
		stats.Totals.Code += lang.Code
		stats.Totals.Comments += lang.Comments
		stats.Totals.Blanks += lang.Blanks
		stats.Totals.Complexity += lang.Complexity
	}

	return stats, nil
}
