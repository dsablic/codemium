# Trends: Historical Code Statistics Over Time

## Overview

New `codemium trends` command that analyzes repositories at historical points in time using git history, producing time-series statistics showing how codebases evolve.

## CLI Interface

```
codemium trends --provider github --org myorg \
  --since 2025-03 --until 2026-02 --interval monthly \
  [--output trends.json] [all existing filter flags]
```

- `--since` / `--until`: Required. Format `YYYY-MM` for monthly, `YYYY-MM-DD` for weekly.
- `--interval`: `monthly` (default) or `weekly`.
- All existing filter flags carry over: `--repos`, `--exclude`, `--include-forks`, `--include-archived`, `--concurrency`.

## Architecture

### Approach: Sequential per-repo

For each repo: full clone -> find last commit before each target date -> checkout & analyze -> next repo -> cleanup.

- Worker pool parallelizes across repos (same as `analyze`)
- Within a repo, snapshots are sequential (cheap local git checkout)
- One full clone on disk per concurrent worker — bounded disk usage

### Clone Strategy

New `Cloner.CloneFull()` method — full clone (no depth limit, no single-branch) to a temp dir. Returns the `*git.Repository` handle along with the dir path and cleanup func.

### Snapshot Resolution

New `internal/history` package:

```go
func FindCommits(repo *git.Repository, dates []time.Time) (map[time.Time]plumbing.Hash, error)
```

Walks the default branch log once, finds the last commit at or before each target date. Dates with no commits (repo didn't exist yet) are omitted from the map.

### Per-repo Worker Flow

1. Full clone
2. Compute target dates from --since/--until/--interval
3. `FindCommits()` to get commit hashes per date
4. For each date (chronological): checkout commit -> `analyzer.Analyze()` -> collect stats
5. Cleanup

## Data Model

```go
type TrendsReport struct {
    GeneratedAt  string           `json:"generated_at"`
    Provider     string           `json:"provider"`
    Workspace    string           `json:"workspace,omitempty"`
    Organization string           `json:"organization,omitempty"`
    Filters      Filters          `json:"filters"`
    Since        string           `json:"since"`
    Until        string           `json:"until"`
    Interval     string           `json:"interval"`
    Periods      []string         `json:"periods"`
    Snapshots    []PeriodSnapshot `json:"snapshots"`
    Errors       []RepoError      `json:"errors,omitempty"`
}

type PeriodSnapshot struct {
    Period       string          `json:"period"`
    Repositories []RepoStats     `json:"repositories"`
    Totals       Stats           `json:"totals"`
    ByLanguage   []LanguageStats `json:"by_language"`
}
```

Each `PeriodSnapshot` is structurally identical to what a single `analyze` run produces, grouped by time period.

## Markdown Rendering

The existing `codemium markdown` command auto-detects `TrendsReport` (presence of `"snapshots"` key) and renders:

- Summary table: one row per period, columns for code/files/comments/complexity with delta from previous period
- Language breakdown: top languages across time
- Per-repo table: each repo's code LOC per period

## Output

JSON only from `trends` command. The `markdown` command handles conversion, auto-detecting report type.
