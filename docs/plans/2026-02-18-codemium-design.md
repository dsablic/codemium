# Codemium Design

A Go CLI tool that generates code statistics (LOC, comments, complexity) across all repositories in a Bitbucket Cloud workspace or GitHub organization.

## CLI Interface

```
# Authenticate
codemium auth login --provider bitbucket
codemium auth login --provider github

# Run analysis
codemium analyze --provider bitbucket --workspace myworkspace [flags]
codemium analyze --provider github --org myorg [flags]

# Flags
--projects "PROJ1,PROJ2"    # filter by Bitbucket projects (ignored for GitHub)
--repos "repo1,repo2"       # filter to specific repos by name
--exclude "repo3,repo4"     # exclude specific repos
--include-archived           # include archived repos (excluded by default)
--include-forks              # include forks (excluded by default)
--concurrency 10             # parallel clone+analyze workers (default: 5)
--output stats.json          # write JSON to file (default: stdout)
--markdown report.md         # generate markdown summary
```

## Architecture

```
codemium/
├── cmd/
│   └── codemium/
│       └── main.go              # CLI entrypoint (cobra)
├── internal/
│   ├── auth/
│   │   ├── auth.go              # Auth interface + token storage
│   │   ├── oauth.go             # Browser-based OAuth flow (local callback server)
│   │   └── credentials.go       # Read/write ~/.config/codemium/credentials.json
│   ├── provider/
│   │   ├── provider.go          # Provider interface (ListRepos)
│   │   ├── bitbucket.go         # Bitbucket Cloud REST API v2.0
│   │   └── github.go            # GitHub REST API
│   ├── analyzer/
│   │   ├── analyzer.go          # Wraps scc processor, returns structured results
│   │   └── clone.go             # go-git shallow clone to temp dir + cleanup
│   ├── worker/
│   │   └── pool.go              # Bounded goroutine pool with progress reporting
│   └── output/
│       ├── json.go              # JSON serializer
│       └── markdown.go          # Markdown summary via text/template
├── go.mod
└── go.sum
```

### Key Interfaces

```go
type Provider interface {
    ListRepos(ctx context.Context, opts ListOpts) ([]Repo, error)
}

type Analyzer interface {
    Analyze(ctx context.Context, dir string) (*RepoStats, error)
}
```

### Data Flow

```
ListRepos -> filter -> worker pool -> (clone -> analyze -> cleanup) per repo -> aggregate -> output
```

Worker pool processes repos concurrently (default 5 workers). Each worker clones via go-git, analyzes via scc library, cleans up temp dir, sends results on a channel. Main goroutine collects results, aggregates totals, writes output.

## Key Dependencies

- **scc** (`github.com/boyter/scc/v3`): Used as a Go library for code analysis. Provides LOC, comments, blanks, cyclomatic complexity for 200+ languages. No subprocess overhead.
- **go-git** (`github.com/go-git/go-git/v5`): Pure Go git client for shallow cloning. No external git binary required. Auth tokens injected programmatically.
- **cobra**: CLI framework.
- **bubbletea/bubbles/lipgloss** (charmbracelet): Terminal UI for progress bars, spinners, per-repo status. Falls back to plain text when stdout is not a TTY (piped).

## Authentication

### Browser-based OAuth (interactive)

**Bitbucket Cloud:** Authorization code grant flow.
1. Open browser to Bitbucket authorize URL
2. Local HTTP server on `:9876` catches callback with auth code
3. Exchange code for access + refresh tokens
4. Store in `~/.config/codemium/credentials.json`
5. Auto-refresh on expiry

**GitHub:** Device flow (like `gh auth login`).
1. POST to GitHub device code endpoint
2. Display user code in terminal, open browser
3. Poll for authorization
4. Store token

### Environment variable tokens (non-interactive)

For CI/CD: `CODEMIUM_BITBUCKET_TOKEN` or `CODEMIUM_GITHUB_TOKEN` env vars. Takes precedence over stored credentials when present.

### OAuth App Credentials

User registers their own OAuth app and provides client ID/secret via:
- `CODEMIUM_BITBUCKET_CLIENT_ID`, `CODEMIUM_BITBUCKET_CLIENT_SECRET`
- `CODEMIUM_GITHUB_CLIENT_ID`
- Or a config file

### Credentials Storage

```json
{
  "bitbucket": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_at": "2026-02-18T13:00:00Z"
  },
  "github": {
    "access_token": "..."
  }
}
```

Stored at `~/.config/codemium/credentials.json` (XDG-compliant).

## Data Model

### Per-repo stats

```json
{
  "repository": "my-repo",
  "project": "PROJ1",
  "provider": "bitbucket",
  "url": "https://bitbucket.org/workspace/my-repo",
  "languages": [
    {
      "name": "Go",
      "files": 42,
      "lines": 8500,
      "code": 6200,
      "comments": 1100,
      "blanks": 1200,
      "complexity": 320
    }
  ],
  "totals": {
    "files": 52,
    "lines": 10000,
    "code": 7300,
    "comments": 1300,
    "blanks": 1400,
    "complexity": 405
  }
}
```

### Top-level output

```json
{
  "generated_at": "2026-02-18T12:00:00Z",
  "provider": "bitbucket",
  "workspace": "myworkspace",
  "filters": { "projects": ["PROJ1"] },
  "repositories": [ "..." ],
  "totals": {
    "repos": 87,
    "files": 4200,
    "lines": 850000,
    "code": 620000,
    "comments": 110000,
    "blanks": 120000,
    "complexity": 32000
  },
  "by_language": [
    { "name": "Go", "files": 1200, "code": 300000, "comments": 50000, "blanks": 40000, "complexity": 15000 }
  ],
  "errors": [
    { "repository": "broken-repo", "error": "clone failed: permission denied" }
  ]
}
```

### Markdown Summary

Table-based report: top languages by LOC, per-repo breakdown, totals row.

## Error Handling

- **Partial failure model**: complete as many repos as possible, report failures in `errors` array
- **Clone failures**: logged, repo skipped
- **Rate limiting**: exponential backoff with jitter on 429 responses
- **Token expiry mid-run**: auto-refresh, retry
- **scc failure on repo**: capture error, skip repo
- **Ctrl+C**: graceful shutdown via context cancellation, output results collected so far

## Repo Filtering

- Archived repos: excluded by default (`--include-archived` to opt in)
- Forks: excluded by default (`--include-forks` to opt in)
- Empty repos: skipped, noted in errors array

## Clone Strategy

- `go-git` shallow clone (depth 1, single branch, default branch only)
- Auth token injected via `http.BasicAuth` in go-git transport options
- Temp dirs cleaned up via `defer` (even on panic)
- No SSH key setup required
