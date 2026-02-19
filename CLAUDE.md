# CLAUDE.md

## Project Overview

Codemium is a Go CLI tool that generates code statistics (LOC, comments, blanks, cyclomatic complexity) across all repositories in a Bitbucket Cloud workspace or GitHub organization.

## Build & Test

```bash
go build ./cmd/codemium        # Build
go test ./...                  # Run all tests
go test ./... -short           # Run tests (skip slow/integration)
go vet ./...                   # Static analysis
```

## Project Structure

```
cmd/codemium/          CLI entrypoint (Cobra commands, report building)
internal/
  model/               Shared data types (Repo, RepoStats, Report, etc.)
  auth/                OAuth flows + credential storage
    credentials.go     FileStore: ~/.config/codemium/credentials.json
    bitbucket.go       Authorization code grant with local callback server
    github.go          Device flow + gh CLI token fallback
  provider/            Repository listing from APIs
    provider.go        Provider interface definition
    bitbucket.go       Bitbucket Cloud REST API v2.0
    github.go          GitHub REST API
  analyzer/
    analyzer.go        Code analysis using scc as a Go library
    clone.go           Shallow cloning via go-git with token auth
  worker/
    pool.go            Bounded goroutine pool with progress callbacks
  ui/
    progress.go        Bubbletea progress bar (TTY) / plain text fallback
  output/
    json.go            JSON report writer
    markdown.go        Markdown report writer
```

## Key Dependencies

- **scc** (`github.com/boyter/scc/v3`) - Code analysis (LOC, comments, complexity) for 200+ languages, used as a Go library
- **go-git** (`github.com/go-git/go-git/v5`) - Pure Go git client for shallow cloning
- **Cobra** (`github.com/spf13/cobra`) - CLI framework
- **Bubbletea/Bubbles/Lipgloss** - Terminal UI for progress display

## Architecture Notes

- **Provider abstraction**: `provider.Provider` interface allows adding new git hosting providers. Each provider implements `ListRepos(ctx, ListOpts)`.
- **Worker pool**: Bounded goroutine pool with semaphore pattern. Configurable concurrency via `--concurrency` flag.
- **Partial failure**: Repos that fail to clone or analyze are recorded as errors in the report; the run continues.
- **Auth**: Credentials stored at `~/.config/codemium/credentials.json` (0600 perms). Resolution order: env vars (`CODEMIUM_<PROVIDER>_TOKEN`) → saved credentials → `gh auth token` CLI (GitHub only).
- **Clone strategy**: Shallow clone (depth 1, single branch, no tags) to temp dir, deleted after analysis.
- **scc initialization**: `processor.ProcessConstants()` called via `sync.Once` since scc requires global initialization.

## Conventions

- Pure Go, no CGO (`CGO_ENABLED=0`)
- All packages have corresponding `_test.go` files
- Test servers (httptest) used for provider and auth tests
- No external tools required at runtime (no git binary, no scc binary)
- After code changes, update relevant docs (README.md, this file) to reflect new behavior, flags, auth flows, etc.

## Release

Releases are automated via goreleaser on version tags:

```bash
git tag v0.2.0
git push origin v0.2.0
```

This triggers `.github/workflows/release.yml` which builds binaries for Linux/macOS (amd64, arm64) and Windows (amd64).

Version info injected via ldflags: `main.version`, `main.commit`, `main.date`.
