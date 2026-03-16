# CLAUDE.md

## Project Overview

Codemium is a Go CLI tool that generates code statistics (LOC, comments, blanks, cyclomatic complexity) across all repositories in a Bitbucket Cloud workspace, GitHub organization, GitHub user account, or GitLab group.

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
    gitlab.go          glab CLI token fallback
  provider/            Repository listing from APIs
    provider.go        Provider interface definition
    ratelimit.go       Rate-limited HTTP transport (429 retry + token-bucket)
    bitbucket.go       Bitbucket Cloud REST API v2.0
    github.go          GitHub REST API
    gitlab.go          GitLab REST API v4
  analyzer/
    analyzer.go        Code analysis using scc as a Go library
    clone.go           Shallow/full cloning via go-git with token auth + checkout
  churn/
    churn.go           Code churn analysis and hotspot computation
  license/
    license.go         SPDX license detection per repo
  history/
    history.go         Date generation and git commit resolution for trends
  narrative/
    narrative.go       AI CLI detection, prompt building, execution for narrative reports
  worker/
    pool.go            Bounded goroutine pool with progress callbacks (analyze + trends)
  ui/
    progress.go        Bubbletea progress bar (TTY) / plain text fallback
  aidetect/
    detect.go           AI signal detection (co-author, message patterns, bot authors)
  aiestimate/
    estimate.go         AI estimation orchestrator (per-repo commit scanning)
  secrets/
    secrets.go          Gitleaks-based secret scanning per repo
  sbom/
    sbom.go             Syft-based SBOM dependency inventory per repo
  health/
    health.go           Health classification (Classify, ClassifyFromCommits)
    details.go          Deep health analysis (authors, churn, velocity per window)
    summary.go          Aggregate health summary across repos
  output/
    json.go            JSON report writer
    markdown.go        Markdown report writer
```

## Key Dependencies

- **scc** (`github.com/boyter/scc/v3`) - Code analysis (LOC, comments, complexity) for 200+ languages, used as a Go library
- **go-git** (`github.com/go-git/go-git/v5`) - Pure Go git client for shallow cloning
- **go-enry** (`github.com/go-enry/go-enry/v2`) - Vendor, generated, and binary file detection
- **go-license-detector** (`github.com/go-enry/go-license-detector/v4`) - SPDX license detection per directory
- **Cobra** (`github.com/spf13/cobra`) - CLI framework
- **Bubbletea/Bubbles/Lipgloss** - Terminal UI for progress display
- **gitleaks** (`github.com/zricethezav/gitleaks/v8`) - Secret scanning for API keys, tokens, passwords
- **syft** (`github.com/anchore/syft`) - SBOM generation and dependency inventory across ecosystems

## Architecture Notes

- **Provider abstraction**: `provider.Provider` interface allows adding new git hosting providers. Each provider implements `ListRepos(ctx, ListOpts)`.
- **Worker pool**: Bounded goroutine pool with semaphore pattern. Configurable concurrency via `--concurrency` flag.
- **Rate limiting**: `RateLimitTransport` in `provider/ratelimit.go` implements `http.RoundTripper` with token-bucket rate limiting and 429 retry (exponential backoff, `Retry-After` header). Injected via `--rate-limit` flag (default: 0 = unlimited, retry-only). All providers accept `*http.Client` to share the transport.
- **Partial failure**: Repos that fail to clone or analyze are recorded as errors in the report; the run continues.
- **Auth**: Credentials stored at `~/.config/codemium/credentials.json` (0600 perms). Resolution order: env vars (`CODEMIUM_<PROVIDER>_TOKEN`) → saved credentials → CLI fallback (`gh auth token` for GitHub, `glab config get token` for GitLab).
- **Clone strategy**: Shallow clone (depth 1, single branch, no tags) to temp dir, deleted after analysis.
- **scc initialization**: `processor.ProcessConstants()` called via `sync.Once` since scc requires global initialization.
- **AI estimation**: When `--ai-estimate` is used, a second pass fetches commit history via provider REST APIs. `provider.CommitLister` interface provides `ListCommits` and `CommitStats`. `aidetect.Detect` classifies commits, `aiestimate.Estimate` orchestrates per-repo. Results attach to existing report model as optional fields.
- **Health classification**: When `--health` is used, repos are classified as Active (<180d), Maintained (180-365d), or Abandoned (>365d) based on last commit date. Repos where commit history cannot be fetched (API errors, permissions) are classified as Failed with the error message stored in `RepoHealth.Error`. `--health-details` adds deep analysis: per-window author counts, code churn, bus factor, and velocity trend. Uses the same `CommitLister` interface.
- **Error logging**: API errors from health, health-details, AI estimation, and partial commit stat failures are collected and written to `<report>.error.log` (derived from the report path, e.g. `report.error.log` for `report.json`) when any errors occur. Each line is prefixed with a category for easy filtering. `AnalyzeDetails` and `aiestimate.Estimate` return `(result, []string, error)` where `[]string` contains partial error messages.
- **Vendor/generated filtering**: Always-on filtering using `go-enry` to skip vendor, generated, and binary files during analysis. `FilteredFiles` count is tracked per repo and in report totals.
- **License detection**: After analysis, `license.Detect` scans the cloned repo directory for SPDX license identifiers (e.g., "MIT", "Apache-2.0"). Results appear in the per-repo License column.
- **Code churn / hotspots**: Opt-in via `--churn` flag. Uses provider REST APIs to fetch per-file change data (`--churn-limit N` sets max commits, default 500). `churn.Analyze` collects per-file change frequencies; `churn.ComputeHotspots` ranks files by churn x complexity. Top 20 hotspots shown per repo.
- **Durable clone**: When `--clone <dir>` is set, repos are cloned to `<dir>/<repo-slug>/` with a no-op cleanup function. Existing directories are reused without re-cloning (cache behavior). Works with both `Clone()` and `Download()` paths.
- **Secret scanning**: When `--secrets` is used, each repo is scanned for secrets (API keys, tokens, passwords) using gitleaks v8 as a Go library. Runs during the main analysis phase on the cloned directory. Results include finding count and list of files with secrets (no actual secret values). Aggregate summary added to report.
- **SBOM / Dependency inventory**: When `--sbom` is used, each repo is scanned for dependencies using syft as a Go library. Detects packages across ecosystems (Go modules, npm, pip, Maven, etc.). Results include per-repo total dependency count and ecosystem breakdown. Aggregate summary added to report.

## Conventions

- Pure Go, no CGO (`CGO_ENABLED=0`)
- All packages have corresponding `_test.go` files
- Test servers (httptest) used for provider and auth tests
- No external tools required at runtime (no git binary, no scc binary)
- After code changes, update relevant docs (README.md, this file) to reflect new behavior, flags, auth flows, etc. Specifically: new CLI flags go in README's "Additional flags" table and usage examples; new architecture decisions go in the "Architecture Notes" section of this file; new packages go in the "Project Structure" section of this file.

## Release

Releases are automated via goreleaser on version tags:

```bash
git tag v0.2.0
git push origin v0.2.0
```

This triggers `.github/workflows/release.yml` which builds binaries for Linux/macOS (amd64, arm64) and Windows (amd64).

Version info injected via ldflags: `main.version`, `main.commit`, `main.date`.

### Versioning Guidelines

Use semantic versioning (MAJOR.MINOR.PATCH):

- **PATCH** (v0.x.Y): Small changes, bug fixes, minor enhancements
  - Bug fixes in analysis or output
  - Minor UI tweaks
  - Dependency updates (patch/minor)
- **MINOR** (v0.X.0): New features, significant functionality
  - New CLI flags (e.g., `--sbom`, `--secrets`)
  - New provider support
  - New output formats or report sections
  - Major dependency upgrades (e.g., Charm v1 → v2)
- **MAJOR** (vX.0.0): Breaking changes
  - Changed CLI flag names or behavior
  - Changed output format in incompatible ways
  - Removed features or flags
  - Config/credentials format changes
