# Durable Clone & Secret Scanning Design

**Date:** 2026-03-02
**Issues:** #7 (Secret Scanning), #8 (Durable Clone)

## Feature #8: Durable Clone (`--clone`)

### New Flag

`--clone <directory>` on the `analyze` command.

### Behavior

- When set, repos clone to `<directory>/<repo-slug>/` instead of `os.MkdirTemp`.
- The cleanup function becomes a no-op (repos persist after analysis).
- If `<directory>/<repo-slug>/` already exists, skip cloning entirely and analyze the existing directory.
- The directory is created automatically if it doesn't exist (`os.MkdirAll`).
- Works with both `Clone()` and `Download()` paths.

### Changes

- **`analyzer/clone.go`** — Add `CloneTo(ctx, cloneURL, destDir)` and `DownloadTo(ctx, url, destDir)` methods that return a no-op cleanup. If `destDir` exists, return immediately.
- **`cmd/codemium/main.go`** — New `--clone` string flag. In the analysis worker, branch on whether `--clone` is set to choose between temp clone and durable clone.

## Feature #7: Secret Scanning (`--secrets`)

### New Flag

`--secrets` (bool, default false) on the `analyze` command.

### New Package

`internal/secrets/secrets.go`

### Behavior

- Opt-in via `--secrets`, same pattern as `--churn` and `--health`.
- Runs during the main analysis phase (inside the same worker callback, after `Analyze()` and `license.Detect()`) since it needs the cloned directory before cleanup.
- Uses gitleaks `detect` package to scan working tree files.
- Results attached to `RepoStats` as an optional `*SecretsReport` field.

### Model Additions

In `internal/model/model.go`:

```go
type SecretsReport struct {
    FindingsCount    int      `json:"findings_count"`
    FilesWithSecrets []string `json:"files_with_secrets,omitempty"`
}

type SecretsAggregate struct {
    TotalFindings     int `json:"total_findings"`
    ReposWithSecrets  int `json:"repos_with_secrets"`
}
```

### `secrets.Scan(dir string) (*SecretsReport, error)`

- Loads the default gitleaks config (built-in rules).
- Runs file-only detection on the directory.
- Deduplicates files, counts findings.
- Never includes actual secret values in output.

### Report Integration

- Per-repo: `SecretsReport` field on `RepoStats`.
- Aggregate: `*SecretsAggregate` field on `Report` with total findings count and repos-with-secrets count.
- Markdown output: column showing finding count per repo, summary row.
