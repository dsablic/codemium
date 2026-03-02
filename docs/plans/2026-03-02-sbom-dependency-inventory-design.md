# SBOM / Dependency Inventory Design

**Date:** 2026-03-02
**TODO item:** #6

## Feature: SBOM / Dependency Inventory (`--sbom`)

### New Flag

`--sbom` (bool, default false) on the `analyze` command.

### New Package

`internal/sbom/sbom.go`

### Behavior

- Opt-in via `--sbom`, same pattern as `--secrets`.
- Runs during the main analysis phase (inside the worker callback, after `license.Detect()`).
- Uses syft's `GetSource()` + `CreateSBOM()` to scan the cloned directory.
- Iterates the package catalog to count dependencies and group by ecosystem.
- Results attached to `RepoStats` as an optional `*SBOMReport` field.

### Model Additions

In `internal/model/model.go`:

```go
type EcosystemDeps struct {
    Ecosystem string `json:"ecosystem"`
    Count     int    `json:"count"`
}

type SBOMReport struct {
    TotalDeps  int             `json:"total_deps"`
    Ecosystems []EcosystemDeps `json:"ecosystems,omitempty"`
}

type SBOMAggregate struct {
    TotalDeps     int             `json:"total_deps"`
    ReposWithDeps int             `json:"repos_with_deps"`
    Ecosystems    []EcosystemDeps `json:"ecosystems,omitempty"`
}
```

### `sbom.Scan(ctx, dir string) (*SBOMReport, error)`

- Creates a syft source from the directory via `syft.GetSource()`.
- Generates SBOM via `syft.CreateSBOM()`.
- Iterates package catalog, counts per ecosystem (e.g. "go-module", "npm", "pip").
- Returns summary with total count and per-ecosystem breakdown.

### Report Integration

- Per-repo: `SBOMReport` field on `RepoStats`.
- Aggregate: `*SBOMAggregate` field on `Report` with total deps, repos-with-deps, and merged ecosystem breakdown.
- Markdown output: dependency count column per repo, ecosystem breakdown summary section.
