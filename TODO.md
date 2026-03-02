# TODO: Additional Code Analysis Metrics

Potential off-the-shelf Go libraries to integrate into codemium, ordered by value/impact.

## Tier 1 — High Value, Low Effort

### 1. Vendor/Generated File Filtering
- **Library:** `github.com/go-enry/go-enry/v2`
- **What:** `IsVendor()`, `IsGenerated()`, `IsBinary()` — filter out non-human code from stats
- **Why:** Immediately improves accuracy of existing LOC/complexity metrics across all languages. No new report section needed, just cleaner numbers.
- **Effort:** Small — call before/during scc analysis to exclude files
- **Status: Done** — Always-on filtering via go-enry. `FilteredFiles` count tracked per repo and in report totals.

### 2. License Detection
- **Library:** `github.com/google/licensecheck` (Google, used by pkg.go.dev)
- **Alt:** `github.com/go-enry/go-license-detector/v4/licensedb` (directory-level, SPDX, confidence scores)
- **What:** Detect license per repo, report SPDX identifier
- **Why:** License compliance is a universal concern. Every repo scan benefits from knowing the license. Language-agnostic, lightweight.
- **Effort:** Small — scan LICENSE/COPYING files in cloned repo, add field to RepoStats
- **Status: Done** — Implemented using `go-license-detector/v4`. SPDX license shown in per-repo License column.

### 3. Code Churn / Hotspots (no new dependency)
- **Library:** None — build on existing `go-git`
- **What:** Per-file change frequency, lines added/removed over time, hotspot detection (files that change most often + are most complex)
- **Why:** Churn correlates strongly with bug density. Hotspots (high churn + high complexity) are the most actionable metric for prioritizing refactoring. Already have go-git and commit history access.
- **Effort:** Medium — iterate commit log, accumulate per-file diffs
- **Status: Done** — Opt-in via `--churn` flag (`--churn-limit N` for max commits, default 500). Uses provider REST APIs for per-file change data. Top 20 hotspots (churn x complexity) shown per repo.

## Tier 2 — High Value, Moderate Effort

### 4. Multi-Language Metrics (Coupling, Maintainability)
- **Library:** `github.com/halleck45/ast-metrics`
- **What:** Cyclomatic complexity, Maintainability Index, fan-in/fan-out coupling, LOC — for Go, Python, Rust, PHP
- **Why:** Only multi-language option for coupling and maintainability metrics. Fills the gap scc can't cover. ~128 stars, actively maintained.
- **Effort:** Medium — library API not well-documented, would need to study source. Partial language coverage.

### 5. Security Vulnerability Scanning (Dependencies)
- **Library:** `golang.org/x/vuln/scan` (Go team, official)
- **What:** Scan Go repos for known vulnerabilities in dependencies, with reachability analysis
- **Why:** Security is always high-value. Official Go tooling, trustworthy results. Could report vulnerability count per repo.
- **Effort:** Medium — only works on Go repos, requires module-aware loading

### 6. SBOM / Dependency Inventory
- **Library:** `github.com/anchore/syft` (~8.4k stars, designed as CLI + Go library)
- **What:** Generate Software Bill of Materials — list all dependencies across ecosystems (Go, npm, pip, etc.)
- **Why:** Dependency count, ecosystem breakdown, and supply chain visibility are increasingly required for compliance. Multi-language.
- **Effort:** Medium-high — large dependency footprint, but clean library API
- **Status: Done** — Opt-in via `--sbom` flag. Uses syft as a Go library to detect dependencies across ecosystems (Go, npm, pip, Maven, etc.). Per-repo summary shows total count and ecosystem breakdown.

## Tier 3 — Valuable for Go-Heavy Workspaces

### 7. Cognitive Complexity (Go only)
- **Library:** `github.com/uudashr/gocognit` (~440 stars)
- **What:** Per-function cognitive complexity — measures how hard code is to intuitively understand (different from cyclomatic)
- **Why:** Better predictor of maintainability than cyclomatic complexity. Clean API: `gocognit.Complexity(fset, funcDecl)`.
- **Effort:** Small — but Go source files only

### 8. Maintainability Index (Go only)
- **Library:** `github.com/yagipy/maintidx`
- **What:** Composite score from Halstead volume + cyclomatic complexity + LOC (Microsoft formula)
- **Why:** Single number that summarizes code health per function. Integrated into golangci-lint ecosystem.
- **Effort:** Small — provides `go/analysis.Analyzer`, but Go-only

### 9. Per-Function Cyclomatic Complexity (Go only)
- **Library:** `github.com/fzipp/gocyclo` (~1.5k stars)
- **What:** Per-function cyclomatic complexity (scc gives file-level totals only)
- **Why:** Function-level granularity enables finding the worst offenders. Could report top-N most complex functions.
- **Effort:** Small — clean API, but Go-only

### 10. Security Code Analysis (Go only)
- **Library:** `github.com/securego/gosec/v2` (~8.7k stars)
- **What:** 40+ rules: SQL injection, command injection, hardcoded credentials, weak crypto, path traversal, etc.
- **Why:** Static security issue count per repo is highly actionable. Well-maintained, OWASP project.
- **Effort:** Medium — provides `go/analysis.Analyzer`, Go-only

## Tier 4 — Niche / Lower Priority

### 11. Code Duplication Detection (Go only)
- **Library:** `github.com/mibk/dupl` (~363 stars)
- **What:** Clone detection via suffix trees on serialized ASTs
- **Why:** Duplication is a useful code smell metric, but Go-only and the library API requires wrapping internal packages.
- **Effort:** Medium — not designed as a clean library

### 12. Dead Code Detection (Go only)
- **Library:** `golang.org/x/tools/go/callgraph/rta` (Go team)
- **What:** Find unreachable functions via Rapid Type Analysis
- **Why:** Useful but narrow — only finds dead functions, not dead data. Requires full SSA loading.
- **Effort:** High — needs full program analysis, Go-only

### 13. Dependency Coupling Graphs (Go only)
- **Library:** `golang.org/x/tools/refactor/importgraph` (Go team)
- **What:** Forward/reverse import graphs, fan-in/fan-out per package
- **Why:** Useful for architectural analysis but requires building metrics on top of raw graph data.
- **Effort:** Medium — low-level, you build the metrics yourself

### 14. Dependency License Checking
- **Library:** `github.com/ribice/glice/v2`
- **What:** Fetch license info for each dependency from GitHub
- **Why:** Complementary to repo-level license detection, but limited to Go deps on GitHub and rate-limited.
- **Effort:** Small — but narrow scope

### 15. Halstead Metrics (Go only)
- **Library:** `github.com/shoooooman/go-complexity-analysis`
- **What:** Halstead volume, difficulty, effort, vocabulary, length
- **Why:** Academic interest, feeds into Maintainability Index. Small community (~25 stars).
- **Effort:** Small — but poorly documented API, Go-only
