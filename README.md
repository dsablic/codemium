# Codemium

[![CI](https://github.com/dsablic/codemium/actions/workflows/ci.yml/badge.svg)](https://github.com/dsablic/codemium/actions/workflows/ci.yml)
[![Release](https://github.com/dsablic/codemium/actions/workflows/release.yml/badge.svg)](https://github.com/dsablic/codemium/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dsablic/codemium)](https://goreportcard.com/report/github.com/dsablic/codemium)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Generate code statistics across all repositories in a Bitbucket Cloud workspace, GitHub organization, GitHub user account, or GitLab group. Produces per-repo and aggregate metrics including lines of code, comments, blanks, and cyclomatic complexity for 200+ languages.

## Features

- Analyze all repos in a Bitbucket workspace, GitHub organization, GitHub user account, or GitLab group
- Filter by Bitbucket projects, specific repos, or exclusion lists
- Per-language breakdown: files, code lines, comments, blanks, complexity
- Automatic vendor/generated/binary file filtering for accurate metrics (powered by go-enry)
- Per-repo license detection with SPDX identifiers (e.g., MIT, Apache-2.0)
- Code churn and hotspot analysis: find files that change most often and are most complex
- JSON output to file (default: `output/report.json`) and optional markdown summary
- Parallel processing with configurable concurrency
- Progress bar in terminal, plain text fallback in CI/CD
- AI code estimation: detect AI-assisted commits via co-author tags, message patterns, and bot authors
- Pure Go, no external dependencies at runtime (no git or scc binary needed)

## Installation

### Homebrew

```bash
brew install dsablic/tap/codemium
```

### Pre-built binaries

Download from the [releases page](https://github.com/dsablic/codemium/releases).

### From source

```bash
go install github.com/dsablic/codemium/cmd/codemium@latest
```

## Authentication

Codemium supports interactive API token login and environment variable tokens.

### Bitbucket

**Option 1: API token (interactive)**

1. Create a scoped API token at https://id.atlassian.com/manage-profile/security/api-tokens — click **"Create API token with scopes"**, select **Bitbucket** as the app, and enable **Repository Read**
2. Run:
   ```bash
   codemium auth login --provider bitbucket
   ```
   This prompts for your Atlassian email and API token. Credentials are verified against the Bitbucket API and stored at `~/.config/codemium/credentials.json`.

**Option 2: Environment variable (CI/CD)**

```bash
export CODEMIUM_BITBUCKET_USERNAME=your_email
export CODEMIUM_BITBUCKET_TOKEN=your_api_token
```

### GitHub

**Option 1: gh CLI (recommended)**

If you already have the [GitHub CLI](https://cli.github.com/) installed and authenticated, codemium uses its token automatically — no extra setup needed:

```bash
# If not already authenticated:
gh auth login

# Then just run codemium directly:
codemium analyze --provider github --org myorg
```

You can also explicitly save the token to codemium's credential store:

```bash
codemium auth login --provider github
```

**Option 2: OAuth device flow**

If you have a GitHub OAuth App, you can use the device flow instead:

```bash
export CODEMIUM_GITHUB_CLIENT_ID=your_client_id
codemium auth login --provider github
```

This displays a code to enter at github.com/login/device.

**Option 3: Environment variable (CI/CD)**

```bash
export CODEMIUM_GITHUB_TOKEN=your_personal_access_token
```

**Resolution order:** `CODEMIUM_GITHUB_TOKEN` env var > saved credentials > `gh auth token` CLI.

### GitLab

**Option 1: Personal access token (interactive)**

1. Create a personal access token at https://gitlab.com/-/user_settings/personal_access_tokens with the `read_api` scope
2. Run:
   ```bash
   codemium auth login --provider gitlab
   ```
   This prompts for your token, verifies it against the GitLab API, and stores it at `~/.config/codemium/credentials.json`.

**Option 2: glab CLI**

If you have the [GitLab CLI](https://gitlab.com/gitlab-org/cli) installed and authenticated, codemium can use its token automatically:

```bash
glab auth login
codemium analyze --provider gitlab --group mygroup
```

**Option 3: Environment variable (CI/CD)**

```bash
export CODEMIUM_GITLAB_TOKEN=your_personal_access_token
```

**Resolution order:** `CODEMIUM_GITLAB_TOKEN` env var > saved credentials > `glab config get token` CLI.

## Usage

### Analyze a Bitbucket workspace

```bash
# All repos in a workspace
codemium analyze --provider bitbucket --workspace myworkspace

# Filter by Bitbucket projects
codemium analyze --provider bitbucket --workspace myworkspace --projects PROJ1,PROJ2

# Specific repos only
codemium analyze --provider bitbucket --workspace myworkspace --repos repo1,repo2

# Exclude repos
codemium analyze --provider bitbucket --workspace myworkspace --exclude old-repo,deprecated-repo
```

### Analyze a GitHub organization

```bash
# All repos in an org
codemium analyze --provider github --org myorg

# Specific repos
codemium analyze --provider github --org myorg --repos api,frontend
```

### Analyze a GitHub user's repos

```bash
# All repos for a user (includes private repos the token has access to)
codemium analyze --provider github --user myuser

# Specific repos
codemium analyze --provider github --user myuser --repos repo1,repo2
```

### Analyze a GitLab group

```bash
# All repos in a group (includes subgroups)
codemium analyze --provider gitlab --group mygroup

# Nested group
codemium analyze --provider gitlab --group myorg/mysubgroup

# Specific repos
codemium analyze --provider gitlab --group mygroup --repos api,frontend
```

### Analyze trends over time

The `trends` command analyzes repositories at historical points in time using git history, showing how codebases evolve over configurable intervals.

```bash
# Monthly trends for the past year
codemium trends --provider github --org myorg --since 2025-03 --until 2026-02

# Weekly trends
codemium trends --provider github --org myorg --since 2025-01-01 --until 2025-03-01 --interval weekly

# Output to file, then convert to markdown
codemium trends --provider github --org myorg --since 2025-01 --until 2025-12 --output trends.json
codemium markdown trends.json > trends.md
```

**Note:** For Bitbucket, `trends` requires OAuth credentials (not API tokens), since it needs to clone full git history. Set `CODEMIUM_BITBUCKET_CLIENT_ID` and `CODEMIUM_BITBUCKET_CLIENT_SECRET`, then run `codemium auth login --provider bitbucket`.

### Output options

```bash
# JSON to default file (output/report.json)
codemium analyze --provider github --org myorg

# JSON to custom file
codemium analyze --provider github --org myorg --output report.json

# Markdown summary
codemium analyze --provider github --org myorg --markdown report.md

# Both
codemium analyze --provider github --org myorg --output report.json --markdown report.md
```

### AI narrative analysis

Generate a rich narrative analysis of your codebase using an AI CLI:

```bash
# Auto-detect AI CLI (tries claude, codex, gemini in order)
codemium markdown --narrative report.json

# Use a specific AI CLI
codemium markdown --narrative --ai-cli gemini report.json

# Add custom instructions
codemium markdown --narrative --ai-prompt "Focus on test coverage gaps" report.json

# Load instructions from file
codemium markdown --narrative --ai-prompt-file analysis-prompt.txt report.json

# Works with trends reports too
codemium markdown --narrative trends.json
```

Requires one of: [Claude Code](https://claude.com/claude-code), [Codex CLI](https://github.com/openai/codex), or [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed and authenticated.

**Providing context for better narratives:** The AI generates richer analysis when given domain context about your organization. Use `--ai-prompt` or `--ai-prompt-file` to describe project areas, team structure, or what specific repos contain:

```bash
# Inline context
codemium markdown --narrative --ai-prompt 'Project codes map to these areas:
- SVC = Backend Services
- WEB = Customer-Facing Web Apps
- MOB = Mobile Apps (iOS & Android)
- PLAT = Platform & Infrastructure
- SDK = Public SDKs and Client Libraries

The SVC repos include both microservices and shared libraries.
The PLAT team also maintains CI/CD pipelines.' report.json

# Or load from a file for longer descriptions
codemium markdown --narrative --ai-prompt-file org-context.txt report.json
```

This is especially useful when Bitbucket project codes or repo naming conventions aren't self-explanatory — the AI will use your descriptions to assign human-readable names and provide more insightful analysis.

### Repository health classification

Classify repositories as Active, Maintained, Abandoned, or Failed based on commit history:

```bash
# Quick health check (1 API call per repo, no cloning)
codemium analyze --provider github --org myorg --health

# Deep health analysis with author counts, churn, and velocity per window
codemium analyze --provider github --org myorg --health-details

# Limit commits scanned for deep analysis (default: 500)
codemium analyze --provider github --org myorg --health-details --health-commit-limit 200
```

Health categories:
- **Active**: last commit < 180 days ago
- **Maintained**: 180–365 days ago
- **Abandoned**: > 365 days ago
- **Failed**: commit history could not be fetched (API error, permissions, etc.)

### Persistent cloning

By default, repos are cloned to a temp directory and deleted after analysis. Use `--clone` to keep them:

```bash
# Clone repos to ./repos/<repo-slug>/ and keep them after analysis
codemium analyze --provider github --org myorg --clone ./repos

# Subsequent runs reuse existing clones (no re-download)
codemium analyze --provider github --org myorg --clone ./repos
```

### Secret scanning

Scan repositories for leaked secrets (API keys, tokens, passwords) using gitleaks:

```bash
codemium analyze --provider github --org myorg --secrets
```

Results show per-repo finding counts and which files contain secrets (actual secret values are never included in the report).

### Rate limiting and error logging

API requests that receive a 429 (Too Many Requests) response are automatically retried with exponential backoff (up to 5 retries). Use `--rate-limit` to proactively throttle requests and avoid hitting rate limits (e.g., `--rate-limit 5` for GitLab's 300 req/min raw endpoint limit).

When API errors occur during health classification, AI estimation, or detailed analysis, an error log is automatically written next to the JSON report (e.g., `output/report.error.log` for `output/report.json`). Each line is prefixed with a category (`[health]`, `[health-details]`, `[ai-estimate]`, `[ai-estimate-detail]`) for easy filtering with `grep`.

### Additional flags

```bash
--concurrency 10            # Parallel workers (default: 5)
--rate-limit 5              # Max API requests per second (default: unlimited)
--include-archived          # Include archived repos (excluded by default)
--include-forks             # Include forked repos (excluded by default)
--ai-estimate               # Estimate AI-generated code via commit history analysis
--ai-commit-limit 200       # Max commits to scan per repo (default: 200)
--health                    # Classify repos by activity level
--health-details            # Deep health analysis (implies --health)
--health-commit-limit 500   # Max commits for health details (default: 500)
--churn                     # Enable code churn and hotspot analysis
--churn-limit 500           # Max commits to scan per repo for churn (default: 500)
--clone ./repos                 # Persist cloned repos to directory (reuses existing clones)
--secrets                       # Scan repos for secrets (API keys, tokens, passwords)
```

## Output Format

### JSON

```json
{
  "generated_at": "2026-02-18T12:00:00Z",
  "provider": "github",
  "organization": "myorg",
  "filters": {},
  "repositories": [
    {
      "repository": "my-repo",
      "provider": "github",
      "url": "https://github.com/myorg/my-repo",
      "languages": [
        {
          "name": "Go",
          "files": 42,
          "lines": 5000,
          "code": 3800,
          "comments": 400,
          "blanks": 800,
          "complexity": 120
        }
      ],
      "totals": {
        "files": 42,
        "lines": 5000,
        "code": 3800,
        "comments": 400,
        "blanks": 800,
        "complexity": 120
      }
    }
  ],
  "totals": {
    "repos": 1,
    "files": 42,
    "lines": 5000,
    "code": 3800,
    "comments": 400,
    "blanks": 800,
    "complexity": 120
  },
  "by_language": [
    {
      "name": "Go",
      "files": 42,
      "lines": 5000,
      "code": 3800,
      "comments": 400,
      "blanks": 800,
      "complexity": 120
    }
  ]
}
```

### Markdown

The `--markdown` flag generates a GitHub-flavored markdown report with:

- Summary table with aggregate metrics
- Language breakdown sorted by code lines
- Per-repository table with links
- Error section for repos that failed to process

## License

MIT License - see [LICENSE](LICENSE) for details.
