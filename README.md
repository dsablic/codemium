# Codemium

[![CI](https://github.com/dsablic/codemium/actions/workflows/ci.yml/badge.svg)](https://github.com/dsablic/codemium/actions/workflows/ci.yml)
[![Release](https://github.com/dsablic/codemium/actions/workflows/release.yml/badge.svg)](https://github.com/dsablic/codemium/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dsablic/codemium)](https://goreportcard.com/report/github.com/dsablic/codemium)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Generate code statistics across all repositories in a Bitbucket Cloud workspace or GitHub organization. Produces per-repo and aggregate metrics including lines of code, comments, blanks, and cyclomatic complexity for 200+ languages.

## Features

- Analyze all repos in a Bitbucket workspace or GitHub organization
- Filter by Bitbucket projects, specific repos, or exclusion lists
- Per-language breakdown: files, code lines, comments, blanks, complexity
- JSON output (default) and optional markdown summary
- Parallel processing with configurable concurrency
- Progress bar in terminal, plain text fallback in CI/CD
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
# JSON to stdout (default)
codemium analyze --provider github --org myorg

# JSON to file
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

### Additional flags

```bash
--concurrency 10       # Parallel workers (default: 5)
--include-archived     # Include archived repos (excluded by default)
--include-forks        # Include forked repos (excluded by default)
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
