# Narrative Generation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `--narrative` flag to the `markdown` command that pipes JSON reports through an AI CLI to generate rich narrative analysis.

**Architecture:** New `internal/narrative` package handles CLI detection, prompt building, and execution. The `markdown` command gains flags to enable narrative mode, pick the AI CLI, and pass custom instructions. JSON report bytes are piped to the CLI's stdin with a built-in prompt; stdout is captured as the output markdown.

**Tech Stack:** Go `os/exec` for CLI invocation, existing `cmd/codemium/main.go` for flag wiring.

---

### Task 1: Create narrative package with CLI detection

**Files:**
- Create: `internal/narrative/narrative.go`
- Create: `internal/narrative/narrative_test.go`

**Step 1: Write the failing test**

Create `internal/narrative/narrative_test.go`:

```go
package narrative_test

import (
	"testing"

	"github.com/dsablic/codemium/internal/narrative"
)

func TestSupportedCLIs(t *testing.T) {
	supported := narrative.SupportedCLIs()
	if len(supported) != 3 {
		t.Fatalf("expected 3 supported CLIs, got %d", len(supported))
	}
	expected := []string{"claude", "codex", "gemini"}
	for i, name := range expected {
		if supported[i] != name {
			t.Errorf("expected supported[%d] = %s, got %s", i, name, supported[i])
		}
	}
}

func TestDetectCLI_Fallback(t *testing.T) {
	// DetectCLI with a custom lookup that finds nothing
	_, err := narrative.DetectCLIWith(func(name string) (string, error) {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	})
	if err == nil {
		t.Error("expected error when no CLI found")
	}
}

func TestDetectCLI_FindsClaude(t *testing.T) {
	cli, err := narrative.DetectCLIWith(func(name string) (string, error) {
		if name == "claude" {
			return "/usr/bin/claude", nil
		}
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli != "claude" {
		t.Errorf("expected claude, got %s", cli)
	}
}

func TestDetectCLI_PrefersOrder(t *testing.T) {
	// All available, should pick claude (first in order)
	cli, err := narrative.DetectCLIWith(func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli != "claude" {
		t.Errorf("expected claude (first in priority), got %s", cli)
	}
}
```

Note: needs `"os/exec"` import for `exec.Error` and `exec.ErrNotFound`.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/narrative/ -v`
Expected: FAIL — package doesn't exist.

**Step 3: Write minimal implementation**

Create `internal/narrative/narrative.go`:

```go
package narrative

import (
	"fmt"
	"os/exec"
	"strings"
)

var supportedCLIs = []string{"claude", "codex", "gemini"}

// SupportedCLIs returns the list of supported AI CLI names in detection priority order.
func SupportedCLIs() []string {
	return supportedCLIs
}

// LookupFunc is a function that checks if a CLI binary exists in PATH.
type LookupFunc func(name string) (string, error)

// DetectCLI finds the first available AI CLI in PATH.
func DetectCLI() (string, error) {
	return DetectCLIWith(exec.LookPath)
}

// DetectCLIWith finds the first available AI CLI using the provided lookup function.
func DetectCLIWith(lookup LookupFunc) (string, error) {
	for _, name := range supportedCLIs {
		if _, err := lookup(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no supported AI CLI found in PATH (install one of: %s)", strings.Join(supportedCLIs, ", "))
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/narrative/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/narrative/
git commit -m "feat: add narrative package with AI CLI detection"
```

---

### Task 2: Add prompt building and CLI execution

**Files:**
- Modify: `internal/narrative/narrative.go`
- Modify: `internal/narrative/narrative_test.go`

**Step 1: Write the failing test**

Add to `internal/narrative/narrative_test.go`:

```go
func TestBuildArgs(t *testing.T) {
	tests := []struct {
		cli      string
		prompt   string
		wantCmd  string
		wantArgs []string
	}{
		{"claude", "analyze this", "claude", []string{"-p", "analyze this"}},
		{"codex", "analyze this", "codex", []string{"exec", "analyze this"}},
		{"gemini", "analyze this", "gemini", []string{"-p", "analyze this"}},
	}

	for _, tt := range tests {
		t.Run(tt.cli, func(t *testing.T) {
			cmd, args := narrative.BuildArgs(tt.cli, tt.prompt)
			if cmd != tt.wantCmd {
				t.Errorf("cmd = %s, want %s", cmd, tt.wantCmd)
			}
			if len(args) != len(tt.wantArgs) {
				t.Fatalf("args len = %d, want %d: %v", len(args), len(tt.wantArgs), args)
			}
			for i, a := range args {
				if a != tt.wantArgs[i] {
					t.Errorf("args[%d] = %s, want %s", i, a, tt.wantArgs[i])
				}
			}
		})
	}
}

func TestDefaultPromptContainsInstructions(t *testing.T) {
	p := narrative.DefaultPrompt("")
	if !strings.Contains(p, "markdown") {
		t.Error("default prompt should mention markdown")
	}
	if !strings.Contains(p, "JSON") {
		t.Error("default prompt should mention JSON")
	}
}

func TestDefaultPromptAppendsCustom(t *testing.T) {
	p := narrative.DefaultPrompt("Focus on security repos")
	if !strings.Contains(p, "Focus on security repos") {
		t.Error("default prompt should contain custom instructions")
	}
}
```

Note: needs `"strings"` import.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/narrative/ -run "TestBuildArgs|TestDefaultPrompt" -v`
Expected: FAIL — `BuildArgs` and `DefaultPrompt` undefined.

**Step 3: Write implementation**

Add to `internal/narrative/narrative.go`:

```go
import (
	"bytes"
	"context"
	"io"
)

// BuildArgs returns the command name and arguments for invoking the given AI CLI
// in non-interactive mode with the given prompt.
func BuildArgs(cli, prompt string) (string, []string) {
	switch cli {
	case "codex":
		return "codex", []string{"exec", prompt}
	case "gemini":
		return "gemini", []string{"-p", prompt}
	default: // claude
		return "claude", []string{"-p", prompt}
	}
}

// DefaultPrompt returns the built-in prompt for narrative generation.
// If extra is non-empty, it is appended as additional instructions.
func DefaultPrompt(extra string) string {
	prompt := `You are a technical writer analyzing a codebase statistics report in JSON format provided via stdin.

The input is a JSON report from the "codemium" tool. It may be one of two formats:

1. **Standard Report** (has "repositories" key): A point-in-time snapshot with per-repo stats, totals, and language breakdowns.
2. **Trends Report** (has "snapshots" key): A time-series with multiple period snapshots, each containing per-repo stats.

Your job is to produce a comprehensive markdown document analyzing this data. Output ONLY valid markdown — no code fences wrapping the entire output, no preamble like "Here is the analysis".

## For Standard Reports:

- Start with a title, summary header (total repos, total code lines, top languages, generated date)
- Write a "High-Level Overview" section (2-3 paragraphs) that:
  - Summarizes the overall codebase scope and architecture
  - Groups repositories by project keys or naming patterns into logical product areas
  - Identifies outliers (very large repos that skew totals, repos with unusual comment ratios)
  - Notes the distribution of languages and what it reveals about the tech stack
- Add a "Summary by Product Area" table with columns: Product Area, Repos, Code Lines, Comment Lines, Comment %, Complexity
- Add a "Top 10 Repositories by Code Size" table
- For each product area, add a section with a summary line and per-repo table (columns: Repo with link, Code Lines, Comment %, Complexity)
- Use number formatting with commas for readability (e.g., 1,234,567)
- Compute derived metrics: comment ratio (comments / (code + comments) * 100), and note patterns

## For Trends Reports:

- Start with a title and summary of the time range and interval
- Write a "High-Level Overview" analyzing growth/decline trajectory
- Identify the fastest-growing and shrinking repos/languages
- Note any inflection points or notable changes between periods
- Add a summary table showing totals per period with deltas
- Add per-repo growth tables for the most interesting repos
- Comment on what the trends suggest about development focus and priorities`

	if extra != "" {
		prompt += "\n\n## Additional Instructions\n\n" + extra
	}

	return prompt
}

// Generate runs the AI CLI with the given JSON report data and returns the narrative markdown.
func Generate(ctx context.Context, cli string, jsonData []byte, prompt string) (string, error) {
	cmdName, args := BuildArgs(cli, prompt)

	cmd := exec.CommandContext(ctx, cmdName, args...)
	cmd.Stdin = bytes.NewReader(jsonData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg != "" {
			return "", fmt.Errorf("%s failed: %w\n%s", cli, err, errMsg)
		}
		return "", fmt.Errorf("%s failed: %w", cli, err)
	}

	return stdout.String(), nil
}
```

Note: `io` import can be removed if unused; keep `bytes`, `context`, `fmt`, `os/exec`, `strings`.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/narrative/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/narrative/
git commit -m "feat: add prompt building and CLI execution for narrative"
```

---

### Task 3: Wire narrative flags into markdown command

**Files:**
- Modify: `cmd/codemium/main.go`

**Step 1: Add flags to newMarkdownCmd**

In `cmd/codemium/main.go`, update `newMarkdownCmd()` to add the narrative flags:

```go
func newMarkdownCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "markdown [file]",
		Short: "Convert JSON report to markdown",
		Long:  "Reads a JSON report from a file argument or stdin and writes markdown to stdout.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runMarkdown,
	}

	cmd.Flags().Bool("narrative", false, "Generate AI narrative analysis instead of tables")
	cmd.Flags().String("ai-cli", "", "AI CLI to use (claude, codex, gemini). Default: auto-detect")
	cmd.Flags().String("ai-prompt", "", "Additional instructions for the AI narrative")
	cmd.Flags().String("ai-prompt-file", "", "Read additional AI instructions from file")

	return cmd
}
```

**Step 2: Update runMarkdown to handle narrative mode**

Replace the `runMarkdown` function:

```go
func runMarkdown(cmd *cobra.Command, args []string) error {
	var r io.Reader = os.Stdin
	if len(args) == 1 {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("open file: %w", err)
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	useNarrative, _ := cmd.Flags().GetBool("narrative")

	if useNarrative {
		return runNarrative(cmd, data)
	}

	// Auto-detect report type: try TrendsReport first
	var trends model.TrendsReport
	if err := json.Unmarshal(data, &trends); err == nil && len(trends.Snapshots) > 0 {
		return output.WriteTrendsMarkdown(os.Stdout, trends)
	}

	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parse JSON report: %w", err)
	}

	return output.WriteMarkdown(os.Stdout, report)
}

func runNarrative(cmd *cobra.Command, data []byte) error {
	aiCLI, _ := cmd.Flags().GetString("ai-cli")
	aiPrompt, _ := cmd.Flags().GetString("ai-prompt")
	aiPromptFile, _ := cmd.Flags().GetString("ai-prompt-file")

	if aiPrompt != "" && aiPromptFile != "" {
		return fmt.Errorf("--ai-prompt and --ai-prompt-file are mutually exclusive")
	}

	if aiPromptFile != "" {
		content, err := os.ReadFile(aiPromptFile)
		if err != nil {
			return fmt.Errorf("read prompt file: %w", err)
		}
		aiPrompt = string(content)
	}

	if aiCLI == "" {
		detected, err := narrative.DetectCLI()
		if err != nil {
			return err
		}
		aiCLI = detected
		fmt.Fprintf(os.Stderr, "Using %s for narrative generation\n", aiCLI)
	}

	prompt := narrative.DefaultPrompt(aiPrompt)

	ctx := cmd.Context()
	result, err := narrative.Generate(ctx, aiCLI, data, prompt)
	if err != nil {
		return fmt.Errorf("narrative generation: %w", err)
	}

	fmt.Fprint(os.Stdout, result)
	return nil
}
```

Add `"github.com/dsablic/codemium/internal/narrative"` to the imports.

**Step 3: Verify build**

Run: `go build ./cmd/codemium`
Expected: builds without errors.

**Step 4: Verify help text**

Run: `./codemium markdown --help`
Expected: shows `--narrative`, `--ai-cli`, `--ai-prompt`, `--ai-prompt-file` flags.

**Step 5: Commit**

```bash
git add cmd/codemium/main.go
git commit -m "feat: wire narrative flags into markdown command"
```

---

### Task 4: Update docs

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

**Step 1: Add narrative section to README**

Add after the "Output options" section:

```markdown
### AI narrative analysis

Generate a rich narrative analysis of your codebase using an AI CLI:

\```bash
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
\```

Requires one of: [Claude Code](https://claude.com/claude-code), [Codex CLI](https://github.com/openai/codex), or [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed and authenticated.
```

**Step 2: Update CLAUDE.md project structure**

Add to the project structure:

```
  narrative/
    narrative.go       AI CLI detection, prompt building, execution
```

**Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: add narrative generation usage and update project structure"
```

---

### Task 5: Run full test suite and verify build

**Step 1: Run all tests**

Run: `go test ./... -short -v`
Expected: All tests pass.

**Step 2: Run vet**

Run: `go vet ./...`
Expected: No issues.

**Step 3: Build**

Run: `go build ./cmd/codemium`
Expected: Clean build.
