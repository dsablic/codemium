package narrative

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// supportedCLIs is the ordered list of AI CLI tools we can invoke.
var supportedCLIs = []string{"claude", "codex", "gemini"}

// SupportedCLIs returns the list of supported AI CLI tool names.
func SupportedCLIs() []string {
	out := make([]string, len(supportedCLIs))
	copy(out, supportedCLIs)
	return out
}

// LookupFunc resolves a command name to its path. Compatible with exec.LookPath.
type LookupFunc func(name string) (string, error)

// DetectCLI finds the first supported AI CLI available on the system PATH.
func DetectCLI() (string, error) {
	return DetectCLIWith(exec.LookPath)
}

// DetectCLIWith finds the first supported AI CLI using the provided lookup function.
// It iterates the supported CLIs in order and returns the first one the lookup finds.
// Returns an error if none of the supported CLIs are found.
func DetectCLIWith(lookup LookupFunc) (string, error) {
	for _, cli := range supportedCLIs {
		if _, err := lookup(cli); err == nil {
			return cli, nil
		}
	}
	return "", fmt.Errorf("no supported AI CLI found; install one of: %s", strings.Join(supportedCLIs, ", "))
}

// BuildArgs returns the command name and argument slice for a non-interactive
// invocation of the given CLI with the provided prompt.
// For codex, the prompt is not passed as an argument — it is piped via stdin
// (using "-" to read from stdin) because codex exec ignores stdin when a
// prompt argument is present.
func BuildArgs(cli, prompt string) (string, []string) {
	switch cli {
	case "codex":
		return "codex", []string{"exec", "-"}
	case "gemini":
		return "gemini", []string{"-p", prompt}
	default: // "claude" and fallback
		return "claude", []string{"-p", prompt}
	}
}

// DefaultPrompt returns the built-in prompt for the given report type.
// reportType should be "standard" or "trends".
// If extra is non-empty it is appended as additional instructions.
func DefaultPrompt(reportType, extra string) string {
	var b strings.Builder

	b.WriteString(`You are enhancing a code statistics report with narrative analysis. You will receive a pre-computed markdown report via stdin. The report contains accurate tables with all metrics already calculated. There is a {{NARRATIVE}} placeholder where your narrative paragraphs should go.

Write 2-3 paragraphs to replace the {{NARRATIVE}} placeholder. Output ONLY the paragraph text — no headings, no code fences, no preamble like "Here is the analysis:".

`)

	if reportType == "trends" {
		b.WriteString(`Your analysis should:
- Analyze the overall growth or decline trajectory across all periods
- Identify the fastest-growing and shrinking repositories or languages
- Note any inflection points or significant changes between periods
- Comment on what the trends suggest about development priorities
`)
	} else {
		b.WriteString(`Your analysis should:
- Summarize the overall scope and architecture of the codebase
- If repos are grouped by product area, describe what each area appears to cover based on the repository names within it, and assign descriptive human-readable names (e.g., "Backend Services" instead of "BAC")
- Identify outliers: very large repos that skew totals, repos with unusual comment ratios, or unusually high complexity
- Note what the language distribution reveals about the tech stack
- Call out interesting patterns across product areas (e.g., which groups have the highest complexity, lowest comment ratios, or the most repos)
`)
	}

	b.WriteString(`
Use **bold** for emphasis on key metrics and product area names. Reference specific repos by name with backtick formatting (e.g., ` + "`repo-name`" + `).
`)

	if extra != "" {
		b.WriteString("\nAdditional instructions:\n\n")
		b.WriteString(extra)
		b.WriteString("\n")
	}

	return b.String()
}

// buildStdin constructs the stdin payload for the given CLI.
// For codex, the prompt and data are combined into stdin because codex exec
// reads the prompt from stdin (via "-") rather than as an argument.
// For claude and gemini, only the document is piped (prompt goes via -p flag).
func buildStdin(cli string, document []byte, prompt string) *bytes.Reader {
	if cli == "codex" {
		var buf bytes.Buffer
		buf.WriteString(prompt)
		buf.WriteString("\n\nHere is the pre-computed markdown report:\n\n")
		buf.Write(document)
		return bytes.NewReader(buf.Bytes())
	}
	return bytes.NewReader(document)
}

// Generate pre-processes the JSON data into a complete markdown document with
// tables and computed metrics, then runs the AI CLI to generate narrative
// paragraphs which are inserted into the document at the {{NARRATIVE}} placeholder.
func Generate(ctx context.Context, cli string, jsonData []byte, extraInstructions string) (string, error) {
	doc, reportType, err := PrepareDocument(jsonData)
	if err != nil {
		return "", fmt.Errorf("prepare document: %w", err)
	}

	prompt := DefaultPrompt(reportType, extraInstructions)

	name, args := BuildArgs(cli, prompt)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = buildStdin(cli, []byte(doc), prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg != "" {
			return "", fmt.Errorf("%s failed: %w: %s", cli, err, strings.TrimSpace(errMsg))
		}
		return "", fmt.Errorf("%s failed: %w", cli, err)
	}

	narrativeText := strings.TrimSpace(stdout.String())
	result := strings.Replace(doc, narrativePlaceholder, narrativeText, 1)
	return result, nil
}
