package narrative_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dsablic/codemium/internal/narrative"
)

func TestSupportedCLIs(t *testing.T) {
	clis := narrative.SupportedCLIs()
	want := []string{"claude", "codex", "gemini"}

	if len(clis) != len(want) {
		t.Fatalf("expected %d CLIs, got %d", len(want), len(clis))
	}
	for i, name := range want {
		if clis[i] != name {
			t.Errorf("SupportedCLIs()[%d] = %q, want %q", i, clis[i], name)
		}
	}
}

func TestDetectCLI_Fallback(t *testing.T) {
	lookup := func(name string) (string, error) {
		return "", fmt.Errorf("not found: %s", name)
	}

	_, err := narrative.DetectCLIWith(lookup)
	if err == nil {
		t.Fatal("expected error when no CLI is found")
	}
	if !strings.Contains(err.Error(), "no supported AI CLI found") {
		t.Errorf("unexpected error message: %s", err)
	}
}

func TestDetectCLI_FindsClaude(t *testing.T) {
	lookup := func(name string) (string, error) {
		if name == "claude" {
			return "/usr/local/bin/claude", nil
		}
		return "", fmt.Errorf("not found: %s", name)
	}

	cli, err := narrative.DetectCLIWith(lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli != "claude" {
		t.Errorf("expected claude, got %q", cli)
	}
}

func TestDetectCLI_PrefersOrder(t *testing.T) {
	lookup := func(name string) (string, error) {
		return "/usr/local/bin/" + name, nil
	}

	cli, err := narrative.DetectCLIWith(lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli != "claude" {
		t.Errorf("expected claude (first in order), got %q", cli)
	}
}

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		cli      string
		prompt   string
		wantName string
		wantArgs []string
	}{
		{
			cli:      "claude",
			prompt:   "analyze this",
			wantName: "claude",
			wantArgs: []string{"-p", "analyze this"},
		},
		{
			cli:      "codex",
			prompt:   "analyze this",
			wantName: "codex",
			wantArgs: []string{"exec", "-"},
		},
		{
			cli:      "gemini",
			prompt:   "analyze this",
			wantName: "gemini",
			wantArgs: []string{"-p", "analyze this"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cli, func(t *testing.T) {
			name, args := narrative.BuildArgs(tt.cli, tt.prompt)
			if name != tt.wantName {
				t.Errorf("BuildArgs(%q, ...) name = %q, want %q", tt.cli, name, tt.wantName)
			}
			if len(args) != len(tt.wantArgs) {
				t.Fatalf("BuildArgs(%q, ...) args len = %d, want %d", tt.cli, len(args), len(tt.wantArgs))
			}
			for i, a := range tt.wantArgs {
				if args[i] != a {
					t.Errorf("BuildArgs(%q, ...) args[%d] = %q, want %q", tt.cli, i, args[i], a)
				}
			}
		})
	}
}

func TestDefaultPromptStandard(t *testing.T) {
	prompt := narrative.DefaultPrompt("standard", "")

	for _, keyword := range []string{"narrative", "{{NARRATIVE}}", "scope", "outlier"} {
		if !strings.Contains(strings.ToLower(prompt), strings.ToLower(keyword)) {
			t.Errorf("standard prompt should mention %q", keyword)
		}
	}
}

func TestDefaultPromptTrends(t *testing.T) {
	prompt := narrative.DefaultPrompt("trends", "")

	for _, keyword := range []string{"narrative", "{{NARRATIVE}}", "growth", "decline"} {
		if !strings.Contains(strings.ToLower(prompt), strings.ToLower(keyword)) {
			t.Errorf("trends prompt should mention %q", keyword)
		}
	}
}

func TestDefaultPromptAppendsCustom(t *testing.T) {
	custom := "Focus on security-related repositories only."
	prompt := narrative.DefaultPrompt("standard", custom)

	if !strings.Contains(prompt, custom) {
		t.Error("DefaultPrompt should contain the custom additional instructions")
	}
	if !strings.Contains(prompt, "Additional instructions") {
		t.Error("DefaultPrompt should contain 'Additional instructions' header")
	}
}
