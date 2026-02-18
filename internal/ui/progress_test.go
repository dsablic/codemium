// internal/ui/progress_test.go
package ui_test

import (
	"testing"

	"github.com/dsablic/codemium/internal/ui"
)

func TestPlainProgress(t *testing.T) {
	var messages []string
	p := ui.NewPlainProgress(func(msg string) {
		messages = append(messages, msg)
	})

	p.Update(1, 5, "repo-1")
	p.Update(2, 5, "repo-2")
	p.Done(5)

	if len(messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(messages))
	}
}

func TestIsTTY(t *testing.T) {
	// Just verify it doesn't panic — the result depends on the test runner
	_ = ui.IsTTY()
}
