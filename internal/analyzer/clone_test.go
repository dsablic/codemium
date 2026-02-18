// internal/analyzer/clone_test.go
package analyzer_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dsablic/codemium/internal/analyzer"
)

func TestCloneAndCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping clone test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cloner := analyzer.NewCloner("", "")

	// Clone a small public repo
	dir, cleanup, err := cloner.Clone(ctx, "https://github.com/kelseyhightower/nocode.git")
	if err != nil {
		t.Fatalf("clone failed: %v", err)
	}

	// Verify directory exists and has files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read cloned dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("cloned directory is empty")
	}

	// Cleanup should remove the directory
	cleanup()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected directory to be removed after cleanup, but it still exists")
	}
}
