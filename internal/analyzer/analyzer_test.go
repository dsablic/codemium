// internal/analyzer/analyzer_test.go
package analyzer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsablic/codemium/internal/analyzer"
)

func TestAnalyzeDirectory(t *testing.T) {
	dir := t.TempDir()

	// Write a Go file
	goCode := `package main

import "fmt"

// main prints a greeting
func main() {
	fmt.Println("hello")
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(goCode), 0644)

	// Write a Python file
	pyCode := `# A simple script
def greet(name):
    """Greet someone."""
    print(f"Hello, {name}")

# Call it
greet("world")
`
	os.WriteFile(filepath.Join(dir, "script.py"), []byte(pyCode), 0644)

	a := analyzer.New()
	stats, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	if len(stats.Languages) == 0 {
		t.Fatal("expected at least one language")
	}

	foundGo := false
	foundPy := false
	for _, lang := range stats.Languages {
		if lang.Name == "Go" {
			foundGo = true
			if lang.Code == 0 {
				t.Error("expected Go code lines > 0")
			}
			if lang.Comments == 0 {
				t.Error("expected Go comment lines > 0")
			}
		}
		if lang.Name == "Python" {
			foundPy = true
			if lang.Code == 0 {
				t.Error("expected Python code lines > 0")
			}
		}
	}
	if !foundGo {
		t.Error("expected Go language in results")
	}
	if !foundPy {
		t.Error("expected Python language in results")
	}

	if stats.Totals.Files != 2 {
		t.Errorf("expected 2 files total, got %d", stats.Totals.Files)
	}
	if stats.Totals.Code == 0 {
		t.Error("expected total code lines > 0")
	}
}

func TestAnalyzeEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	a := analyzer.New()
	stats, err := a.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	if stats.Totals.Files != 0 {
		t.Errorf("expected 0 files, got %d", stats.Totals.Files)
	}
}
