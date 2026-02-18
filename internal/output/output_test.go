// internal/output/output_test.go
package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/output"
)

func sampleReport() model.Report {
	return model.Report{
		GeneratedAt: "2026-02-18T12:00:00Z",
		Provider:    "bitbucket",
		Workspace:   "myworkspace",
		Filters:     model.Filters{Projects: []string{"PROJ1"}},
		Repositories: []model.RepoStats{
			{
				Repository: "api-service",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				URL:        "https://bitbucket.org/myworkspace/api-service",
				Languages: []model.LanguageStats{
					{Name: "Go", Files: 30, Lines: 5000, Code: 4000, Comments: 500, Blanks: 500, Complexity: 200},
					{Name: "YAML", Files: 5, Lines: 200, Code: 180, Comments: 10, Blanks: 10, Complexity: 0},
				},
				Totals: model.Stats{Files: 35, Lines: 5200, Code: 4180, Comments: 510, Blanks: 510, Complexity: 200},
			},
			{
				Repository: "web-app",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				URL:        "https://bitbucket.org/myworkspace/web-app",
				Languages: []model.LanguageStats{
					{Name: "TypeScript", Files: 50, Lines: 8000, Code: 6000, Comments: 1000, Blanks: 1000, Complexity: 400},
				},
				Totals: model.Stats{Files: 50, Lines: 8000, Code: 6000, Comments: 1000, Blanks: 1000, Complexity: 400},
			},
		},
		Totals: model.Stats{Repos: 2, Files: 85, Lines: 13200, Code: 10180, Comments: 1510, Blanks: 1510, Complexity: 600},
		ByLanguage: []model.LanguageStats{
			{Name: "TypeScript", Files: 50, Lines: 8000, Code: 6000, Comments: 1000, Blanks: 1000, Complexity: 400},
			{Name: "Go", Files: 30, Lines: 5000, Code: 4000, Comments: 500, Blanks: 500, Complexity: 200},
			{Name: "YAML", Files: 5, Lines: 200, Code: 180, Comments: 10, Blanks: 10, Complexity: 0},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := output.WriteJSON(&buf, report); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Totals.Code != 10180 {
		t.Errorf("expected total code 10180, got %d", decoded.Totals.Code)
	}
}

func TestWriteMarkdown(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("failed to write markdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "api-service") {
		t.Error("markdown should contain repo name api-service")
	}
	if !strings.Contains(md, "TypeScript") {
		t.Error("markdown should contain language TypeScript")
	}
	if !strings.Contains(md, "|") {
		t.Error("markdown should contain table pipes")
	}
}
