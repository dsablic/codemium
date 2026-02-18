// internal/model/model_test.go
package model_test

import (
	"encoding/json"
	"testing"

	"github.com/dsablic/codemium/internal/model"
)

func TestReportJSON(t *testing.T) {
	report := model.Report{
		GeneratedAt: "2026-02-18T12:00:00Z",
		Provider:    "bitbucket",
		Workspace:   "myworkspace",
		Filters:     model.Filters{Projects: []string{"PROJ1"}},
		Repositories: []model.RepoStats{
			{
				Repository: "my-repo",
				Project:    "PROJ1",
				Provider:   "bitbucket",
				URL:        "https://bitbucket.org/myworkspace/my-repo",
				Languages: []model.LanguageStats{
					{Name: "Go", Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
				},
				Totals: model.Stats{Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
			},
		},
		Totals: model.Stats{Repos: 1, Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
		ByLanguage: []model.LanguageStats{
			{Name: "Go", Files: 10, Lines: 500, Code: 400, Comments: 50, Blanks: 50, Complexity: 30},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}

	if decoded.Provider != "bitbucket" {
		t.Errorf("expected provider bitbucket, got %s", decoded.Provider)
	}
	if decoded.Totals.Code != 400 {
		t.Errorf("expected total code 400, got %d", decoded.Totals.Code)
	}
	if len(decoded.Repositories) != 1 {
		t.Errorf("expected 1 repo, got %d", len(decoded.Repositories))
	}
	if decoded.Repositories[0].Project != "PROJ1" {
		t.Errorf("expected project PROJ1, got %s", decoded.Repositories[0].Project)
	}
}
