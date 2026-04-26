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

func sampleTrendsReport() model.TrendsReport {
	return model.TrendsReport{
		GeneratedAt:  "2026-02-19T12:00:00Z",
		Provider:     "github",
		Organization: "myorg",
		Since:        "2025-01",
		Until:        "2025-03",
		Interval:     "monthly",
		Periods:      []string{"2025-01", "2025-02", "2025-03"},
		Snapshots: []model.PeriodSnapshot{
			{
				Period: "2025-01",
				Repositories: []model.RepoStats{
					{Repository: "api", Provider: "github", Totals: model.Stats{Code: 1000, Files: 10}},
				},
				Totals:     model.Stats{Repos: 1, Code: 1000, Files: 10},
				ByLanguage: []model.LanguageStats{{Name: "Go", Code: 1000}},
			},
			{
				Period: "2025-02",
				Repositories: []model.RepoStats{
					{Repository: "api", Provider: "github", Totals: model.Stats{Code: 1200, Files: 12}},
				},
				Totals:     model.Stats{Repos: 1, Code: 1200, Files: 12},
				ByLanguage: []model.LanguageStats{{Name: "Go", Code: 1200}},
			},
			{
				Period: "2025-03",
				Repositories: []model.RepoStats{
					{Repository: "api", Provider: "github", Totals: model.Stats{Code: 1500, Files: 15}},
				},
				Totals:     model.Stats{Repos: 1, Code: 1500, Files: 15},
				ByLanguage: []model.LanguageStats{{Name: "Go", Code: 1500}},
			},
		},
	}
}

func TestWriteTrendsJSON(t *testing.T) {
	report := sampleTrendsReport()
	var buf bytes.Buffer
	if err := output.WriteTrendsJSON(&buf, report); err != nil {
		t.Fatalf("failed to write trends JSON: %v", err)
	}

	var decoded model.TrendsReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded.Snapshots) != 3 {
		t.Errorf("expected 3 snapshots, got %d", len(decoded.Snapshots))
	}
}

func TestWriteTrendsMarkdown(t *testing.T) {
	report := sampleTrendsReport()
	var buf bytes.Buffer
	if err := output.WriteTrendsMarkdown(&buf, report); err != nil {
		t.Fatalf("failed to write trends markdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "2025-01") {
		t.Error("markdown should contain period 2025-01")
	}
	if !strings.Contains(md, "2025-03") {
		t.Error("markdown should contain period 2025-03")
	}
	if !strings.Contains(md, "api") {
		t.Error("markdown should contain repo name")
	}
	if !strings.Contains(md, "+") {
		t.Error("markdown should contain delta indicators")
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

func TestWriteMarkdownWithAIEstimate(t *testing.T) {
	report := sampleReport()
	report.AIEstimate = &model.AIEstimate{
		TotalCommits:  200,
		AICommits:     50,
		CommitPercent: 25.0,
		AIAdditions:   3000,
	}
	report.Repositories[0].AIEstimate = &model.AIEstimate{
		TotalCommits:  100,
		AICommits:     30,
		CommitPercent: 30.0,
		AIAdditions:   2000,
	}
	report.Repositories[1].AIEstimate = &model.AIEstimate{
		TotalCommits:  100,
		AICommits:     20,
		CommitPercent: 20.0,
		AIAdditions:   1000,
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "AI Code Estimation") {
		t.Error("markdown should contain AI Code Estimation section")
	}
	if !strings.Contains(md, "25.0%") {
		t.Error("markdown should contain aggregate commit percentage")
	}
	if !strings.Contains(md, "AI Commits %") {
		t.Error("markdown should contain AI Commits % column in repo table")
	}
}

func TestWriteMarkdownLicenseColumn(t *testing.T) {
	report := sampleReport()
	report.Repositories[0].License = "MIT"
	// Leave Repositories[1].License empty to test em-dash fallback

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "| License |") {
		t.Error("markdown should contain License column header")
	}
	if !strings.Contains(md, "| MIT |") {
		t.Error("markdown should contain MIT license value")
	}
	if !strings.Contains(md, "| \u2014 |") {
		t.Error("markdown should contain em-dash for missing license")
	}
}

func TestWriteMarkdownWithoutAIEstimate(t *testing.T) {
	report := sampleReport()

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if strings.Contains(md, "AI Code Estimation") {
		t.Error("markdown should NOT contain AI Code Estimation when not present")
	}
	if strings.Contains(md, "AI Commits %") {
		t.Error("markdown should NOT contain AI columns when not present")
	}
}

func TestWriteMarkdownHealthSummary(t *testing.T) {
	report := sampleReport()
	report.HealthSummary = &model.HealthSummary{
		Active:     model.HealthCategorySummary{Repos: 1, Code: 6000, CodePercent: 58.9},
		Maintained: model.HealthCategorySummary{Repos: 1, Code: 4180, CodePercent: 41.1},
		Abandoned:  model.HealthCategorySummary{Repos: 0, Code: 0, CodePercent: 0.0},
	}
	report.Repositories[0].Health = &model.RepoHealth{
		Category:        model.HealthActive,
		LastCommitDate:  "2026-02-10",
		DaysSinceCommit: 8,
	}
	report.Repositories[1].Health = &model.RepoHealth{
		Category:        model.HealthMaintained,
		LastCommitDate:  "2025-06-01",
		DaysSinceCommit: 262,
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Repository Health") {
		t.Error("markdown should contain Repository Health section")
	}
	if !strings.Contains(md, "Active (<180d)") {
		t.Error("markdown should contain Active category row")
	}
	if !strings.Contains(md, "58.9%") {
		t.Error("markdown should contain Active code percentage")
	}
	if !strings.Contains(md, "| Health") {
		t.Error("markdown should contain Health column in repo table")
	}
	if !strings.Contains(md, "Active (8d)") {
		t.Error("markdown should contain per-repo health value")
	}
	if !strings.Contains(md, "Maintained (262d)") {
		t.Error("markdown should contain maintained health value")
	}
}

func TestWriteMarkdownHealthDetails(t *testing.T) {
	report := sampleReport()
	report.HealthSummary = &model.HealthSummary{
		Active: model.HealthCategorySummary{Repos: 2, Code: 10180, CodePercent: 100.0},
	}
	report.Repositories[0].Health = &model.RepoHealth{
		Category:        model.HealthActive,
		DaysSinceCommit: 5,
	}
	report.Repositories[0].HealthDetails = &model.RepoHealthDetails{
		AuthorsByWindow: map[string]int{"0-6mo": 3, "6-12mo": 2},
		ChurnByWindow: map[string]model.WindowChurnStats{
			"0-6mo":  {Additions: 500, Deletions: 100, NetChurn: 400, Commits: 20},
			"6-12mo": {Additions: 300, Deletions: 50, NetChurn: 250, Commits: 10},
		},
		BusFactor:     2.5,
		VelocityTrend: 1.2,
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Health Details") {
		t.Error("markdown should contain Health Details section")
	}
	if !strings.Contains(md, "0-6mo") {
		t.Error("markdown should contain 0-6mo window")
	}
	if !strings.Contains(md, "api-service") {
		t.Error("markdown should contain repo name in health details")
	}
}

func TestWriteMarkdownChurnHotspots(t *testing.T) {
	report := sampleReport()
	report.Repositories[0].Churn = &model.ChurnStats{
		TotalCommits: 50,
		TopFiles: []model.FileChurn{
			{Path: "main.go", Changes: 30, Additions: 500, Deletions: 200},
			{Path: "handler.go", Changes: 20, Additions: 300, Deletions: 100},
		},
		Hotspots: []model.FileChurn{
			{Path: "main.go", Changes: 30, Complexity: 45, Hotspot: 1350},
		},
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Code Churn") {
		t.Error("markdown should contain Code Churn section")
	}
	if !strings.Contains(md, "api-service") {
		t.Error("markdown should contain repo name in churn section")
	}
	if !strings.Contains(md, "Commits scanned") {
		t.Error("markdown should contain commits scanned")
	}
	if !strings.Contains(md, "main.go") {
		t.Error("markdown should contain file name")
	}
	if !strings.Contains(md, "Hotspots") {
		t.Error("markdown should contain Hotspots subsection")
	}
	if !strings.Contains(md, "1350") {
		t.Error("markdown should contain hotspot score")
	}
}

func TestWriteMarkdownSecretsSummary(t *testing.T) {
	report := sampleReport()
	report.SecretsSummary = &model.SecretsAggregate{
		TotalFindings:    5,
		ReposWithSecrets: 1,
	}
	report.Repositories[0].Secrets = &model.SecretsReport{
		FindingsCount:    5,
		FilesWithSecrets: []string{".env", "config.yaml"},
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Secret Scanning") {
		t.Error("markdown should contain Secret Scanning section")
	}
	if !strings.Contains(md, "Total Findings") {
		t.Error("markdown should contain Total Findings row")
	}
	if !strings.Contains(md, "| 5 |") {
		t.Error("markdown should contain findings count")
	}
	if !strings.Contains(md, "| Secrets") {
		t.Error("markdown should contain Secrets column in repo table")
	}
}

func TestWriteMarkdownSBOMSummary(t *testing.T) {
	report := sampleReport()
	report.SBOMSummary = &model.SBOMAggregate{
		TotalDeps:     120,
		ReposWithDeps: 2,
		Ecosystems: []model.EcosystemDeps{
			{Ecosystem: "go-module", Count: 80},
			{Ecosystem: "npm", Count: 40},
		},
	}
	report.Repositories[0].SBOM = &model.SBOMReport{
		TotalDeps: 80,
		Ecosystems: []model.EcosystemDeps{
			{Ecosystem: "go-module", Count: 80},
		},
	}
	report.Repositories[1].SBOM = &model.SBOMReport{
		TotalDeps: 40,
		Ecosystems: []model.EcosystemDeps{
			{Ecosystem: "npm", Count: 40},
		},
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Dependencies (SBOM)") {
		t.Error("markdown should contain Dependencies (SBOM) section")
	}
	if !strings.Contains(md, "Total Dependencies") {
		t.Error("markdown should contain Total Dependencies row")
	}
	if !strings.Contains(md, "| 120 |") {
		t.Error("markdown should contain total deps count")
	}
	if !strings.Contains(md, "go-module") {
		t.Error("markdown should contain go-module ecosystem")
	}
	if !strings.Contains(md, "npm") {
		t.Error("markdown should contain npm ecosystem")
	}
	if !strings.Contains(md, "| Deps") {
		t.Error("markdown should contain Deps column in repo table")
	}
}

func TestWriteMarkdownHealthFailed(t *testing.T) {
	report := sampleReport()
	report.HealthSummary = &model.HealthSummary{
		Active: model.HealthCategorySummary{Repos: 1, Code: 6000, CodePercent: 58.9},
		Failed: model.HealthCategorySummary{Repos: 1, Code: 4180},
	}
	report.Repositories[0].Health = &model.RepoHealth{
		Category:        model.HealthActive,
		DaysSinceCommit: 5,
	}
	report.Repositories[1].Health = &model.RepoHealth{
		Category: model.HealthFailed,
		Error:    "API rate limit exceeded",
	}

	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Failed (error)") {
		t.Error("markdown should contain Failed category in summary and repo table")
	}
}
