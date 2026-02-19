package narrative

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dsablic/codemium/internal/model"
)

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
		{-500, "-500"},
		{-1234, "-1,234"},
	}
	for _, tt := range tests {
		got := formatNumber(tt.n)
		if got != tt.want {
			t.Errorf("formatNumber(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestCommentRatio(t *testing.T) {
	tests := []struct {
		comments, code int64
		want           string
	}{
		{0, 0, "0.0%"},
		{0, 100, "0.0%"},
		{10, 90, "10.0%"},
		{1, 99, "1.0%"},
		{50, 50, "50.0%"},
		{107961, 8197829, "1.3%"},
	}
	for _, tt := range tests {
		got := commentRatio(tt.comments, tt.code)
		if got != tt.want {
			t.Errorf("commentRatio(%d, %d) = %q, want %q", tt.comments, tt.code, got, tt.want)
		}
	}
}

func TestFormatDate(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"2026-02-19T07:56:55Z", "2026-02-19"},
		{"2026-02-19", "2026-02-19"},
		{"not-a-date", "not-a-date"},
	}
	for _, tt := range tests {
		got := formatDate(tt.input)
		if got != tt.want {
			t.Errorf("formatDate(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTopLanguageNames(t *testing.T) {
	langs := []model.LanguageStats{
		{Name: "Go", Code: 5000},
		{Name: "Python", Code: 3000},
		{Name: "Ruby", Code: 1000},
		{Name: "Shell", Code: 500},
	}
	got := topLanguageNames(langs, 3)
	if got != "Go, Python, Ruby" {
		t.Errorf("topLanguageNames(..., 3) = %q, want %q", got, "Go, Python, Ruby")
	}

	got = topLanguageNames(langs, 10)
	if got != "Go, Python, Ruby, Shell" {
		t.Errorf("topLanguageNames(..., 10) = %q, want %q", got, "Go, Python, Ruby, Shell")
	}
}

func TestPrepareDocument_StandardReport(t *testing.T) {
	report := model.Report{
		GeneratedAt:  "2026-02-19T12:00:00Z",
		Provider:     "github",
		Organization: "myorg",
		Repositories: []model.RepoStats{
			{
				Repository: "big-repo",
				Project:    "BACK",
				Provider:   "github",
				URL:        "https://github.com/myorg/big-repo",
				Totals:     model.Stats{Files: 100, Lines: 12000, Code: 10000, Comments: 500, Blanks: 1500, Complexity: 200},
			},
			{
				Repository: "small-repo",
				Project:    "BACK",
				Provider:   "github",
				URL:        "https://github.com/myorg/small-repo",
				Totals:     model.Stats{Files: 10, Lines: 1200, Code: 1000, Comments: 50, Blanks: 150, Complexity: 20},
			},
			{
				Repository: "frontend",
				Project:    "WEB",
				Provider:   "github",
				URL:        "https://github.com/myorg/frontend",
				Totals:     model.Stats{Files: 50, Lines: 6000, Code: 5000, Comments: 200, Blanks: 800, Complexity: 80},
			},
		},
		Totals: model.Stats{
			Repos: 3, Files: 160, Lines: 19200, Code: 16000, Comments: 750, Blanks: 2450, Complexity: 300,
		},
		ByLanguage: []model.LanguageStats{
			{Name: "Go", Code: 11000},
			{Name: "TypeScript", Code: 5000},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	doc, reportType, err := PrepareDocument(data)
	if err != nil {
		t.Fatalf("PrepareDocument: %v", err)
	}
	if reportType != "standard" {
		t.Errorf("reportType = %q, want %q", reportType, "standard")
	}

	// Check key elements
	checks := []string{
		"# myorg — Repository Overview",
		"**Total repositories:** 3",
		"**Overall comment ratio:** 4.5%",
		"**Top languages:** Go, TypeScript",
		"{{NARRATIVE}}",
		"## Summary by Product Area",
		"| BACK | 2 | 11,000 |",
		"| WEB | 1 | 5,000 |",
		"## Top 10 Repositories by Code Size",
		"[big-repo](https://github.com/myorg/big-repo)",
		"## BACK",
		"**2 repositories**",
		"## WEB",
	}
	for _, check := range checks {
		if !strings.Contains(doc, check) {
			t.Errorf("document should contain %q", check)
		}
	}
}

func TestPrepareDocument_NoProjects(t *testing.T) {
	report := model.Report{
		GeneratedAt:  "2026-02-19T12:00:00Z",
		Provider:     "github",
		Organization: "myorg",
		Repositories: []model.RepoStats{
			{Repository: "repo-a", URL: "https://github.com/myorg/repo-a", Totals: model.Stats{Code: 5000}},
			{Repository: "repo-b", URL: "https://github.com/myorg/repo-b", Totals: model.Stats{Code: 3000}},
		},
		Totals:     model.Stats{Repos: 2, Code: 8000},
		ByLanguage: []model.LanguageStats{{Name: "Go", Code: 8000}},
	}

	data, _ := json.Marshal(report)
	doc, _, err := PrepareDocument(data)
	if err != nil {
		t.Fatalf("PrepareDocument: %v", err)
	}

	// Should NOT have product area table
	if strings.Contains(doc, "Summary by Product Area") {
		t.Error("document without projects should not have product area table")
	}
	// Should have flat listing
	if !strings.Contains(doc, "## All Repositories") {
		t.Error("document without projects should have 'All Repositories' section")
	}
}

func TestPrepareDocument_TrendsReport(t *testing.T) {
	trends := model.TrendsReport{
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
				Totals: model.Stats{Files: 100, Code: 10000, Comments: 500, Complexity: 100},
				ByLanguage: []model.LanguageStats{
					{Name: "Go", Code: 8000},
					{Name: "Python", Code: 2000},
				},
				Repositories: []model.RepoStats{
					{Repository: "api", Totals: model.Stats{Code: 10000}},
				},
			},
			{
				Period: "2025-02",
				Totals: model.Stats{Files: 110, Code: 11000, Comments: 550, Complexity: 110},
				ByLanguage: []model.LanguageStats{
					{Name: "Go", Code: 9000},
					{Name: "Python", Code: 2000},
				},
				Repositories: []model.RepoStats{
					{Repository: "api", Totals: model.Stats{Code: 11000}},
				},
			},
			{
				Period: "2025-03",
				Totals: model.Stats{Files: 120, Code: 12000, Comments: 600, Complexity: 120},
				ByLanguage: []model.LanguageStats{
					{Name: "Go", Code: 10000},
					{Name: "Python", Code: 2000},
				},
				Repositories: []model.RepoStats{
					{Repository: "api", Totals: model.Stats{Code: 12000}},
				},
			},
		},
	}

	data, _ := json.Marshal(trends)
	doc, reportType, err := PrepareDocument(data)
	if err != nil {
		t.Fatalf("PrepareDocument: %v", err)
	}
	if reportType != "trends" {
		t.Errorf("reportType = %q, want %q", reportType, "trends")
	}

	checks := []string{
		"# myorg — Code Trends",
		"**Period:** 2025-01 to 2025-03 (monthly)",
		"{{NARRATIVE}}",
		"## Period Summary",
		"+1,000",
		"## Languages Over Time",
		"## Repositories Over Time",
	}
	for _, check := range checks {
		if !strings.Contains(doc, check) {
			t.Errorf("trends document should contain %q", check)
		}
	}
}

func TestGroupByProject(t *testing.T) {
	repos := []model.RepoStats{
		{Repository: "a", Project: "P1", Totals: model.Stats{Code: 100, Comments: 10, Complexity: 5}},
		{Repository: "b", Project: "P2", Totals: model.Stats{Code: 500, Comments: 50, Complexity: 25}},
		{Repository: "c", Project: "P1", Totals: model.Stats{Code: 200, Comments: 20, Complexity: 10}},
	}

	groups := groupByProject(repos)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// P2 should be first (500 > 300 total code)
	if groups[0].Project != "P2" {
		t.Errorf("first group should be P2 (highest code), got %q", groups[0].Project)
	}
	if groups[1].Project != "P1" {
		t.Errorf("second group should be P1, got %q", groups[1].Project)
	}

	// P1 repos should be sorted by code descending
	if groups[1].Repos[0].Repository != "c" {
		t.Errorf("P1 repos should be sorted by code desc; first should be 'c', got %q", groups[1].Repos[0].Repository)
	}
}
