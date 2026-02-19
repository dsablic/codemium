package narrative

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dsablic/codemium/internal/model"
)

const narrativePlaceholder = "{{NARRATIVE}}"

// projectGroup aggregates stats for repos sharing the same project key.
type projectGroup struct {
	Project    string
	Repos      []model.RepoStats
	Code       int64
	Comments   int64
	Complexity int64
}

// PrepareDocument parses JSON report data and generates a complete markdown
// document with all tables and computed metrics. The document contains a
// {{NARRATIVE}} placeholder where AI-generated analysis should be inserted.
// Returns the document, the report type ("standard" or "trends"), and any error.
func PrepareDocument(jsonData []byte) (string, string, error) {
	var trends model.TrendsReport
	if err := json.Unmarshal(jsonData, &trends); err == nil && len(trends.Snapshots) > 0 {
		return prepareTrendsDoc(trends), "trends", nil
	}

	var report model.Report
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return "", "", fmt.Errorf("parse JSON: %w", err)
	}
	return prepareReportDoc(report), "standard", nil
}

func prepareReportDoc(report model.Report) string {
	var b strings.Builder

	// Title
	name := report.Workspace
	if name == "" {
		name = report.Organization
	}
	fmt.Fprintf(&b, "# %s — Repository Overview\n\n", name)

	// Summary header
	fmt.Fprintf(&b, "**Total repositories:** %s\n", formatNumber(int64(report.Totals.Repos)))
	fmt.Fprintf(&b, "**Total lines:** %s (code: %s, comments: %s, blanks: %s)\n",
		formatNumber(report.Totals.Lines),
		formatNumber(report.Totals.Code),
		formatNumber(report.Totals.Comments),
		formatNumber(report.Totals.Blanks))
	fmt.Fprintf(&b, "**Overall comment ratio:** %s\n", commentRatio(report.Totals.Comments, report.Totals.Code))
	fmt.Fprintf(&b, "**Overall complexity:** %s\n", formatNumber(report.Totals.Complexity))
	fmt.Fprintf(&b, "**Top languages:** %s\n", topLanguageNames(report.ByLanguage, 7))
	fmt.Fprintf(&b, "**Generated:** %s\n\n", formatDate(report.GeneratedAt))

	// Narrative placeholder
	b.WriteString("## High-Level Overview\n\n")
	b.WriteString(narrativePlaceholder)
	b.WriteString("\n\n")

	// Group repos by project
	groups := groupByProject(report.Repositories)
	hasGroups := len(groups) > 1 || (len(groups) == 1 && groups[0].Project != "")

	if hasGroups {
		// Summary by Product Area table
		b.WriteString("## Summary by Product Area\n\n")
		b.WriteString("| Product Area | Repos | Code Lines | Comment Lines | Comment % | Complexity |\n")
		b.WriteString("|-------------|------:|-----------:|--------------:|----------:|-----------:|\n")
		for _, g := range groups {
			fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s |\n",
				g.Project, len(g.Repos),
				formatNumber(g.Code), formatNumber(g.Comments),
				commentRatio(g.Comments, g.Code),
				formatNumber(g.Complexity))
		}
		fmt.Fprintf(&b, "| **TOTAL** | **%d** | **%s** | **%s** | **%s** | **%s** |\n\n",
			report.Totals.Repos,
			formatNumber(report.Totals.Code),
			formatNumber(report.Totals.Comments),
			commentRatio(report.Totals.Comments, report.Totals.Code),
			formatNumber(report.Totals.Complexity))
	}

	// Top 10 repos
	top10 := topRepos(report.Repositories, 10)
	b.WriteString("## Top 10 Repositories by Code Size\n\n")
	if hasGroups {
		b.WriteString("| Repo | Product Area | Code Lines | Comment % | Complexity |\n")
		b.WriteString("|------|-------------|----------:|---------:|-----------:|\n")
		for _, r := range top10 {
			fmt.Fprintf(&b, "| [%s](%s) | %s | %s | %s | %s |\n",
				r.Repository, r.URL, r.Project,
				formatNumber(r.Totals.Code),
				commentRatio(r.Totals.Comments, r.Totals.Code),
				formatNumber(r.Totals.Complexity))
		}
	} else {
		b.WriteString("| Repo | Code Lines | Comment % | Complexity |\n")
		b.WriteString("|------|----------:|---------:|-----------:|\n")
		for _, r := range top10 {
			fmt.Fprintf(&b, "| [%s](%s) | %s | %s | %s |\n",
				r.Repository, r.URL,
				formatNumber(r.Totals.Code),
				commentRatio(r.Totals.Comments, r.Totals.Code),
				formatNumber(r.Totals.Complexity))
		}
	}
	b.WriteString("\n---\n\n")

	// Per-area sections
	if hasGroups {
		for _, g := range groups {
			fmt.Fprintf(&b, "## %s\n\n", g.Project)
			fmt.Fprintf(&b, "**%d repositories** | Code: %s | Comments: %s | Comment %%: %s | Complexity: %s\n\n",
				len(g.Repos),
				formatNumber(g.Code), formatNumber(g.Comments),
				commentRatio(g.Comments, g.Code),
				formatNumber(g.Complexity))
			b.WriteString("| Repo | Code Lines | Comment % | Complexity |\n")
			b.WriteString("|------|----------:|---------:|-----------:|\n")
			for _, r := range g.Repos {
				fmt.Fprintf(&b, "| [%s](%s) | %s | %s | %s |\n",
					r.Repository, r.URL,
					formatNumber(r.Totals.Code),
					commentRatio(r.Totals.Comments, r.Totals.Code),
					formatNumber(r.Totals.Complexity))
			}
			b.WriteString("\n")
		}
	} else {
		// Flat listing: all repos sorted by code size
		b.WriteString("## All Repositories\n\n")
		b.WriteString("| Repo | Code Lines | Comment % | Complexity |\n")
		b.WriteString("|------|----------:|---------:|-----------:|\n")
		sorted := make([]model.RepoStats, len(report.Repositories))
		copy(sorted, report.Repositories)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Totals.Code > sorted[j].Totals.Code
		})
		for _, r := range sorted {
			fmt.Fprintf(&b, "| [%s](%s) | %s | %s | %s |\n",
				r.Repository, r.URL,
				formatNumber(r.Totals.Code),
				commentRatio(r.Totals.Comments, r.Totals.Code),
				formatNumber(r.Totals.Complexity))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func prepareTrendsDoc(report model.TrendsReport) string {
	var b strings.Builder

	// Title
	name := report.Workspace
	if name == "" {
		name = report.Organization
	}
	fmt.Fprintf(&b, "# %s — Code Trends\n\n", name)

	// Header
	fmt.Fprintf(&b, "**Provider:** %s\n", report.Provider)
	fmt.Fprintf(&b, "**Period:** %s to %s (%s)\n", report.Since, report.Until, report.Interval)
	fmt.Fprintf(&b, "**Generated:** %s\n\n", formatDate(report.GeneratedAt))

	// Narrative placeholder
	b.WriteString("## Overview\n\n")
	b.WriteString(narrativePlaceholder)
	b.WriteString("\n\n")

	// Period summary table
	b.WriteString("## Period Summary\n\n")
	b.WriteString("| Period | Files | Code | Comments | Complexity | Code Delta |\n")
	b.WriteString("|--------|------:|-----:|---------:|-----------:|-----------:|\n")
	var prevCode int64
	for _, snap := range report.Snapshots {
		delta := ""
		if prevCode > 0 {
			diff := snap.Totals.Code - prevCode
			if diff >= 0 {
				delta = "+" + formatNumber(diff)
			} else {
				delta = formatNumber(diff)
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			snap.Period,
			formatNumber(snap.Totals.Files),
			formatNumber(snap.Totals.Code),
			formatNumber(snap.Totals.Comments),
			formatNumber(snap.Totals.Complexity),
			delta)
		prevCode = snap.Totals.Code
	}
	b.WriteString("\n")

	// Languages over time
	langSet := map[string]int64{}
	for _, snap := range report.Snapshots {
		for _, lang := range snap.ByLanguage {
			if lang.Code > langSet[lang.Name] {
				langSet[lang.Name] = lang.Code
			}
		}
	}
	type langEntry struct {
		Name    string
		MaxCode int64
	}
	var langEntries []langEntry
	for name, maxCode := range langSet {
		langEntries = append(langEntries, langEntry{name, maxCode})
	}
	sort.Slice(langEntries, func(i, j int) bool {
		return langEntries[i].MaxCode > langEntries[j].MaxCode
	})
	// Top 10 languages
	if len(langEntries) > 10 {
		langEntries = langEntries[:10]
	}

	b.WriteString("## Languages Over Time\n\n")
	b.WriteString("| Language |")
	for _, p := range report.Periods {
		fmt.Fprintf(&b, " %s |", p)
	}
	b.WriteString("\n|----------|")
	for range report.Periods {
		b.WriteString("------:|")
	}
	b.WriteString("\n")

	for _, le := range langEntries {
		fmt.Fprintf(&b, "| %s |", le.Name)
		for _, snap := range report.Snapshots {
			code := int64(0)
			for _, lang := range snap.ByLanguage {
				if lang.Name == le.Name {
					code = lang.Code
					break
				}
			}
			fmt.Fprintf(&b, " %s |", formatNumber(code))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Repos over time (top 20 by max code)
	repoMax := map[string]int64{}
	for _, snap := range report.Snapshots {
		for _, repo := range snap.Repositories {
			if repo.Totals.Code > repoMax[repo.Repository] {
				repoMax[repo.Repository] = repo.Totals.Code
			}
		}
	}
	type repoEntry struct {
		Name    string
		MaxCode int64
	}
	var repoEntries []repoEntry
	for name, maxCode := range repoMax {
		repoEntries = append(repoEntries, repoEntry{name, maxCode})
	}
	sort.Slice(repoEntries, func(i, j int) bool {
		return repoEntries[i].MaxCode > repoEntries[j].MaxCode
	})
	if len(repoEntries) > 20 {
		repoEntries = repoEntries[:20]
	}

	b.WriteString("## Repositories Over Time\n\n")
	b.WriteString("| Repository |")
	for _, p := range report.Periods {
		fmt.Fprintf(&b, " %s |", p)
	}
	b.WriteString("\n|------------|")
	for range report.Periods {
		b.WriteString("------:|")
	}
	b.WriteString("\n")

	for _, re := range repoEntries {
		fmt.Fprintf(&b, "| %s |", re.Name)
		for _, snap := range report.Snapshots {
			code := int64(0)
			for _, repo := range snap.Repositories {
				if repo.Repository == re.Name {
					code = repo.Totals.Code
					break
				}
			}
			fmt.Fprintf(&b, " %s |", formatNumber(code))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	return b.String()
}

// groupByProject groups repos by their project field and computes aggregate stats.
// Groups are sorted by total code lines descending.
func groupByProject(repos []model.RepoStats) []projectGroup {
	m := make(map[string]*projectGroup)
	var keys []string
	for _, r := range repos {
		proj := r.Project
		if _, ok := m[proj]; !ok {
			m[proj] = &projectGroup{Project: proj}
			keys = append(keys, proj)
		}
		g := m[proj]
		g.Repos = append(g.Repos, r)
		g.Code += r.Totals.Code
		g.Comments += r.Totals.Comments
		g.Complexity += r.Totals.Complexity
	}

	groups := make([]projectGroup, 0, len(keys))
	for _, k := range keys {
		groups = append(groups, *m[k])
	}

	// Sort groups by code size descending
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Code > groups[j].Code
	})

	// Sort repos within each group by code size descending
	for i := range groups {
		sort.Slice(groups[i].Repos, func(a, b int) bool {
			return groups[i].Repos[a].Totals.Code > groups[i].Repos[b].Totals.Code
		})
	}

	return groups
}

// topRepos returns the top N repos sorted by code lines descending.
func topRepos(repos []model.RepoStats, n int) []model.RepoStats {
	sorted := make([]model.RepoStats, len(repos))
	copy(sorted, repos)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Totals.Code > sorted[j].Totals.Code
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

// topLanguageNames returns a comma-separated list of the top N language names by code size.
func topLanguageNames(langs []model.LanguageStats, n int) string {
	sorted := make([]model.LanguageStats, len(langs))
	copy(sorted, langs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Code > sorted[j].Code
	})
	names := make([]string, 0, n)
	for i := 0; i < n && i < len(sorted); i++ {
		names = append(names, sorted[i].Name)
	}
	return strings.Join(names, ", ")
}

// formatNumber formats an integer with comma separators (e.g., 1,234,567).
func formatNumber(n int64) string {
	if n < 0 {
		return "-" + formatNumber(-n)
	}
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var result strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result.WriteByte(',')
		}
		result.WriteRune(c)
	}
	return result.String()
}

// commentRatio computes comments / (comments + code) as a percentage string.
func commentRatio(comments, code int64) string {
	total := comments + code
	if total == 0 {
		return "0.0%"
	}
	ratio := float64(comments) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", ratio)
}

// formatDate extracts a YYYY-MM-DD date from an ISO timestamp.
func formatDate(isoTimestamp string) string {
	t, err := time.Parse(time.RFC3339, isoTimestamp)
	if err != nil {
		// Try date-only formats
		if t, err := time.Parse("2006-01-02", isoTimestamp); err == nil {
			return t.Format("2006-01-02")
		}
		return isoTimestamp
	}
	return t.Format("2006-01-02")
}
