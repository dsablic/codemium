// internal/output/markdown.go
package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dsablic/codemium/internal/model"
)

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// WriteMarkdown writes the report as GitHub-flavored markdown to w.
func WriteMarkdown(w io.Writer, report model.Report) error {
	fmt.Fprintf(w, "# Code Statistics Report\n\n")
	fmt.Fprintf(w, "**Provider:** %s\n", report.Provider)
	if report.Workspace != "" {
		fmt.Fprintf(w, "**Workspace:** %s\n", report.Workspace)
	}
	if report.Organization != "" {
		fmt.Fprintf(w, "**Organization:** %s\n", report.Organization)
	}
	fmt.Fprintf(w, "**Generated:** %s\n\n", report.GeneratedAt)

	// Summary totals
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Repositories | %d |\n", report.Totals.Repos)
	fmt.Fprintf(w, "| Files | %d |\n", report.Totals.Files)
	fmt.Fprintf(w, "| Lines | %d |\n", report.Totals.Lines)
	fmt.Fprintf(w, "| Code | %d |\n", report.Totals.Code)
	fmt.Fprintf(w, "| Comments | %d |\n", report.Totals.Comments)
	fmt.Fprintf(w, "| Blanks | %d |\n", report.Totals.Blanks)
	fmt.Fprintf(w, "| Complexity | %d |\n", report.Totals.Complexity)
	if report.Totals.FilteredFiles > 0 {
		fmt.Fprintf(w, "| Filtered Files | %d |\n", report.Totals.FilteredFiles)
	}
	fmt.Fprintln(w)

	// AI Code Estimation (only if present)
	if report.AIEstimate != nil {
		fmt.Fprintf(w, "## AI Code Estimation\n\n")
		fmt.Fprintf(w, "| Metric | Total | AI-Attributed | Percentage |\n")
		fmt.Fprintf(w, "|--------|------:|:-------------:|-----------:|\n")
		fmt.Fprintf(w, "| Commits | %d | %d | %.1f%% |\n",
			report.AIEstimate.TotalCommits, report.AIEstimate.AICommits, report.AIEstimate.CommitPercent)
		if report.AIEstimate.AIAdditions > 0 {
			fmt.Fprintf(w, "| Line additions | — | %d | — |\n", report.AIEstimate.AIAdditions)
		}
		fmt.Fprintln(w)
	}

	// Repository Health (only if present)
	if report.HealthSummary != nil {
		fmt.Fprintf(w, "## Repository Health\n\n")
		fmt.Fprintf(w, "| Category | Repos | Code Lines | %% of Code |\n")
		fmt.Fprintf(w, "|----------|------:|-----------:|----------:|\n")
		fmt.Fprintf(w, "| Active (<180d) | %d | %d | %.1f%% |\n",
			report.HealthSummary.Active.Repos, report.HealthSummary.Active.Code, report.HealthSummary.Active.CodePercent)
		fmt.Fprintf(w, "| Maintained (180-365d) | %d | %d | %.1f%% |\n",
			report.HealthSummary.Maintained.Repos, report.HealthSummary.Maintained.Code, report.HealthSummary.Maintained.CodePercent)
		fmt.Fprintf(w, "| Abandoned (>365d) | %d | %d | %.1f%% |\n",
			report.HealthSummary.Abandoned.Repos, report.HealthSummary.Abandoned.Code, report.HealthSummary.Abandoned.CodePercent)
		if report.HealthSummary.Failed.Repos > 0 {
			fmt.Fprintf(w, "| Failed (error) | %d | %d | — |\n",
				report.HealthSummary.Failed.Repos, report.HealthSummary.Failed.Code)
		}
		fmt.Fprintln(w)
	}

	// Secrets Summary (only if present)
	if report.SecretsSummary != nil {
		fmt.Fprintf(w, "## Secret Scanning\n\n")
		fmt.Fprintf(w, "| Metric | Value |\n")
		fmt.Fprintf(w, "|--------|-------|\n")
		fmt.Fprintf(w, "| Total Findings | %d |\n", report.SecretsSummary.TotalFindings)
		fmt.Fprintf(w, "| Repos with Secrets | %d |\n", report.SecretsSummary.ReposWithSecrets)
		fmt.Fprintln(w)
	}

	// By language
	fmt.Fprintf(w, "## Languages\n\n")
	fmt.Fprintf(w, "| Language | Files | Code | Comments | Blanks | Complexity |\n")
	fmt.Fprintf(w, "|----------|------:|-----:|---------:|-------:|-----------:|\n")
	for _, lang := range report.ByLanguage {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d |\n",
			lang.Name, lang.Files, lang.Code, lang.Comments, lang.Blanks, lang.Complexity)
	}
	fmt.Fprintln(w)

	// Per repository
	hasAI := report.AIEstimate != nil
	hasHealth := report.HealthSummary != nil
	hasSecrets := report.SecretsSummary != nil
	fmt.Fprintf(w, "## Repositories\n\n")

	// Build header based on which optional columns are present
	header := "| Repository | Project | License | Files | Code | Comments | Complexity"
	separator := "|------------|---------|---------|------:|-----:|---------:|-----------:"
	if hasHealth {
		header += " | Health"
		separator += "|-------:"
	}
	if hasAI {
		header += " | AI Commits % | AI Additions"
		separator += "|-------------:|-------------:"
	}
	if hasSecrets {
		header += " | Secrets"
		separator += "|--------:"
	}
	fmt.Fprintf(w, "%s |\n%s|\n", header, separator)

	for _, repo := range report.Repositories {
		lic := repo.License
		if lic == "" {
			lic = "\u2014"
		}
		fmt.Fprintf(w, "| [%s](%s) | %s | %s | %d | %d | %d | %d",
			repo.Repository, repo.URL, repo.Project, lic, repo.Totals.Files, repo.Totals.Code,
			repo.Totals.Comments, repo.Totals.Complexity)
		if hasHealth {
			healthStr := "\u2014"
			if repo.Health != nil {
				switch {
				case repo.Health.Category == model.HealthFailed:
					healthStr = "Failed (error)"
				case repo.Health.DaysSinceCommit >= 0:
					healthStr = fmt.Sprintf("%s (%dd)", capitalize(string(repo.Health.Category)), repo.Health.DaysSinceCommit)
				default:
					healthStr = fmt.Sprintf("%s (no commits)", capitalize(string(repo.Health.Category)))
				}
			}
			fmt.Fprintf(w, " | %s", healthStr)
		}
		if hasAI {
			aiPct := "\u2014"
			aiAdd := "\u2014"
			if repo.AIEstimate != nil {
				aiPct = fmt.Sprintf("%.1f%%", repo.AIEstimate.CommitPercent)
				aiAdd = fmt.Sprintf("%d", repo.AIEstimate.AIAdditions)
			}
			fmt.Fprintf(w, " | %s | %s", aiPct, aiAdd)
		}
		if hasSecrets {
			secretsStr := "0"
			if repo.Secrets != nil && repo.Secrets.FindingsCount > 0 {
				secretsStr = fmt.Sprintf("%d", repo.Secrets.FindingsCount)
			}
			fmt.Fprintf(w, " | %s", secretsStr)
		}
		fmt.Fprintln(w, " |")
	}
	fmt.Fprintln(w)

	// Health Details (only if present)
	if hasHealth {
		var hasDetails bool
		for _, repo := range report.Repositories {
			if repo.HealthDetails != nil {
				hasDetails = true
				break
			}
		}
		if hasDetails {
			fmt.Fprintf(w, "## Health Details\n\n")
			fmt.Fprintf(w, "| Repository | Window | Authors | Commits | Additions | Deletions | Net Churn |\n")
			fmt.Fprintf(w, "|------------|--------|--------:|--------:|----------:|----------:|----------:|\n")
			for _, repo := range report.Repositories {
				if repo.HealthDetails == nil {
					continue
				}
				for _, window := range []string{"0-6mo", "6-12mo", "12mo+"} {
					cs, hasChurn := repo.HealthDetails.ChurnByWindow[window]
					authors := repo.HealthDetails.AuthorsByWindow[window]
					if !hasChurn && authors == 0 {
						continue
					}
					fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %d |\n",
						repo.Repository, window, authors, cs.Commits, cs.Additions, cs.Deletions, cs.NetChurn)
				}
			}
			fmt.Fprintln(w)
		}
	}

	// Code Churn
	var hasChurn bool
	for _, repo := range report.Repositories {
		if repo.Churn != nil && len(repo.Churn.TopFiles) > 0 {
			hasChurn = true
			break
		}
	}

	if hasChurn {
		fmt.Fprintf(w, "## Code Churn\n\n")
		for _, repo := range report.Repositories {
			if repo.Churn == nil || len(repo.Churn.TopFiles) == 0 {
				continue
			}
			fmt.Fprintf(w, "### %s\n\n", repo.Repository)
			fmt.Fprintf(w, "**Commits scanned:** %d\n\n", repo.Churn.TotalCommits)

			fmt.Fprintf(w, "| File | Changes | Additions | Deletions |\n")
			fmt.Fprintf(w, "|------|--------:|----------:|----------:|\n")
			for _, f := range repo.Churn.TopFiles {
				fmt.Fprintf(w, "| %s | %d | %d | %d |\n", f.Path, f.Changes, f.Additions, f.Deletions)
			}
			fmt.Fprintln(w)

			if len(repo.Churn.Hotspots) > 0 {
				fmt.Fprintf(w, "**Hotspots** (high churn x high complexity):\n\n")
				fmt.Fprintf(w, "| File | Changes | Complexity | Hotspot Score |\n")
				fmt.Fprintf(w, "|------|--------:|-----------:|--------------:|\n")
				for _, h := range repo.Churn.Hotspots {
					fmt.Fprintf(w, "| %s | %d | %d | %.0f |\n", h.Path, h.Changes, h.Complexity, h.Hotspot)
				}
				fmt.Fprintln(w)
			}
		}
	}

	// Errors
	if len(report.Errors) > 0 {
		fmt.Fprintf(w, "## Errors\n\n")
		for _, e := range report.Errors {
			fmt.Fprintf(w, "- **%s**: %s\n", e.Repository, e.Error)
		}
		fmt.Fprintln(w)
	}

	return nil
}

// WriteTrendsMarkdown writes the trends report as GitHub-flavored markdown to w.
func WriteTrendsMarkdown(w io.Writer, report model.TrendsReport) error {
	fmt.Fprintf(w, "# Code Trends Report\n\n")
	fmt.Fprintf(w, "**Provider:** %s\n", report.Provider)
	if report.Workspace != "" {
		fmt.Fprintf(w, "**Workspace:** %s\n", report.Workspace)
	}
	if report.Organization != "" {
		fmt.Fprintf(w, "**Organization:** %s\n", report.Organization)
	}
	fmt.Fprintf(w, "**Period:** %s to %s (%s)\n", report.Since, report.Until, report.Interval)
	fmt.Fprintf(w, "**Generated:** %s\n\n", report.GeneratedAt)

	// Summary table: one row per period
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Period | Files | Code | Comments | Blanks | Complexity | Code Delta |\n")
	fmt.Fprintf(w, "|--------|------:|-----:|---------:|-------:|-----------:|-----------:|\n")
	var prevCode int64
	for _, snap := range report.Snapshots {
		delta := ""
		if prevCode > 0 {
			diff := snap.Totals.Code - prevCode
			if diff >= 0 {
				delta = fmt.Sprintf("+%d", diff)
			} else {
				delta = fmt.Sprintf("%d", diff)
			}
		}
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d | %s |\n",
			snap.Period, snap.Totals.Files, snap.Totals.Code,
			snap.Totals.Comments, snap.Totals.Blanks, snap.Totals.Complexity, delta)
		prevCode = snap.Totals.Code
	}
	fmt.Fprintln(w)

	// Language breakdown across time
	fmt.Fprintf(w, "## Languages Over Time\n\n")
	fmt.Fprintf(w, "| Language |")
	for _, p := range report.Periods {
		fmt.Fprintf(w, " %s |", p)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "|----------|")
	for range report.Periods {
		fmt.Fprintf(w, "-----:|")
	}
	fmt.Fprintln(w)

	langSet := map[string]bool{}
	for _, snap := range report.Snapshots {
		for _, lang := range snap.ByLanguage {
			langSet[lang.Name] = true
		}
	}
	var langNames []string
	for name := range langSet {
		langNames = append(langNames, name)
	}
	sort.Strings(langNames)

	for _, name := range langNames {
		fmt.Fprintf(w, "| %s |", name)
		for _, snap := range report.Snapshots {
			code := int64(0)
			for _, lang := range snap.ByLanguage {
				if lang.Name == name {
					code = lang.Code
					break
				}
			}
			fmt.Fprintf(w, " %d |", code)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)

	// Per-repo code over time
	fmt.Fprintf(w, "## Repositories Over Time\n\n")
	fmt.Fprintf(w, "| Repository |")
	for _, p := range report.Periods {
		fmt.Fprintf(w, " %s |", p)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "|------------|")
	for range report.Periods {
		fmt.Fprintf(w, "-----:|")
	}
	fmt.Fprintln(w)

	repoSet := map[string]bool{}
	for _, snap := range report.Snapshots {
		for _, repo := range snap.Repositories {
			repoSet[repo.Repository] = true
		}
	}
	var repoNames []string
	for name := range repoSet {
		repoNames = append(repoNames, name)
	}
	sort.Strings(repoNames)

	for _, name := range repoNames {
		fmt.Fprintf(w, "| %s |", name)
		for _, snap := range report.Snapshots {
			code := int64(0)
			for _, repo := range snap.Repositories {
				if repo.Repository == name {
					code = repo.Totals.Code
					break
				}
			}
			fmt.Fprintf(w, " %d |", code)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)

	if len(report.Errors) > 0 {
		fmt.Fprintf(w, "## Errors\n\n")
		for _, e := range report.Errors {
			fmt.Fprintf(w, "- **%s**: %s\n", e.Repository, e.Error)
		}
		fmt.Fprintln(w)
	}

	return nil
}
