// internal/output/markdown.go
package output

import (
	"fmt"
	"io"

	"github.com/dsablic/codemium/internal/model"
)

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
	fmt.Fprintf(w, "| Complexity | %d |\n\n", report.Totals.Complexity)

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
	fmt.Fprintf(w, "## Repositories\n\n")
	fmt.Fprintf(w, "| Repository | Project | Files | Code | Comments | Complexity |\n")
	fmt.Fprintf(w, "|------------|---------|------:|-----:|---------:|-----------:|\n")
	for _, repo := range report.Repositories {
		fmt.Fprintf(w, "| [%s](%s) | %s | %d | %d | %d | %d |\n",
			repo.Repository, repo.URL, repo.Project, repo.Totals.Files, repo.Totals.Code, repo.Totals.Comments, repo.Totals.Complexity)
	}
	fmt.Fprintln(w)

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
