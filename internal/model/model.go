// internal/model/model.go
package model

// Repo represents a repository from a provider.
type Repo struct {
	Name          string
	Slug          string
	Project       string
	URL           string
	CloneURL      string
	DownloadURL   string // tarball download URL (used when git clone isn't available)
	Provider      string
	DefaultBranch string
	Archived      bool
	Fork          bool
}

// LanguageStats holds code statistics for a single language.
type LanguageStats struct {
	Name       string `json:"name"`
	Files      int64  `json:"files"`
	Lines      int64  `json:"lines"`
	Code       int64  `json:"code"`
	Comments   int64  `json:"comments"`
	Blanks     int64  `json:"blanks"`
	Complexity int64  `json:"complexity"`
}

// Stats holds aggregate code statistics.
type Stats struct {
	Repos      int   `json:"repos,omitempty"`
	Files      int64 `json:"files"`
	Lines      int64 `json:"lines"`
	Code       int64 `json:"code"`
	Comments   int64 `json:"comments"`
	Blanks     int64 `json:"blanks"`
	Complexity int64 `json:"complexity"`
}

// RepoStats holds the analysis results for a single repository.
type RepoStats struct {
	Repository string          `json:"repository"`
	Project    string          `json:"project,omitempty"`
	Provider   string          `json:"provider"`
	URL        string          `json:"url"`
	Languages  []LanguageStats `json:"languages"`
	Totals     Stats           `json:"totals"`
}

// RepoError records a repository that failed to process.
type RepoError struct {
	Repository string `json:"repository"`
	Error      string `json:"error"`
}

// Filters records what filters were applied to the analysis.
type Filters struct {
	Projects []string `json:"projects,omitempty"`
	Repos    []string `json:"repos,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}

// PeriodSnapshot holds stats for all repos at a single point in time.
type PeriodSnapshot struct {
	Period       string          `json:"period"`
	Repositories []RepoStats     `json:"repositories"`
	Totals       Stats           `json:"totals"`
	ByLanguage   []LanguageStats `json:"by_language"`
}

// TrendsReport is the top-level output for historical trends.
type TrendsReport struct {
	GeneratedAt  string           `json:"generated_at"`
	Provider     string           `json:"provider"`
	Workspace    string           `json:"workspace,omitempty"`
	Organization string           `json:"organization,omitempty"`
	Filters      Filters          `json:"filters"`
	Since        string           `json:"since"`
	Until        string           `json:"until"`
	Interval     string           `json:"interval"`
	Periods      []string         `json:"periods"`
	Snapshots    []PeriodSnapshot `json:"snapshots"`
	Errors       []RepoError      `json:"errors,omitempty"`
}

// Report is the top-level output structure.
type Report struct {
	GeneratedAt  string          `json:"generated_at"`
	Provider     string          `json:"provider"`
	Workspace    string          `json:"workspace,omitempty"`
	Organization string          `json:"organization,omitempty"`
	Filters      Filters         `json:"filters"`
	Repositories []RepoStats     `json:"repositories"`
	Totals       Stats           `json:"totals"`
	ByLanguage   []LanguageStats `json:"by_language"`
	Errors       []RepoError     `json:"errors,omitempty"`
}
