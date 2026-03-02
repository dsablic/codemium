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
	Repos         int   `json:"repos,omitempty"`
	Files         int64 `json:"files"`
	Lines         int64 `json:"lines"`
	Code          int64 `json:"code"`
	Comments      int64 `json:"comments"`
	Blanks        int64 `json:"blanks"`
	Complexity    int64 `json:"complexity"`
	FilteredFiles int64 `json:"filtered_files,omitempty"`
}

// RepoStats holds the analysis results for a single repository.
type RepoStats struct {
	Repository    string             `json:"repository"`
	Project       string             `json:"project,omitempty"`
	Provider      string             `json:"provider"`
	URL           string             `json:"url"`
	License       string             `json:"license,omitempty"`
	Languages     []LanguageStats    `json:"languages"`
	Totals        Stats              `json:"totals"`
	FilteredFiles int64              `json:"filtered_files,omitempty"`
	Churn         *ChurnStats        `json:"churn,omitempty"`
	AIEstimate    *AIEstimate        `json:"ai_estimate,omitempty"`
	Health        *RepoHealth        `json:"health,omitempty"`
	HealthDetails *RepoHealthDetails `json:"health_details,omitempty"`
	Secrets       *SecretsReport     `json:"secrets,omitempty"`
}

// RepoError records a repository that failed to process.
type RepoError struct {
	Repository string `json:"repository"`
	Error      string `json:"error"`
}

// FileChurn holds churn metrics for a single file.
type FileChurn struct {
	Path       string  `json:"path"`
	Changes    int64   `json:"changes"`
	Additions  int64   `json:"additions"`
	Deletions  int64   `json:"deletions"`
	Complexity int64   `json:"complexity,omitempty"`
	Hotspot    float64 `json:"hotspot,omitempty"`
}

// ChurnStats holds code churn and hotspot data for a repository.
type ChurnStats struct {
	TotalCommits int64       `json:"total_commits"`
	TopFiles     []FileChurn `json:"top_files"`
	Hotspots     []FileChurn `json:"hotspots,omitempty"`
}

// AISignal represents why a commit was flagged as AI-authored.
type AISignal string

const (
	SignalCoAuthor      AISignal = "co-author"
	SignalCommitMessage AISignal = "commit-message"
	SignalBotAuthor     AISignal = "bot-author"
)

// AICommit represents a single AI-attributed commit.
type AICommit struct {
	Hash      string     `json:"hash"`
	Author    string     `json:"author"`
	Message   string     `json:"message"`
	Signals   []AISignal `json:"signals"`
	Additions int64      `json:"additions"`
	Deletions int64      `json:"deletions"`
}

// AIEstimate holds AI attribution metrics.
type AIEstimate struct {
	TotalCommits    int64      `json:"total_commits"`
	AICommits       int64      `json:"ai_commits"`
	CommitPercent   float64    `json:"commit_percent"`
	TotalAdditions  int64      `json:"total_additions"`
	AIAdditions     int64      `json:"ai_additions"`
	AdditionPercent float64    `json:"addition_percent"`
	Details         []AICommit `json:"details,omitempty"`
}

// HealthCategory classifies a repository's activity level.
type HealthCategory string

const (
	HealthActive     HealthCategory = "active"
	HealthMaintained HealthCategory = "maintained"
	HealthAbandoned  HealthCategory = "abandoned"
	HealthFailed     HealthCategory = "failed"
)

// RepoHealth holds the health classification for a repository.
type RepoHealth struct {
	Category        HealthCategory `json:"category"`
	LastCommitDate  string         `json:"last_commit_date"`
	DaysSinceCommit int            `json:"days_since_commit"`
	Error           string         `json:"error,omitempty"`
}

// RepoHealthDetails holds deep health analysis for a repository.
type RepoHealthDetails struct {
	AuthorsByWindow map[string]int              `json:"authors_by_window,omitempty"`
	ChurnByWindow   map[string]WindowChurnStats `json:"churn_by_window,omitempty"`
	BusFactor       float64                     `json:"bus_factor"`
	VelocityTrend   float64                     `json:"velocity_trend"`
}

// WindowChurnStats holds code churn metrics for a time window.
type WindowChurnStats struct {
	Additions int64 `json:"additions"`
	Deletions int64 `json:"deletions"`
	NetChurn  int64 `json:"net_churn"`
	Commits   int   `json:"commits"`
}

// HealthCategorySummary aggregates repos and code for a health category.
type HealthCategorySummary struct {
	Repos       int     `json:"repos"`
	Code        int64   `json:"code"`
	CodePercent float64 `json:"code_percent"`
}

// HealthSummary holds aggregate health data across all repos.
type HealthSummary struct {
	Active     HealthCategorySummary `json:"active"`
	Maintained HealthCategorySummary `json:"maintained"`
	Abandoned  HealthCategorySummary `json:"abandoned"`
	Failed     HealthCategorySummary `json:"failed"`
}

// SecretsReport holds secret scanning results for a single repository.
type SecretsReport struct {
	FindingsCount    int      `json:"findings_count"`
	FilesWithSecrets []string `json:"files_with_secrets,omitempty"`
}

// SecretsAggregate holds aggregate secret scanning data across all repos.
type SecretsAggregate struct {
	TotalFindings    int `json:"total_findings"`
	ReposWithSecrets int `json:"repos_with_secrets"`
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
	GeneratedAt   string          `json:"generated_at"`
	Provider      string          `json:"provider"`
	Workspace     string          `json:"workspace,omitempty"`
	Organization  string          `json:"organization,omitempty"`
	Filters       Filters         `json:"filters"`
	Repositories  []RepoStats     `json:"repositories"`
	Totals        Stats           `json:"totals"`
	ByLanguage    []LanguageStats `json:"by_language"`
	Errors        []RepoError     `json:"errors,omitempty"`
	AIEstimate    *AIEstimate     `json:"ai_estimate,omitempty"`
	HealthSummary  *HealthSummary    `json:"health_summary,omitempty"`
	SecretsSummary *SecretsAggregate `json:"secrets_summary,omitempty"`
}
