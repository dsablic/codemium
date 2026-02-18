package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/dsablic/codemium/internal/analyzer"
	"github.com/dsablic/codemium/internal/auth"
	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/output"
	"github.com/dsablic/codemium/internal/provider"
	"github.com/dsablic/codemium/internal/ui"
	"github.com/dsablic/codemium/internal/worker"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:     "codemium",
		Short:   "Generate code statistics across repositories",
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	root.AddCommand(newAuthCmd())
	root.AddCommand(newAnalyzeCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication",
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with a provider",
		RunE:  runAuthLogin,
	}
	loginCmd.Flags().String("provider", "", "Provider to authenticate with (bitbucket, github)")
	loginCmd.MarkFlagRequired("provider")

	cmd.AddCommand(loginCmd)
	return cmd
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	providerName, _ := cmd.Flags().GetString("provider")

	store := auth.NewFileStore(auth.DefaultStorePath())
	ctx := cmd.Context()

	var cred auth.Credentials
	var err error

	switch providerName {
	case "bitbucket":
		clientID := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_ID")
		clientSecret := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_SECRET")
		if clientID == "" || clientSecret == "" {
			return fmt.Errorf("set CODEMIUM_BITBUCKET_CLIENT_ID and CODEMIUM_BITBUCKET_CLIENT_SECRET environment variables")
		}
		bb := &auth.BitbucketOAuth{ClientID: clientID, ClientSecret: clientSecret}
		fmt.Fprintln(os.Stderr, "Opening browser for Bitbucket authorization...")
		cred, err = bb.Login(ctx)

	case "github":
		clientID := os.Getenv("CODEMIUM_GITHUB_CLIENT_ID")
		if clientID == "" {
			return fmt.Errorf("set CODEMIUM_GITHUB_CLIENT_ID environment variable")
		}
		gh := &auth.GitHubOAuth{ClientID: clientID, OpenBrowser: true}
		cred, err = gh.Login(ctx)

	default:
		return fmt.Errorf("unsupported provider: %s (use bitbucket or github)", providerName)
	}

	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if err := store.Save(providerName, cred); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Successfully authenticated with %s!\n", providerName)
	return nil
}

func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze repositories and generate code statistics",
		RunE:  runAnalyze,
	}

	cmd.Flags().String("provider", "", "Provider (bitbucket, github)")
	cmd.Flags().String("workspace", "", "Bitbucket workspace slug")
	cmd.Flags().String("org", "", "GitHub organization")
	cmd.Flags().StringSlice("projects", nil, "Filter by Bitbucket project keys")
	cmd.Flags().StringSlice("repos", nil, "Filter to specific repo names")
	cmd.Flags().StringSlice("exclude", nil, "Exclude specific repos")
	cmd.Flags().Bool("include-archived", false, "Include archived repos")
	cmd.Flags().Bool("include-forks", false, "Include forked repos")
	cmd.Flags().Int("concurrency", 5, "Number of parallel workers")
	cmd.Flags().String("output", "", "Write JSON to file (default: stdout)")
	cmd.Flags().String("markdown", "", "Write markdown summary to file")

	cmd.MarkFlagRequired("provider")

	return cmd
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer cancel()

	providerName, _ := cmd.Flags().GetString("provider")
	workspace, _ := cmd.Flags().GetString("workspace")
	org, _ := cmd.Flags().GetString("org")
	projects, _ := cmd.Flags().GetStringSlice("projects")
	repos, _ := cmd.Flags().GetStringSlice("repos")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	includeArchived, _ := cmd.Flags().GetBool("include-archived")
	includeForks, _ := cmd.Flags().GetBool("include-forks")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	outputPath, _ := cmd.Flags().GetString("output")
	markdownPath, _ := cmd.Flags().GetString("markdown")

	// Load credentials
	store := auth.NewFileStore(auth.DefaultStorePath())
	cred, err := store.LoadWithEnv(providerName)
	if err != nil {
		return fmt.Errorf("not authenticated with %s — run 'codemium auth login --provider %s' first", providerName, providerName)
	}

	// Refresh if expired (Bitbucket)
	if cred.Expired() && cred.RefreshToken != "" {
		clientID := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_ID")
		clientSecret := os.Getenv("CODEMIUM_BITBUCKET_CLIENT_SECRET")
		bb := &auth.BitbucketOAuth{ClientID: clientID, ClientSecret: clientSecret}
		cred, err = bb.RefreshToken(ctx, cred.RefreshToken)
		if err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
		store.Save(providerName, cred)
	}

	// Create provider
	var prov provider.Provider
	switch providerName {
	case "bitbucket":
		if workspace == "" {
			return fmt.Errorf("--workspace is required for bitbucket")
		}
		prov = provider.NewBitbucket(cred.AccessToken, "")
	case "github":
		if org == "" {
			return fmt.Errorf("--org is required for github")
		}
		prov = provider.NewGitHub(cred.AccessToken, "")
	default:
		return fmt.Errorf("unsupported provider: %s", providerName)
	}

	// List repos
	fmt.Fprintln(os.Stderr, "Listing repositories...")
	repoList, err := prov.ListRepos(ctx, provider.ListOpts{
		Workspace:       workspace,
		Organization:    org,
		Projects:        projects,
		Repos:           repos,
		Exclude:         exclude,
		IncludeArchived: includeArchived,
		IncludeForks:    includeForks,
	})
	if err != nil {
		return fmt.Errorf("list repos: %w", err)
	}

	if len(repoList) == 0 {
		return fmt.Errorf("no repositories found")
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories\n", len(repoList))

	// Set up progress
	useTUI := ui.IsTTY()
	var program *tea.Program
	if useTUI {
		program = ui.RunTUI(len(repoList))
		go func() {
			program.Run()
		}()
	}

	// Process repos
	cloner := analyzer.NewCloner(cred.AccessToken)
	codeAnalyzer := analyzer.New()

	progressFn := func(completed, total int, repo model.Repo) {
		if useTUI && program != nil {
			program.Send(ui.ProgressMsg{
				Completed: completed,
				Total:     total,
				RepoName:  repo.Slug,
			})
		} else {
			fmt.Fprintf(os.Stderr, "[%d/%d] Analyzed %s\n", completed, total, repo.Slug)
		}
	}

	results := worker.RunWithProgress(ctx, repoList, concurrency, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
		dir, cleanup, err := cloner.Clone(ctx, repo.CloneURL)
		if err != nil {
			return nil, err
		}
		defer cleanup()

		stats, err := codeAnalyzer.Analyze(ctx, dir)
		if err != nil {
			return nil, err
		}

		stats.Repository = repo.Slug
		stats.Project = repo.Project
		stats.Provider = repo.Provider
		stats.URL = repo.URL
		return stats, nil
	}, progressFn)

	if useTUI && program != nil {
		program.Send(ui.DoneMsg{})
		// Give TUI a moment to render the done message
		time.Sleep(100 * time.Millisecond)
		program.Quit()
	}

	// Build report
	report := buildReport(providerName, workspace, org, projects, repos, exclude, results)

	// Write JSON output
	var jsonWriter io.Writer = os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		jsonWriter = f
	}
	if err := output.WriteJSON(jsonWriter, report); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}

	// Write markdown if requested
	if markdownPath != "" {
		f, err := os.Create(markdownPath)
		if err != nil {
			return fmt.Errorf("create markdown file: %w", err)
		}
		defer f.Close()
		if err := output.WriteMarkdown(f, report); err != nil {
			return fmt.Errorf("write markdown: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Markdown summary written to %s\n", markdownPath)
	}

	return nil
}

func buildReport(providerName, workspace, org string, projects, repos, exclude []string, results []worker.Result) model.Report {
	report := model.Report{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Provider:     providerName,
		Workspace:    workspace,
		Organization: org,
		Filters: model.Filters{
			Projects: projects,
			Repos:    repos,
			Exclude:  exclude,
		},
	}

	langTotals := map[string]*model.LanguageStats{}

	for _, r := range results {
		if r.Err != nil {
			report.Errors = append(report.Errors, model.RepoError{
				Repository: r.Repo.Slug,
				Error:      r.Err.Error(),
			})
			continue
		}

		report.Repositories = append(report.Repositories, *r.Stats)
		report.Totals.Repos++
		report.Totals.Files += r.Stats.Totals.Files
		report.Totals.Lines += r.Stats.Totals.Lines
		report.Totals.Code += r.Stats.Totals.Code
		report.Totals.Comments += r.Stats.Totals.Comments
		report.Totals.Blanks += r.Stats.Totals.Blanks
		report.Totals.Complexity += r.Stats.Totals.Complexity

		for _, lang := range r.Stats.Languages {
			lt, ok := langTotals[lang.Name]
			if !ok {
				lt = &model.LanguageStats{Name: lang.Name}
				langTotals[lang.Name] = lt
			}
			lt.Files += lang.Files
			lt.Lines += lang.Lines
			lt.Code += lang.Code
			lt.Comments += lang.Comments
			lt.Blanks += lang.Blanks
			lt.Complexity += lang.Complexity
		}
	}

	for _, lt := range langTotals {
		report.ByLanguage = append(report.ByLanguage, *lt)
	}

	// Sort by code descending
	sort.Slice(report.ByLanguage, func(i, j int) bool {
		return report.ByLanguage[i].Code > report.ByLanguage[j].Code
	})

	return report
}
