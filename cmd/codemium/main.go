package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"

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
	root.AddCommand(newMarkdownCmd())

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
		if clientID != "" && clientSecret != "" {
			bb := &auth.BitbucketOAuth{ClientID: clientID, ClientSecret: clientSecret}
			fmt.Fprintln(os.Stderr, "Opening browser for Bitbucket authorization...")
			cred, err = bb.Login(ctx)
		} else {
			cred, err = loginBitbucketAPIToken()
		}

	case "github":
		clientID := os.Getenv("CODEMIUM_GITHUB_CLIENT_ID")
		if clientID != "" {
			gh := &auth.GitHubOAuth{ClientID: clientID, OpenBrowser: true}
			cred, err = gh.Login(ctx)
		} else if token, ok := auth.GhCLIToken(); ok {
			fmt.Fprintln(os.Stderr, "Using token from gh CLI")
			cred = auth.Credentials{AccessToken: token}
		} else {
			return fmt.Errorf("install gh CLI and run 'gh auth login', or set CODEMIUM_GITHUB_CLIENT_ID")
		}

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

func loginBitbucketAPIToken() (auth.Credentials, error) {
	fmt.Fprintln(os.Stderr, "Bitbucket API token login")
	fmt.Fprintln(os.Stderr, "Create a scoped token at: https://id.atlassian.com/manage-profile/security/api-tokens")
	fmt.Fprintln(os.Stderr, "  -> 'Create API token with scopes' -> Bitbucket -> Repository Read, Project Read")
	fmt.Fprintln(os.Stderr)

	reader := bufio.NewReader(os.Stdin)

	fmt.Fprint(os.Stderr, "Email: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("read email: %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return auth.Credentials{}, fmt.Errorf("email is required")
	}

	fmt.Fprint(os.Stderr, "API token: ")
	tokenBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("read token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return auth.Credentials{}, fmt.Errorf("API token is required")
	}

	// Verify credentials by calling the Bitbucket user API
	req, err := http.NewRequest(http.MethodGet, "https://api.bitbucket.org/2.0/user", nil)
	if err != nil {
		return auth.Credentials{}, err
	}
	req.SetBasicAuth(username, token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("verify credentials: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return auth.Credentials{}, fmt.Errorf("invalid email or API token")
	}
	if resp.StatusCode != http.StatusOK {
		return auth.Credentials{}, fmt.Errorf("bitbucket API returned status %d", resp.StatusCode)
	}

	return auth.Credentials{
		AccessToken: token,
		Username:    username,
	}, nil
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
		prov = provider.NewBitbucket(cred.AccessToken, cred.Username, "")
	case "github":
		if org == "" {
			return fmt.Errorf("--org is required for github")
		}
		prov = provider.NewGitHub(cred.AccessToken, "")
	default:
		return fmt.Errorf("unsupported provider: %s", providerName)
	}

	// Interactive project picker for Bitbucket
	if providerName == "bitbucket" && len(projects) == 0 && ui.IsTTY() {
		bb := prov.(*provider.Bitbucket)
		fmt.Fprintln(os.Stderr, "Fetching projects...")
		projectList, err := bb.ListProjects(ctx, workspace)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		if len(projectList) > 0 {
			selected, err := ui.PickProjects(projectList)
			if err != nil {
				return fmt.Errorf("project picker: %w", err)
			}
			if len(selected) > 0 {
				projects = selected
			}
		}
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
	cloner := analyzer.NewCloner(cred.AccessToken, cred.Username)
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
		var dir string
		var cleanup func()
		var err error
		if repo.DownloadURL != "" {
			dir, cleanup, err = cloner.Download(ctx, repo.DownloadURL)
		} else {
			dir, cleanup, err = cloner.Clone(ctx, repo.CloneURL)
		}
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

	return nil
}

func newMarkdownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "markdown [file]",
		Short: "Convert JSON report to markdown",
		Long:  "Reads a JSON report from a file argument or stdin and writes markdown to stdout.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runMarkdown,
	}
}

func runMarkdown(cmd *cobra.Command, args []string) error {
	var r io.Reader = os.Stdin
	if len(args) == 1 {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("open file: %w", err)
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	// Auto-detect report type: try TrendsReport first
	var trends model.TrendsReport
	if err := json.Unmarshal(data, &trends); err == nil && len(trends.Snapshots) > 0 {
		return output.WriteTrendsMarkdown(os.Stdout, trends)
	}

	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parse JSON report: %w", err)
	}

	return output.WriteMarkdown(os.Stdout, report)
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
