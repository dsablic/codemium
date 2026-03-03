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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dsablic/codemium/internal/aiestimate"
	"github.com/dsablic/codemium/internal/analyzer"
	"github.com/dsablic/codemium/internal/auth"
	"github.com/dsablic/codemium/internal/churn"
	"github.com/dsablic/codemium/internal/health"
	"github.com/dsablic/codemium/internal/history"
	"github.com/dsablic/codemium/internal/license"
	"github.com/dsablic/codemium/internal/model"
	"github.com/dsablic/codemium/internal/narrative"
	"github.com/dsablic/codemium/internal/sbom"
	"github.com/dsablic/codemium/internal/secrets"
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

// errorEntry represents a diagnostic error for the error log.
type errorEntry struct {
	Category string
	Repo     string
	Message  string
}

func main() {
	root := &cobra.Command{
		Use:     "codemium",
		Short:   "Generate code statistics across repositories",
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	root.AddCommand(newAuthCmd())
	root.AddCommand(newAnalyzeCmd())
	root.AddCommand(newMarkdownCmd())
	root.AddCommand(newTrendsCmd())

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
	loginCmd.Flags().String("provider", "", "Provider to authenticate with (bitbucket, github, gitlab)")
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

	case "gitlab":
		cred, err = loginGitLabPAT()

	default:
		return fmt.Errorf("unsupported provider: %s (use bitbucket, github, or gitlab)", providerName)
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

func loginGitLabPAT() (auth.Credentials, error) {
	fmt.Fprintln(os.Stderr, "GitLab personal access token login")
	fmt.Fprintln(os.Stderr, "Create a token at: https://gitlab.com/-/user_settings/personal_access_tokens")
	fmt.Fprintln(os.Stderr, "  -> Required scope: read_api")
	fmt.Fprintln(os.Stderr)

	baseURL := os.Getenv("CODEMIUM_GITLAB_URL")
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}

	fmt.Fprint(os.Stderr, "Personal access token: ")
	tokenBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("read token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return auth.Credentials{}, fmt.Errorf("personal access token is required")
	}

	// Verify by calling the GitLab user API
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v4/user", nil)
	if err != nil {
		return auth.Credentials{}, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("verify credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return auth.Credentials{}, fmt.Errorf("invalid personal access token")
	}
	if resp.StatusCode != http.StatusOK {
		return auth.Credentials{}, fmt.Errorf("gitlab API returned status %d", resp.StatusCode)
	}

	var user struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return auth.Credentials{}, fmt.Errorf("decode user response: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Authenticated as %s\n", user.Username)

	return auth.Credentials{
		AccessToken: token,
		Username:    user.Username,
	}, nil
}

func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze repositories and generate code statistics",
		RunE:  runAnalyze,
	}

	cmd.Flags().String("provider", "", "Provider (bitbucket, github, gitlab)")
	cmd.Flags().String("workspace", "", "Bitbucket workspace slug")
	cmd.Flags().String("org", "", "GitHub organization")
	cmd.Flags().String("user", "", "GitHub user (alternative to --org for personal repos)")
	cmd.Flags().String("group", "", "GitLab group path or ID")
	cmd.Flags().StringSlice("projects", nil, "Filter by Bitbucket project keys")
	cmd.Flags().StringSlice("repos", nil, "Filter to specific repo names")
	cmd.Flags().StringSlice("exclude", nil, "Exclude specific repos")
	cmd.Flags().Bool("include-archived", false, "Include archived repos")
	cmd.Flags().Bool("include-forks", false, "Include forked repos")
	cmd.Flags().Int("concurrency", 5, "Number of parallel workers")
	cmd.Flags().String("output", "output/report.json", "Write JSON to file")
	cmd.Flags().Bool("ai-estimate", false, "Estimate AI-written code percentage")
	cmd.Flags().Int("ai-commit-limit", 500, "Max commits to scan per repo for AI estimation (0 = unlimited)")
	cmd.Flags().Bool("health", false, "Classify repos by activity (active/maintained/abandoned)")
	cmd.Flags().Bool("health-details", false, "Deep health analysis: authors, churn, velocity per window (implies --health)")
	cmd.Flags().Int("health-commit-limit", 500, "Max commits to scan per repo for health details (0 = unlimited)")
	cmd.Flags().Bool("churn", false, "Analyze code churn and hotspots")
	cmd.Flags().Int("churn-limit", 500, "Max commits to scan per repo for churn analysis (0 = unlimited)")
	cmd.Flags().Float64("rate-limit", 0, "Max API requests per second (0 = unlimited)")
	cmd.Flags().String("clone", "", "Persist cloned repos to directory (reuses existing clones)")
	cmd.Flags().Bool("secrets", false, "Scan repositories for secrets (API keys, tokens, passwords)")
	cmd.Flags().Bool("sbom", false, "Generate dependency inventory (SBOM) per repository")

	cmd.MarkFlagRequired("provider")

	return cmd
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer cancel()

	providerName, _ := cmd.Flags().GetString("provider")
	workspace, _ := cmd.Flags().GetString("workspace")
	org, _ := cmd.Flags().GetString("org")
	user, _ := cmd.Flags().GetString("user")
	group, _ := cmd.Flags().GetString("group")
	projects, _ := cmd.Flags().GetStringSlice("projects")
	repos, _ := cmd.Flags().GetStringSlice("repos")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	includeArchived, _ := cmd.Flags().GetBool("include-archived")
	includeForks, _ := cmd.Flags().GetBool("include-forks")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	outputPath, _ := cmd.Flags().GetString("output")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")
	cloneDir, _ := cmd.Flags().GetString("clone")
	secretsFlag, _ := cmd.Flags().GetBool("secrets")
	sbomFlag, _ := cmd.Flags().GetBool("sbom")

	// Create rate-limited HTTP client
	httpClient := &http.Client{Transport: &provider.RateLimitTransport{ReqPerSec: rateLimit}}

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
		prov = provider.NewBitbucket(cred.AccessToken, cred.Username, "", httpClient)
	case "github":
		if org != "" && user != "" {
			return fmt.Errorf("--org and --user are mutually exclusive for github")
		}
		if org == "" && user == "" {
			return fmt.Errorf("--org or --user is required for github")
		}
		prov = provider.NewGitHub(cred.AccessToken, "", httpClient)
	case "gitlab":
		if group == "" {
			return fmt.Errorf("--group is required for gitlab")
		}
		baseURL := os.Getenv("CODEMIUM_GITLAB_URL")
		// Enable token refresh when token was sourced from glab CLI
		var refreshFn func() (string, bool)
		if os.Getenv("CODEMIUM_GITLAB_TOKEN") == "" {
			if _, err := store.Load("gitlab"); err != nil {
				refreshFn = auth.GlabCLIToken
			}
		}
		prov = provider.NewGitLabWithRefresh(cred.AccessToken, baseURL, httpClient, refreshFn)
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
	// For GitLab, pass group as Organization
	listOrg := org
	if group != "" {
		listOrg = group
	}

	repoList, err := prov.ListRepos(ctx, provider.ListOpts{
		Workspace:       workspace,
		Organization:    listOrg,
		User:            user,
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

		if cloneDir != "" {
			destDir := filepath.Join(cloneDir, repo.Slug)
			if repo.DownloadURL != "" {
				dir, cleanup, err = cloner.DownloadTo(ctx, repo.DownloadURL, destDir)
			} else {
				dir, cleanup, err = cloner.CloneTo(ctx, repo.CloneURL, destDir)
			}
		} else {
			if repo.DownloadURL != "" {
				dir, cleanup, err = cloner.Download(ctx, repo.DownloadURL)
			} else {
				dir, cleanup, err = cloner.Clone(ctx, repo.CloneURL)
			}
		}
		if err != nil {
			return nil, err
		}
		defer cleanup()

		stats, err := codeAnalyzer.Analyze(ctx, dir)
		if err != nil {
			return nil, err
		}

		stats.License = license.Detect(dir)
		if secretsFlag {
			if sr, err := secrets.Scan(dir); err == nil {
				stats.Secrets = sr
			}
		}
		if sbomFlag {
			if sr, err := sbom.Scan(ctx, dir); err == nil {
				stats.SBOM = sr
			}
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
		program = nil
	}

	// Diagnostic error collection (written to error.log if non-empty)
	var diagErrors []errorEntry
	var diagMu sync.Mutex

	// AI estimation phase
	aiEstimateFlag, _ := cmd.Flags().GetBool("ai-estimate")
	aiCommitLimit, _ := cmd.Flags().GetInt("ai-commit-limit")

	if aiEstimateFlag {
		commitLister, ok := prov.(provider.CommitLister)
		if !ok {
			return fmt.Errorf("provider %s does not support AI estimation", providerName)
		}

		fmt.Fprintln(os.Stderr, "Estimating AI contribution...")

		if useTUI {
			program = ui.RunTUI(len(repoList))
			go func() { program.Run() }()
		}

		aiProgressFn := func(completed, total int, repo model.Repo) {
			if useTUI && program != nil {
				program.Send(ui.ProgressMsg{
					Completed: completed,
					Total:     total,
					RepoName:  repo.Slug,
				})
			} else {
				fmt.Fprintf(os.Stderr, "[%d/%d] Scanned %s\n", completed, total, repo.Slug)
			}
		}

		aiResults := worker.RunWithProgress(ctx, repoList, concurrency, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
			est, partialErrs, err := aiestimate.Estimate(ctx, commitLister, repo, aiCommitLimit)
			if len(partialErrs) > 0 {
				diagMu.Lock()
				for _, pe := range partialErrs {
					diagErrors = append(diagErrors, errorEntry{Category: "ai-estimate-detail", Repo: repo.Slug, Message: pe})
				}
				diagMu.Unlock()
			}
			if err != nil {
				return nil, err
			}
			return &model.RepoStats{
				Repository: repo.Slug,
				AIEstimate: est,
			}, nil
		}, aiProgressFn)

		if useTUI && program != nil {
			program.Send(ui.DoneMsg{})
			time.Sleep(100 * time.Millisecond)
			program.Quit()
			program = nil
		}

		// Attach AI estimates to analysis results
		aiByRepo := make(map[string]*model.AIEstimate)
		for _, r := range aiResults {
			if r.Err != nil {
				diagErrors = append(diagErrors, errorEntry{Category: "ai-estimate", Repo: r.Repo.Slug, Message: r.Err.Error()})
				continue
			}
			if r.Stats != nil && r.Stats.AIEstimate != nil {
				aiByRepo[r.Repo.Slug] = r.Stats.AIEstimate
			}
		}

		for i := range results {
			if results[i].Stats != nil {
				if est, ok := aiByRepo[results[i].Repo.Slug]; ok {
					results[i].Stats.AIEstimate = est
				}
			}
		}
	}

	// Health classification phase
	healthFlag, _ := cmd.Flags().GetBool("health")
	healthDetailsFlag, _ := cmd.Flags().GetBool("health-details")
	healthCommitLimit, _ := cmd.Flags().GetInt("health-commit-limit")

	if healthDetailsFlag {
		healthFlag = true // --health-details implies --health
	}

	if healthFlag {
		commitLister, ok := prov.(provider.CommitLister)
		if !ok {
			return fmt.Errorf("provider %s does not support health classification", providerName)
		}

		fmt.Fprintln(os.Stderr, "Classifying repository health...")

		if useTUI {
			program = ui.RunTUI(len(repoList))
			go func() { program.Run() }()
		}

		commitLimit := 1
		if healthDetailsFlag {
			commitLimit = healthCommitLimit
		}

		healthProgressFn := func(completed, total int, repo model.Repo) {
			if useTUI && program != nil {
				program.Send(ui.ProgressMsg{
					Completed: completed,
					Total:     total,
					RepoName:  repo.Slug,
				})
			} else {
				fmt.Fprintf(os.Stderr, "[%d/%d] Health %s\n", completed, total, repo.Slug)
			}
		}

		now := time.Now().UTC()
		healthResults := worker.RunWithProgress(ctx, repoList, concurrency, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
			commits, err := commitLister.ListCommits(ctx, repo, commitLimit)
			if err != nil {
				diagMu.Lock()
				diagErrors = append(diagErrors, errorEntry{Category: "health", Repo: repo.Slug, Message: err.Error()})
				diagMu.Unlock()
				return &model.RepoStats{
					Repository: repo.Slug,
					Health: &model.RepoHealth{
						Category:        model.HealthFailed,
						DaysSinceCommit: -1,
						Error:           err.Error(),
					},
				}, nil
			}

			h := health.ClassifyFromCommits(commits, now)

			var details *model.RepoHealthDetails
			if healthDetailsFlag && len(commits) > 0 {
				var partialErrs []string
				details, partialErrs, err = health.AnalyzeDetails(ctx, commitLister, repo, commits, now)
				if len(partialErrs) > 0 {
					diagMu.Lock()
					for _, pe := range partialErrs {
						diagErrors = append(diagErrors, errorEntry{Category: "health-details", Repo: repo.Slug, Message: pe})
					}
					diagMu.Unlock()
				}
				if err != nil {
					diagMu.Lock()
					diagErrors = append(diagErrors, errorEntry{Category: "health-details", Repo: repo.Slug, Message: err.Error()})
					diagMu.Unlock()
					return &model.RepoStats{
						Repository: repo.Slug,
						Health:     h,
					}, nil
				}
			}

			return &model.RepoStats{
				Repository:    repo.Slug,
				Health:        h,
				HealthDetails: details,
			}, nil
		}, healthProgressFn)

		if useTUI && program != nil {
			program.Send(ui.DoneMsg{})
			time.Sleep(100 * time.Millisecond)
			program.Quit()
			program = nil
		}

		// Attach health data to analysis results
		healthByRepo := make(map[string]*model.RepoStats)
		for _, r := range healthResults {
			if r.Err == nil && r.Stats != nil {
				healthByRepo[r.Repo.Slug] = r.Stats
			}
		}

		for i := range results {
			if results[i].Stats != nil {
				if hs, ok := healthByRepo[results[i].Repo.Slug]; ok {
					results[i].Stats.Health = hs.Health
					results[i].Stats.HealthDetails = hs.HealthDetails
				}
			}
		}
	}

	// Churn analysis phase
	churnFlag, _ := cmd.Flags().GetBool("churn")
	churnLimit, _ := cmd.Flags().GetInt("churn-limit")

	if churnFlag {
		churnLister, ok := prov.(provider.ChurnLister)
		if !ok {
			return fmt.Errorf("provider %s does not support churn analysis", providerName)
		}

		fmt.Fprintln(os.Stderr, "Analyzing code churn...")

		if useTUI {
			program = ui.RunTUI(len(repoList))
			go func() { program.Run() }()
		}

		churnProgressFn := func(completed, total int, repo model.Repo) {
			if useTUI && program != nil {
				program.Send(ui.ProgressMsg{Completed: completed, Total: total, RepoName: repo.Slug})
			} else {
				fmt.Fprintf(os.Stderr, "[%d/%d] Churn %s\n", completed, total, repo.Slug)
			}
		}

		churnResults := worker.RunWithProgress(ctx, repoList, concurrency, func(ctx context.Context, repo model.Repo) (*model.RepoStats, error) {
			stats, err := churn.Analyze(ctx, churnLister, repo, churnLimit)
			if err != nil {
				return nil, err
			}
			return &model.RepoStats{Repository: repo.Slug, Churn: stats}, nil
		}, churnProgressFn)

		if useTUI && program != nil {
			program.Send(ui.DoneMsg{})
			time.Sleep(100 * time.Millisecond)
			program.Quit()
			program = nil
		}

		churnByRepo := make(map[string]*model.ChurnStats)
		for _, r := range churnResults {
			if r.Err == nil && r.Stats != nil && r.Stats.Churn != nil {
				churnByRepo[r.Repo.Slug] = r.Stats.Churn
			}
		}
		for i := range results {
			if results[i].Stats != nil {
				if cs, ok := churnByRepo[results[i].Repo.Slug]; ok {
					results[i].Stats.Churn = cs
				}
			}
		}
	}

	// Write error.log if there were any diagnostic errors
	if len(diagErrors) > 0 {
		ext := filepath.Ext(outputPath)
		errorLogPath := strings.TrimSuffix(outputPath, ext) + ".error.log"
		if err := os.MkdirAll(filepath.Dir(errorLogPath), 0o755); err != nil {
			return fmt.Errorf("create error log directory: %w", err)
		}
		f, err := os.Create(errorLogPath)
		if err != nil {
			return fmt.Errorf("create error log: %w", err)
		}
		for _, e := range diagErrors {
			fmt.Fprintf(f, "[%s] %s | %s\n", e.Category, e.Repo, e.Message)
		}
		f.Close()
		fmt.Fprintf(os.Stderr, "Error log written to %s (%d entries)\n", errorLogPath, len(diagErrors))
	}

	// Build report — use user/group as organization in metadata when set
	reportOrg := org
	if user != "" {
		reportOrg = user
	}
	if group != "" {
		reportOrg = group
	}
	report := buildReport(providerName, workspace, reportOrg, projects, repos, exclude, results)

	// Write JSON output
	var jsonWriter io.Writer = os.Stdout
	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
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

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", outputPath)
	}

	return nil
}

func newMarkdownCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "markdown [file]",
		Short: "Convert JSON report to markdown",
		Long:  "Reads a JSON report from a file argument or stdin and writes markdown to stdout.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runMarkdown,
	}

	cmd.Flags().Bool("narrative", false, "Generate AI narrative analysis instead of tables")
	cmd.Flags().String("ai-cli", "", "AI CLI to use (claude, codex, gemini). Default: auto-detect")
	cmd.Flags().String("ai-prompt", "", "Additional instructions for the AI narrative")
	cmd.Flags().String("ai-prompt-file", "", "Read additional AI instructions from file")

	return cmd
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

	useNarrative, _ := cmd.Flags().GetBool("narrative")

	if useNarrative {
		return runNarrative(cmd, data)
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

func runNarrative(cmd *cobra.Command, data []byte) error {
	aiCLI, _ := cmd.Flags().GetString("ai-cli")
	aiPrompt, _ := cmd.Flags().GetString("ai-prompt")
	aiPromptFile, _ := cmd.Flags().GetString("ai-prompt-file")

	if aiPrompt != "" && aiPromptFile != "" {
		return fmt.Errorf("--ai-prompt and --ai-prompt-file are mutually exclusive")
	}

	if aiPromptFile != "" {
		content, err := os.ReadFile(aiPromptFile)
		if err != nil {
			return fmt.Errorf("read prompt file: %w", err)
		}
		aiPrompt = string(content)
	}

	if aiCLI == "" {
		detected, err := narrative.DetectCLI()
		if err != nil {
			return err
		}
		aiCLI = detected
		fmt.Fprintf(os.Stderr, "Using %s for narrative generation\n", aiCLI)
	}

	ctx := cmd.Context()
	result, err := narrative.Generate(ctx, aiCLI, data, aiPrompt)
	if err != nil {
		return fmt.Errorf("narrative generation: %w", err)
	}

	fmt.Fprint(os.Stdout, result)
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
		report.Totals.FilteredFiles += r.Stats.FilteredFiles

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

	// Aggregate AI estimates
	var hasAI bool
	var totalCommits, aiCommits, aiAdditions int64
	for _, r := range results {
		if r.Err != nil || r.Stats == nil || r.Stats.AIEstimate == nil {
			continue
		}
		hasAI = true
		totalCommits += r.Stats.AIEstimate.TotalCommits
		aiCommits += r.Stats.AIEstimate.AICommits
		aiAdditions += r.Stats.AIEstimate.AIAdditions
	}
	if hasAI {
		var commitPct float64
		if totalCommits > 0 {
			commitPct = float64(aiCommits) / float64(totalCommits) * 100
		}
		report.AIEstimate = &model.AIEstimate{
			TotalCommits:  totalCommits,
			AICommits:     aiCommits,
			CommitPercent: commitPct,
			AIAdditions:   aiAdditions,
		}
	}

	// Aggregate health summary
	report.HealthSummary = health.Summarize(report.Repositories)

	// Aggregate secrets summary
	var totalFindings, reposWithSecrets int
	for _, repo := range report.Repositories {
		if repo.Secrets != nil && repo.Secrets.FindingsCount > 0 {
			totalFindings += repo.Secrets.FindingsCount
			reposWithSecrets++
		}
	}
	if reposWithSecrets > 0 {
		report.SecretsSummary = &model.SecretsAggregate{
			TotalFindings:    totalFindings,
			ReposWithSecrets: reposWithSecrets,
		}
	}

	// Aggregate SBOM summary
	var sbomTotalDeps, reposWithDeps int
	sbomEcoCounts := map[string]int{}
	for _, repo := range report.Repositories {
		if repo.SBOM != nil && repo.SBOM.TotalDeps > 0 {
			sbomTotalDeps += repo.SBOM.TotalDeps
			reposWithDeps++
			for _, eco := range repo.SBOM.Ecosystems {
				sbomEcoCounts[eco.Ecosystem] += eco.Count
			}
		}
	}
	if reposWithDeps > 0 {
		ecos := make([]model.EcosystemDeps, 0, len(sbomEcoCounts))
		for eco, count := range sbomEcoCounts {
			ecos = append(ecos, model.EcosystemDeps{Ecosystem: eco, Count: count})
		}
		sort.Slice(ecos, func(i, j int) bool {
			return ecos[i].Count > ecos[j].Count
		})
		report.SBOMSummary = &model.SBOMAggregate{
			TotalDeps:     sbomTotalDeps,
			ReposWithDeps: reposWithDeps,
			Ecosystems:    ecos,
		}
	}

	return report
}

func newTrendsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trends",
		Short: "Analyze repository trends over time using git history",
		RunE:  runTrends,
	}

	cmd.Flags().String("provider", "", "Provider (bitbucket, github, gitlab)")
	cmd.Flags().String("workspace", "", "Bitbucket workspace slug")
	cmd.Flags().String("org", "", "GitHub organization")
	cmd.Flags().String("user", "", "GitHub user (alternative to --org for personal repos)")
	cmd.Flags().String("group", "", "GitLab group path or ID")
	cmd.Flags().String("since", "", "Start period (YYYY-MM for monthly, YYYY-MM-DD for weekly)")
	cmd.Flags().String("until", "", "End period (YYYY-MM for monthly, YYYY-MM-DD for weekly)")
	cmd.Flags().String("interval", "monthly", "Interval: monthly or weekly")
	cmd.Flags().StringSlice("repos", nil, "Filter to specific repo names")
	cmd.Flags().StringSlice("exclude", nil, "Exclude specific repos")
	cmd.Flags().Bool("include-archived", false, "Include archived repos")
	cmd.Flags().Bool("include-forks", false, "Include forked repos")
	cmd.Flags().Int("concurrency", 5, "Number of parallel workers")
	cmd.Flags().String("output", "output/report.json", "Write JSON to file")
	cmd.Flags().Float64("rate-limit", 0, "Max API requests per second (0 = unlimited)")

	cmd.MarkFlagRequired("provider")
	cmd.MarkFlagRequired("since")
	cmd.MarkFlagRequired("until")

	return cmd
}

func runTrends(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer cancel()

	providerName, _ := cmd.Flags().GetString("provider")
	workspace, _ := cmd.Flags().GetString("workspace")
	org, _ := cmd.Flags().GetString("org")
	user, _ := cmd.Flags().GetString("user")
	group, _ := cmd.Flags().GetString("group")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	interval, _ := cmd.Flags().GetString("interval")
	repos, _ := cmd.Flags().GetStringSlice("repos")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	includeArchived, _ := cmd.Flags().GetBool("include-archived")
	includeForks, _ := cmd.Flags().GetBool("include-forks")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	outputPath, _ := cmd.Flags().GetString("output")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

	if interval != "monthly" && interval != "weekly" {
		return fmt.Errorf("--interval must be 'monthly' or 'weekly'")
	}

	store := auth.NewFileStore(auth.DefaultStorePath())
	cred, err := store.LoadWithEnv(providerName)
	if err != nil {
		return fmt.Errorf("not authenticated with %s — run 'codemium auth login --provider %s' first", providerName, providerName)
	}

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

	httpClient := &http.Client{Transport: &provider.RateLimitTransport{ReqPerSec: rateLimit}}

	var prov provider.Provider
	switch providerName {
	case "bitbucket":
		if workspace == "" {
			return fmt.Errorf("--workspace is required for bitbucket")
		}
		prov = provider.NewBitbucket(cred.AccessToken, cred.Username, "", httpClient)
	case "github":
		if org != "" && user != "" {
			return fmt.Errorf("--org and --user are mutually exclusive for github")
		}
		if org == "" && user == "" {
			return fmt.Errorf("--org or --user is required for github")
		}
		prov = provider.NewGitHub(cred.AccessToken, "", httpClient)
	case "gitlab":
		if group == "" {
			return fmt.Errorf("--group is required for gitlab")
		}
		baseURL := os.Getenv("CODEMIUM_GITLAB_URL")
		var refreshFn func() (string, bool)
		if os.Getenv("CODEMIUM_GITLAB_TOKEN") == "" {
			if _, err := store.Load("gitlab"); err != nil {
				refreshFn = auth.GlabCLIToken
			}
		}
		prov = provider.NewGitLabWithRefresh(cred.AccessToken, baseURL, httpClient, refreshFn)
	default:
		return fmt.Errorf("unsupported provider: %s", providerName)
	}

	// For GitLab, pass group as Organization
	trendsOrg := org
	if group != "" {
		trendsOrg = group
	}

	fmt.Fprintln(os.Stderr, "Listing repositories...")
	repoList, err := prov.ListRepos(ctx, provider.ListOpts{
		Workspace:       workspace,
		Organization:    trendsOrg,
		User:            user,
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

	// Trends requires full git clone for history — Bitbucket API tokens
	// only support tarball downloads, not git operations.
	if providerName == "bitbucket" && cred.Username != "" {
		return fmt.Errorf("trends requires OAuth credentials for Bitbucket (API tokens cannot clone git history)\nSet CODEMIUM_BITBUCKET_CLIENT_ID and CODEMIUM_BITBUCKET_CLIENT_SECRET, then run: codemium auth login --provider bitbucket")
	}

	dates := history.GenerateDates(since, until, interval)
	if len(dates) == 0 {
		return fmt.Errorf("no periods generated for --since %s --until %s --interval %s", since, until, interval)
	}

	periods := make([]string, len(dates))
	for i, d := range dates {
		periods[i] = history.FormatPeriod(d, interval)
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories, analyzing %d %s periods\n", len(repoList), len(dates), interval)

	useTUI := ui.IsTTY()
	var program *tea.Program
	if useTUI {
		program = ui.RunTUI(len(repoList))
		go func() { program.Run() }()
	}

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

	results := worker.RunTrends(ctx, repoList, concurrency, func(ctx context.Context, repo model.Repo) (map[string]*model.RepoStats, error) {
		gitRepo, dir, cleanup, err := cloner.CloneFull(ctx, repo.CloneURL)
		if err != nil {
			return nil, err
		}
		defer cleanup()

		commitMap, err := history.FindCommits(gitRepo, dates)
		if err != nil {
			return nil, fmt.Errorf("find commits: %w", err)
		}

		snapshots := make(map[string]*model.RepoStats, len(dates))
		for i, date := range dates {
			hash, ok := commitMap[date]
			if !ok {
				continue
			}

			if err := analyzer.Checkout(gitRepo, dir, hash); err != nil {
				continue
			}

			stats, err := codeAnalyzer.Analyze(ctx, dir)
			if err != nil {
				continue
			}

			stats.Repository = repo.Slug
			stats.Project = repo.Project
			stats.Provider = repo.Provider
			stats.URL = repo.URL
			snapshots[periods[i]] = stats
		}

		return snapshots, nil
	}, progressFn)

	if useTUI && program != nil {
		program.Send(ui.DoneMsg{})
		time.Sleep(100 * time.Millisecond)
		program.Quit()
	}

	reportOrg := org
	if user != "" {
		reportOrg = user
	}
	if group != "" {
		reportOrg = group
	}
	report := buildTrendsReport(providerName, workspace, reportOrg, since, until, interval, periods, repos, exclude, results)

	var jsonWriter io.Writer = os.Stdout
	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		jsonWriter = f
	}

	if err := output.WriteTrendsJSON(jsonWriter, report); err != nil {
		return err
	}

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", outputPath)
	}

	return nil
}

func buildTrendsReport(providerName, workspace, org, since, until, interval string, periods, repos, exclude []string, results []worker.TrendsResult) model.TrendsReport {
	report := model.TrendsReport{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Provider:     providerName,
		Workspace:    workspace,
		Organization: org,
		Filters: model.Filters{
			Repos:   repos,
			Exclude: exclude,
		},
		Since:    since,
		Until:    until,
		Interval: interval,
		Periods:  periods,
	}

	snapshotMap := make(map[string]*model.PeriodSnapshot, len(periods))
	for _, p := range periods {
		snapshotMap[p] = &model.PeriodSnapshot{Period: p}
	}

	for _, r := range results {
		if r.Err != nil {
			report.Errors = append(report.Errors, model.RepoError{
				Repository: r.Repo.Slug,
				Error:      r.Err.Error(),
			})
			continue
		}

		for period, stats := range r.Snapshots {
			snap := snapshotMap[period]
			snap.Repositories = append(snap.Repositories, *stats)
			snap.Totals.Repos++
			snap.Totals.Files += stats.Totals.Files
			snap.Totals.Lines += stats.Totals.Lines
			snap.Totals.Code += stats.Totals.Code
			snap.Totals.Comments += stats.Totals.Comments
			snap.Totals.Blanks += stats.Totals.Blanks
			snap.Totals.Complexity += stats.Totals.Complexity

			langMap := map[string]*model.LanguageStats{}
			for _, existing := range snap.ByLanguage {
				copy := existing
				langMap[existing.Name] = &copy
			}
			for _, lang := range stats.Languages {
				lt, ok := langMap[lang.Name]
				if !ok {
					lt = &model.LanguageStats{Name: lang.Name}
					langMap[lang.Name] = lt
				}
				lt.Files += lang.Files
				lt.Lines += lang.Lines
				lt.Code += lang.Code
				lt.Comments += lang.Comments
				lt.Blanks += lang.Blanks
				lt.Complexity += lang.Complexity
			}
			snap.ByLanguage = nil
			for _, lt := range langMap {
				snap.ByLanguage = append(snap.ByLanguage, *lt)
			}
			sort.Slice(snap.ByLanguage, func(i, j int) bool {
				return snap.ByLanguage[i].Code > snap.ByLanguage[j].Code
			})
		}
	}

	for _, p := range periods {
		report.Snapshots = append(report.Snapshots, *snapshotMap[p])
	}

	return report
}
