// internal/provider/github.go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dsablic/codemium/internal/model"
)

const githubAPIBase = "https://api.github.com"

// GitHub implements Provider for GitHub.
type GitHub struct {
	token   string
	baseURL string
	client  *http.Client
}

// NewGitHub creates a new GitHub provider. If baseURL is empty,
// the default GitHub API endpoint is used.
func NewGitHub(token string, baseURL string, client *http.Client) *GitHub {
	if baseURL == "" {
		baseURL = githubAPIBase
	}
	if client == nil {
		client = &http.Client{}
	}
	return &GitHub{
		token:   token,
		baseURL: baseURL,
		client:  client,
	}
}

// ListRepos fetches all repositories matching the given options from
// the GitHub API, handling Link header pagination automatically.
func (g *GitHub) ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error) {
	var allRepos []model.Repo

	var nextURL string
	switch {
	case opts.User != "":
		// Use the authenticated /user/repos endpoint which includes private repos,
		// filtered to repos owned by the authenticated user.
		nextURL = fmt.Sprintf("%s/user/repos?per_page=100&affiliation=owner", g.baseURL)
	default:
		nextURL = fmt.Sprintf("%s/orgs/%s/repos?per_page=100&type=all", g.baseURL, opts.Organization)
	}

	for nextURL != "" {
		repos, next, err := g.fetchPage(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		for _, r := range repos {
			if !opts.IncludeForks && r.Fork {
				continue
			}
			if !opts.IncludeArchived && r.Archived {
				continue
			}
			if len(opts.Repos) > 0 && !contains(opts.Repos, r.Slug) {
				continue
			}
			if len(opts.Exclude) > 0 && contains(opts.Exclude, r.Slug) {
				continue
			}
			allRepos = append(allRepos, r)
		}

		nextURL = next
	}

	return allRepos, nil
}

type githubRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
}

func (g *GitHub) fetchPage(ctx context.Context, pageURL string) ([]model.Repo, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("github API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", statusError("github API", resp)
	}

	var ghRepos []githubRepo
	if err := json.NewDecoder(resp.Body).Decode(&ghRepos); err != nil {
		return nil, "", fmt.Errorf("decode github response: %w", err)
	}

	var repos []model.Repo
	for _, r := range ghRepos {
		repos = append(repos, model.Repo{
			Name:          r.Name,
			Slug:          r.Name,
			URL:           r.HTMLURL,
			CloneURL:      r.CloneURL,
			Provider:      "github",
			DefaultBranch: r.DefaultBranch,
			Archived:      r.Archived,
			Fork:          r.Fork,
		})
	}

	nextURL := parseLinkNext(resp.Header.Get("Link"))
	return repos, nextURL, nil
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func parseLinkNext(header string) string {
	matches := linkNextRe.FindStringSubmatch(header)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func ownerRepo(repoURL string) (string, string) {
	parts := strings.Split(strings.TrimRight(repoURL, "/"), "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

type githubCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Author struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Date  string `json:"date"`
		} `json:"author"`
		Message string `json:"message"`
	} `json:"commit"`
}

type githubCommitDetail struct {
	Stats struct {
		Additions int64 `json:"additions"`
		Deletions int64 `json:"deletions"`
	} `json:"stats"`
}

type githubFileChange struct {
	Filename  string `json:"filename"`
	Additions int64  `json:"additions"`
	Deletions int64  `json:"deletions"`
}

// ListCommits fetches up to limit commits for a repo via the GitHub API.
func (g *GitHub) ListCommits(ctx context.Context, repo model.Repo, limit int) ([]CommitInfo, error) {
	owner, name := ownerRepo(repo.URL)
	if owner == "" {
		return nil, fmt.Errorf("cannot parse owner/repo from URL: %s", repo.URL)
	}

	var all []CommitInfo
	nextURL := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100", g.baseURL, owner, name)

	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+g.token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github commits API: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			err := statusError("github commits API", resp)
			resp.Body.Close()
			return nil, err
		}

		var commits []githubCommit
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode github commits: %w", err)
		}
		resp.Body.Close()

		for _, c := range commits {
			commitDate, err := time.Parse(time.RFC3339, c.Commit.Author.Date)
			if err != nil {
				commitDate = time.Time{} // zero time on parse failure
			}
			all = append(all, CommitInfo{
				Hash:    c.SHA,
				Author:  fmt.Sprintf("%s <%s>", c.Commit.Author.Name, c.Commit.Author.Email),
				Message: c.Commit.Message,
				Date:    commitDate,
			})
			if limit > 0 && len(all) >= limit {
				return all, nil
			}
		}

		nextURL = parseLinkNext(resp.Header.Get("Link"))
	}

	return all, nil
}

// CommitStats fetches addition/deletion counts for a single commit.
func (g *GitHub) CommitStats(ctx context.Context, repo model.Repo, hash string) (int64, int64, error) {
	owner, name := ownerRepo(repo.URL)
	if owner == "" {
		return 0, 0, fmt.Errorf("cannot parse owner/repo from URL: %s", repo.URL)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", g.baseURL, owner, name, hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("github commit detail API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, statusError("github commit detail API", resp)
	}

	var detail githubCommitDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return 0, 0, fmt.Errorf("decode github commit detail: %w", err)
	}

	return detail.Stats.Additions, detail.Stats.Deletions, nil
}

// CommitFileStats fetches per-file addition/deletion counts for a single commit.
func (g *GitHub) CommitFileStats(ctx context.Context, repo model.Repo, hash string) ([]FileChange, error) {
	owner, name := ownerRepo(repo.URL)
	if owner == "" {
		return nil, fmt.Errorf("cannot parse owner/repo from URL: %s", repo.URL)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", g.baseURL, owner, name, hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github commit detail API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, statusError("github commit detail API", resp)
	}

	var detail struct {
		Files []githubFileChange `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("decode github commit files: %w", err)
	}

	changes := make([]FileChange, len(detail.Files))
	for i, f := range detail.Files {
		changes[i] = FileChange{Path: f.Filename, Additions: f.Additions, Deletions: f.Deletions}
	}
	return changes, nil
}
