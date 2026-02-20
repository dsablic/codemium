// internal/provider/github.go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
func NewGitHub(token string, baseURL string) *GitHub {
	if baseURL == "" {
		baseURL = githubAPIBase
	}
	return &GitHub{
		token:   token,
		baseURL: baseURL,
		client:  &http.Client{},
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
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
	Archived bool   `json:"archived"`
	Fork     bool   `json:"fork"`
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
		return nil, "", fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var ghRepos []githubRepo
	if err := json.NewDecoder(resp.Body).Decode(&ghRepos); err != nil {
		return nil, "", fmt.Errorf("decode github response: %w", err)
	}

	var repos []model.Repo
	for _, r := range ghRepos {
		repos = append(repos, model.Repo{
			Name:     r.Name,
			Slug:     r.Name,
			URL:      r.HTMLURL,
			CloneURL: r.CloneURL,
			Provider: "github",
			Archived: r.Archived,
			Fork:     r.Fork,
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

		var commits []githubCommit
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode github commits: %w", err)
		}
		resp.Body.Close()

		for _, c := range commits {
			all = append(all, CommitInfo{
				Hash:    c.SHA,
				Author:  fmt.Sprintf("%s <%s>", c.Commit.Author.Name, c.Commit.Author.Email),
				Message: c.Commit.Message,
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
		return 0, 0, fmt.Errorf("github commit detail API returned status %d", resp.StatusCode)
	}

	var detail githubCommitDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return 0, 0, fmt.Errorf("decode github commit detail: %w", err)
	}

	return detail.Stats.Additions, detail.Stats.Deletions, nil
}
