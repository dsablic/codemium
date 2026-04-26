// internal/provider/gitlab.go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dsablic/codemium/internal/model"
)

const gitlabAPIBase = "https://gitlab.com"

// GitLab implements Provider and CommitLister for GitLab.
type GitLab struct {
	token        string
	baseURL      string
	client       *http.Client
	tokenRefresh func() (string, bool)
	mu           sync.Mutex
}

// NewGitLab creates a new GitLab provider. If baseURL is empty,
// the default GitLab.com endpoint is used.
func NewGitLab(token string, baseURL string, client *http.Client) *GitLab {
	if baseURL == "" {
		baseURL = gitlabAPIBase
	}
	if client == nil {
		client = &http.Client{}
	}
	return &GitLab{
		token:   token,
		baseURL: baseURL,
		client:  client,
	}
}

// NewGitLabWithRefresh creates a GitLab provider with a token refresh callback.
// The refreshFn is called on 401 responses to obtain a fresh token (e.g. via glab CLI).
func NewGitLabWithRefresh(token string, baseURL string, client *http.Client, refreshFn func() (string, bool)) *GitLab {
	g := NewGitLab(token, baseURL, client)
	g.tokenRefresh = refreshFn
	return g
}

type gitlabProject struct {
	ID                int    `json:"id"`
	Path              string `json:"path"`
	PathWithNamespace string `json:"path_with_namespace"`
	Name              string `json:"name"`
	WebURL            string `json:"web_url"`
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	DefaultBranch     string `json:"default_branch"`
	Archived          bool   `json:"archived"`
	ForkedFromProject *struct {
		ID int `json:"id"`
	} `json:"forked_from_project"`
	Namespace struct {
		FullPath string `json:"full_path"`
	} `json:"namespace"`
}

func (g *GitLab) ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error) {
	var allRepos []model.Repo

	group := opts.Organization
	params := url.Values{}
	params.Set("per_page", "100")
	params.Set("include_subgroups", "true")
	params.Set("with_shared", "false")
	if !opts.IncludeArchived {
		params.Set("archived", "false")
	}

	nextURL := fmt.Sprintf("%s/api/v4/groups/%s/projects?%s",
		g.baseURL, url.PathEscape(group), params.Encode())

	for nextURL != "" {
		repos, next, err := g.fetchPage(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		for _, r := range repos {
			if !opts.IncludeForks && r.Fork {
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

func (g *GitLab) doGet(ctx context.Context, reqURL string) (*http.Response, error) {
	g.mu.Lock()
	token := g.token
	g.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized && g.tokenRefresh != nil {
		resp.Body.Close()
		if newToken, ok := g.tokenRefresh(); ok && newToken != token {
			g.mu.Lock()
			g.token = newToken
			g.mu.Unlock()

			req2, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
			if err != nil {
				return nil, err
			}
			req2.Header.Set("Authorization", "Bearer "+newToken)
			return g.client.Do(req2)
		}
		// Token refresh failed or returned same token; return a clear error
		// instead of the response with a closed body.
		return nil, fmt.Errorf("gitlab API returned 401 and token refresh failed")
	}

	return resp, nil
}

func (g *GitLab) fetchPage(ctx context.Context, pageURL string) ([]model.Repo, string, error) {
	resp, err := g.doGet(ctx, pageURL)
	if err != nil {
		return nil, "", fmt.Errorf("gitlab API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", statusError("gitlab API", resp)
	}

	var projects []gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, "", fmt.Errorf("decode gitlab response: %w", err)
	}

	var repos []model.Repo
	for _, p := range projects {
		repos = append(repos, model.Repo{
			Name:          p.Name,
			Slug:          p.Path,
			Project:       p.Namespace.FullPath,
			URL:           p.WebURL,
			CloneURL:      p.HTTPURLToRepo,
			Provider:      "gitlab",
			DefaultBranch: p.DefaultBranch,
			Archived:      p.Archived,
			Fork:          p.ForkedFromProject != nil,
		})
	}

	nextURL := g.nextPageURL(pageURL, resp)
	return repos, nextURL, nil
}

func (g *GitLab) nextPageURL(currentURL string, resp *http.Response) string {
	// Try x-next-page header first (offset-based pagination)
	if next := resp.Header.Get("X-Next-Page"); next != "" {
		u, err := url.Parse(currentURL)
		if err != nil {
			return ""
		}
		q := u.Query()
		q.Set("page", next)
		u.RawQuery = q.Encode()
		return u.String()
	}
	// Fall back to Link header (keyset pagination)
	return parseLinkNext(resp.Header.Get("Link"))
}

// Subgroup represents a GitLab subgroup within a group.
type Subgroup struct {
	ID       int
	Path     string
	FullPath string
	Name     string
}

// ListSubgroups fetches all subgroups in a GitLab group.
func (g *GitLab) ListSubgroups(ctx context.Context, group string) ([]Subgroup, error) {
	var all []Subgroup
	nextURL := fmt.Sprintf("%s/api/v4/groups/%s/subgroups?per_page=100",
		g.baseURL, url.PathEscape(group))

	for nextURL != "" {
		resp, err := g.doGet(ctx, nextURL)
		if err != nil {
			return nil, fmt.Errorf("gitlab subgroups request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			err := statusError("gitlab subgroups API", resp)
			resp.Body.Close()
			return nil, err
		}

		var subgroups []struct {
			ID       int    `json:"id"`
			Path     string `json:"path"`
			FullPath string `json:"full_path"`
			Name     string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&subgroups); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode subgroups response: %w", err)
		}
		resp.Body.Close()

		for _, s := range subgroups {
			all = append(all, Subgroup{
				ID:       s.ID,
				Path:     s.Path,
				FullPath: s.FullPath,
				Name:     s.Name,
			})
		}

		nextURL = g.nextPageURL(nextURL, resp)
	}

	return all, nil
}

func gitlabProjectID(repoURL string) string {
	// Extract path from URL like https://gitlab.com/group/subgroup/project
	u, err := url.Parse(repoURL)
	if err != nil {
		return ""
	}
	path := strings.TrimPrefix(u.Path, "/")
	return url.PathEscape(path)
}

type gitlabCommit struct {
	ID            string `json:"id"`
	AuthorName    string `json:"author_name"`
	AuthorEmail   string `json:"author_email"`
	Message       string `json:"message"`
	CommittedDate string `json:"committed_date"`
}

// ListCommits fetches up to limit commits for a repo via the GitLab API.
func (g *GitLab) ListCommits(ctx context.Context, repo model.Repo, limit int) ([]CommitInfo, error) {
	projectID := gitlabProjectID(repo.URL)
	if projectID == "" {
		return nil, fmt.Errorf("cannot parse project path from URL: %s", repo.URL)
	}

	var all []CommitInfo
	perPage := 100
	if limit > 0 && limit < perPage {
		perPage = limit
	}
	nextURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/commits?per_page=%d",
		g.baseURL, projectID, perPage)

	for nextURL != "" {
		resp, err := g.doGet(ctx, nextURL)
		if err != nil {
			return nil, fmt.Errorf("gitlab commits API: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			err := statusError("gitlab commits API", resp)
			resp.Body.Close()
			return nil, err
		}

		var commits []gitlabCommit
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode gitlab commits: %w", err)
		}

		nextPage := resp.Header.Get("X-Next-Page")
		resp.Body.Close()

		for _, c := range commits {
			commitDate, err := time.Parse(time.RFC3339, c.CommittedDate)
			if err != nil {
				commitDate = time.Time{} // zero time on parse failure
			}
			all = append(all, CommitInfo{
				Hash:    c.ID,
				Author:  fmt.Sprintf("%s <%s>", c.AuthorName, c.AuthorEmail),
				Message: c.Message,
				Date:    commitDate,
			})
			if limit > 0 && len(all) >= limit {
				return all, nil
			}
		}

		if nextPage == "" {
			break
		}
		u, err := url.Parse(nextURL)
		if err != nil {
			break
		}
		q := u.Query()
		q.Set("page", nextPage)
		u.RawQuery = q.Encode()
		nextURL = u.String()
	}

	return all, nil
}

type gitlabCommitDetail struct {
	Stats struct {
		Additions int64 `json:"additions"`
		Deletions int64 `json:"deletions"`
	} `json:"stats"`
}

// CommitStats fetches addition/deletion counts for a single GitLab commit.
func (g *GitLab) CommitStats(ctx context.Context, repo model.Repo, hash string) (int64, int64, error) {
	projectID := gitlabProjectID(repo.URL)
	if projectID == "" {
		return 0, 0, fmt.Errorf("cannot parse project path from URL: %s", repo.URL)
	}

	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/commits/%s",
		g.baseURL, projectID, url.PathEscape(hash))

	resp, err := g.doGet(ctx, apiURL)
	if err != nil {
		return 0, 0, fmt.Errorf("gitlab commit detail API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, statusError("gitlab commit detail API", resp)
	}

	var detail gitlabCommitDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return 0, 0, fmt.Errorf("decode gitlab commit detail: %w", err)
	}

	return detail.Stats.Additions, detail.Stats.Deletions, nil
}

// ensure GitLab satisfies both interfaces at compile time.
var _ Provider = (*GitLab)(nil)
var _ CommitLister = (*GitLab)(nil)
