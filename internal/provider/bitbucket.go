// internal/provider/bitbucket.go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dsablic/codemium/internal/model"
)

const bitbucketAPIBase = "https://api.bitbucket.org"

// Bitbucket implements Provider for Bitbucket Cloud.
type Bitbucket struct {
	token    string
	username string
	baseURL  string
	client   *http.Client
}

// Project represents a Bitbucket project within a workspace.
type Project struct {
	Key  string
	Name string
}

// NewBitbucket creates a new Bitbucket provider. If baseURL is empty,
// the default Bitbucket Cloud API endpoint is used. If username is
// non-empty, Basic Auth is used instead of Bearer token auth.
func NewBitbucket(token, username, baseURL string) *Bitbucket {
	if baseURL == "" {
		baseURL = bitbucketAPIBase
	}
	return &Bitbucket{
		token:    token,
		username: username,
		baseURL:  baseURL,
		client:   &http.Client{},
	}
}

// ListRepos fetches all repositories matching the given options from
// the Bitbucket API, handling pagination automatically.
func (b *Bitbucket) ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error) {
	var allRepos []model.Repo

	nextURL := b.buildListURL(opts)

	for nextURL != "" {
		repos, next, err := b.fetchPage(ctx, nextURL)
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

func (b *Bitbucket) buildListURL(opts ListOpts) string {
	u := fmt.Sprintf("%s/2.0/repositories/%s", b.baseURL, url.PathEscape(opts.Workspace))
	params := url.Values{}
	params.Set("pagelen", "100")

	if len(opts.Projects) > 0 {
		clauses := make([]string, len(opts.Projects))
		for i, p := range opts.Projects {
			clauses[i] = fmt.Sprintf(`project.key="%s"`, p)
		}
		params.Set("q", strings.Join(clauses, " OR "))
	}

	return u + "?" + params.Encode()
}

type bitbucketPage struct {
	Values []json.RawMessage `json:"values"`
	Next   string            `json:"next"`
}

type bitbucketRepo struct {
	Slug     string `json:"slug"`
	FullName string `json:"full_name"`
	Project  struct {
		Key string `json:"key"`
	} `json:"project"`
	MainBranch *struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
	} `json:"links"`
	Parent *struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
}

func (b *Bitbucket) doGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if b.username != "" {
		req.SetBasicAuth(b.username, b.token)
	} else {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.client.Do(req)
}

func (b *Bitbucket) fetchPage(ctx context.Context, pageURL string) ([]model.Repo, string, error) {
	resp, err := b.doGet(ctx, pageURL)
	if err != nil {
		return nil, "", fmt.Errorf("bitbucket API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("bitbucket API returned status %d", resp.StatusCode)
	}

	var page bitbucketPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, "", fmt.Errorf("decode bitbucket response: %w", err)
	}

	var repos []model.Repo
	for _, raw := range page.Values {
		var bbRepo bitbucketRepo
		if err := json.Unmarshal(raw, &bbRepo); err != nil {
			continue
		}

		cloneURL := ""
		for _, c := range bbRepo.Links.Clone {
			if c.Name == "https" {
				cloneURL = c.Href
				break
			}
		}

		branch := "main"
		if bbRepo.MainBranch != nil && bbRepo.MainBranch.Name != "" {
			branch = bbRepo.MainBranch.Name
		}

		downloadURL := fmt.Sprintf("https://bitbucket.org/%s/get/%s.tar.gz",
			bbRepo.FullName, url.PathEscape(branch))

		repos = append(repos, model.Repo{
			Name:          bbRepo.Slug,
			Slug:          bbRepo.Slug,
			Project:       bbRepo.Project.Key,
			URL:           bbRepo.Links.HTML.Href,
			CloneURL:      cloneURL,
			DownloadURL:   downloadURL,
			Provider:      "bitbucket",
			DefaultBranch: branch,
			Fork:          bbRepo.Parent != nil,
		})
	}

	return repos, page.Next, nil
}

type bitbucketProject struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// ListProjects fetches all projects in a Bitbucket workspace, handling
// pagination automatically.
func (b *Bitbucket) ListProjects(ctx context.Context, workspace string) ([]Project, error) {
	var all []Project
	nextURL := fmt.Sprintf("%s/2.0/workspaces/%s/projects?pagelen=100", b.baseURL, url.PathEscape(workspace))

	for nextURL != "" {
		resp, err := b.doGet(ctx, nextURL)
		if err != nil {
			return nil, fmt.Errorf("bitbucket projects request: %w", err)
		}

		if resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, fmt.Errorf("bitbucket projects API returned 403 — add read:project:bitbucket scope to your API token")
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("bitbucket projects API returned status %d", resp.StatusCode)
		}

		var page struct {
			Values []bitbucketProject `json:"values"`
			Next   string             `json:"next"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode projects response: %w", err)
		}
		resp.Body.Close()

		for _, p := range page.Values {
			all = append(all, Project{Key: p.Key, Name: p.Name})
		}
		nextURL = page.Next
	}

	return all, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
