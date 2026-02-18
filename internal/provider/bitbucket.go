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
	token   string
	baseURL string
	client  *http.Client
}

// NewBitbucket creates a new Bitbucket provider. If baseURL is empty,
// the default Bitbucket Cloud API endpoint is used.
func NewBitbucket(token string, baseURL string) *Bitbucket {
	if baseURL == "" {
		baseURL = bitbucketAPIBase
	}
	return &Bitbucket{
		token:   token,
		baseURL: baseURL,
		client:  &http.Client{},
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

func (b *Bitbucket) fetchPage(ctx context.Context, pageURL string) ([]model.Repo, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)

	resp, err := b.client.Do(req)
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

		repos = append(repos, model.Repo{
			Name:     bbRepo.Slug,
			Slug:     bbRepo.Slug,
			Project:  bbRepo.Project.Key,
			URL:      bbRepo.Links.HTML.Href,
			CloneURL: cloneURL,
			Provider: "bitbucket",
			Fork:     bbRepo.Parent != nil,
		})
	}

	return repos, page.Next, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
