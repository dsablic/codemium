// internal/provider/provider.go
package provider

import (
	"context"

	"github.com/dsablic/codemium/internal/model"
)

// ListOpts configures which repositories to retrieve from a provider.
type ListOpts struct {
	Workspace       string
	Organization    string
	User            string
	Projects        []string
	Repos           []string
	Exclude         []string
	IncludeArchived bool
	IncludeForks    bool
}

// Provider is the interface that both Bitbucket and GitHub implement
// for listing repositories.
type Provider interface {
	ListRepos(ctx context.Context, opts ListOpts) ([]model.Repo, error)
}
