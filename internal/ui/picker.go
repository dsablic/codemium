package ui

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/huh"
	"github.com/dsablic/codemium/internal/provider"
)

const selectAllKey = "__all__"

func PickProjects(projects []provider.Project) ([]string, error) {
	if len(projects) == 0 {
		return nil, nil
	}

	sort.Slice(projects, func(i, j int) bool {
		return projects[i].Key < projects[j].Key
	})

	opts := make([]huh.Option[string], 0, len(projects)+1)
	opts = append(opts, huh.NewOption[string]("Select All", selectAllKey))
	for _, p := range projects {
		label := fmt.Sprintf("%s — %s", p.Key, p.Name)
		opts = append(opts, huh.NewOption[string](label, p.Key))
	}

	var selected []string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select Bitbucket projects to analyze").
				Options(opts...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	for _, s := range selected {
		if s == selectAllKey {
			keys := make([]string, len(projects))
			for i, p := range projects {
				keys[i] = p.Key
			}
			return keys, nil
		}
	}

	return selected, nil
}
