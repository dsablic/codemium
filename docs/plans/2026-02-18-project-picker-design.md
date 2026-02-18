# Bitbucket Project Picker Design

## Summary

Add an interactive multi-select picker for Bitbucket projects when running `analyze` without `--projects` in a TTY.

## Behavior

1. User runs `codemium analyze --provider bitbucket --workspace ws` (no `--projects`)
2. If TTY: fetch all projects from Bitbucket API, show interactive picker
3. Picker shows checkbox list with "Select All" toggle at top, then all projects (key + name)
4. Space toggles, Enter confirms
5. Selected project keys feed into the existing `--projects` filter
6. Empty selection = analyze all repos (current behavior)
7. Non-TTY: skip picker, analyze all repos (current behavior preserved)

## Components

### Bitbucket provider: `ListProjects`

New method on `Bitbucket` provider:

```go
type Project struct {
    Key  string
    Name string
}

func (b *Bitbucket) ListProjects(ctx context.Context, workspace string) ([]Project, error)
```

Calls `GET /2.0/workspaces/{workspace}/projects?pagelen=100`, handles pagination.

### UI: project picker using huh

Use `charmbracelet/huh` multi-select form. First option is "Select All" which toggles all projects. Returns selected project keys.

```go
func PickProjects(projects []provider.Project) ([]string, error)
```

### Analyze command integration

In `runAnalyze`, after creating the Bitbucket provider and before `ListRepos`:

```
if bitbucket && no --projects flag && IsTTY:
    projects = ListProjects(...)
    selected = PickProjects(projects)
    if len(selected) > 0:
        opts.Projects = selected
```

## Dependencies

- `charmbracelet/huh` — interactive form library (same Charm ecosystem already in use)
