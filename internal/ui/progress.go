// Package ui provides progress display for repository analysis.
package ui

import (
	"fmt"
	"os"
	"strings"

	"charm.land/bubbles/v2/progress"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"
)

// IsTTY returns true if stderr is a terminal.
func IsTTY() bool {
	return term.IsTerminal(os.Stderr.Fd())
}

// --- Plain text fallback ---

// PlainProgress prints progress messages to a callback function.
// Used when stderr is not a TTY (e.g., piped output).
type PlainProgress struct {
	print func(string)
}

// NewPlainProgress creates a new PlainProgress with the given print callback.
func NewPlainProgress(print func(string)) *PlainProgress {
	return &PlainProgress{print: print}
}

// Update prints a progress message for a completed repository.
func (p *PlainProgress) Update(completed, total int, repoName string) {
	p.print(fmt.Sprintf("[%d/%d] Analyzed %s", completed, total, repoName))
}

// Done prints a completion message.
func (p *PlainProgress) Done(total int) {
	p.print(fmt.Sprintf("Done! Analyzed %d repositories.", total))
}

// --- TUI progress ---

// ProgressMsg is sent to the bubbletea program when a repository is analyzed.
type ProgressMsg struct {
	Completed int
	Total     int
	RepoName  string
}

// DoneMsg is sent to the bubbletea program when all repositories are analyzed.
type DoneMsg struct{}

type model struct {
	progress  progress.Model
	completed int
	total     int
	repoName  string
	done      bool
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

// NewTUIModel creates a new bubbletea model for the progress TUI.
func NewTUIModel(total int) model {
	p := progress.New(
		progress.WithDefaultBlend(),
		progress.WithWidth(50),
		progress.WithoutPercentage(),
	)
	return model{
		progress: p,
		total:    total,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		w := msg.Width - 10
		if w > 60 {
			w = 60
		}
		m.progress.SetWidth(w)
	case ProgressMsg:
		m.completed = msg.Completed
		m.total = msg.Total
		m.repoName = msg.RepoName
		pct := float64(m.completed) / float64(m.total)
		return m, m.progress.SetPercent(pct)
	case DoneMsg:
		m.done = true
		return m, tea.Quit
	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel
		return m, cmd
	}
	return m, nil
}

func (m model) View() tea.View {
	var s string
	if m.done {
		s = fmt.Sprintf("\n  %s\n\n",
			titleStyle.Render(fmt.Sprintf("Done! Analyzed %d repositories.", m.total)))
	} else {
		pad := strings.Repeat(" ", 2)
		counter := infoStyle.Render(fmt.Sprintf("%d/%d", m.completed, m.total))
		desc := m.repoName
		if desc == "" {
			desc = "Starting..."
		}

		s = "\n" +
			pad + titleStyle.Render("Analyzing repositories") + "\n" +
			pad + m.progress.View() + "  " + counter + "\n" +
			pad + infoStyle.Render(desc) + "\n\n"
	}
	return tea.NewView(s)
}

// RunTUI creates and returns a bubbletea program for the progress TUI.
// The program outputs to stderr so JSON output on stdout stays clean.
func RunTUI(total int) *tea.Program {
	m := NewTUIModel(total)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	return p
}
