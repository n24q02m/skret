package tui

import (
	"context"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// RevealFunc fetches (and decrypts) a single secret value on demand.
type RevealFunc func(ctx context.Context, key string) (string, error)

const mask = "••••••••"

type item struct{ key string }

func (i item) Title() string       { return i.key }
func (i item) Description() string { return "" }
func (i item) FilterValue() string { return i.key }

// Model is the browse TUI state. reveal is injected so it is testable without a
// provider or a terminal.
type Model struct {
	list     list.Model
	reveal   RevealFunc
	shown    map[string]string // key -> revealed value (cache)
	revealed map[string]bool   // key -> currently shown
	err      string            // last reveal error (NEVER contains a value)
	ctx      context.Context
}

// NewModel builds a browse Model over the given key names. reveal is invoked
// lazily (at most once per key) the first time a value is shown.
func NewModel(names []string, reveal RevealFunc) Model {
	items := make([]list.Item, len(names))
	for i, n := range names {
		items[i] = item{key: n}
	}
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Secrets"
	return Model{
		list:     l,
		reveal:   reveal,
		shown:    map[string]string{},
		revealed: map[string]bool{},
		ctx:      context.Background(),
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height-3)
		return m, nil
	case tea.KeyMsg:
		if m.list.FilterState() == list.Filtering {
			break // list owns keys while filtering (so typing filters)
		}
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "enter", " ":
			m.toggleReveal()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// toggleReveal flips the reveal state of the selected key, fetching (and
// caching) the value on first reveal. The fetched value is never placed into
// m.err.
func (m *Model) toggleReveal() {
	it, ok := m.list.SelectedItem().(item)
	if !ok {
		return
	}
	if m.revealed[it.key] {
		m.revealed[it.key] = false
		return
	}
	if _, cached := m.shown[it.key]; !cached {
		v, err := m.reveal(m.ctx, it.key)
		if err != nil {
			m.err = "failed to reveal " + it.key // NEVER include the value
			return
		}
		m.shown[it.key] = v
	}
	m.revealed[it.key] = true
	m.err = ""
}

// View implements tea.Model.
func (m Model) View() string {
	detail := ""
	revealAction := "reveal"
	if it, ok := m.list.SelectedItem().(item); ok {
		val := mask
		if m.revealed[it.key] {
			val = m.shown[it.key]
			revealAction = "hide"
		}
		detail = lipgloss.JoinVertical(lipgloss.Left, "Key:   "+it.key, "Value: "+val)
	}
	footer := "up/down move - / filter - enter " + revealAction + " - q quit"
	if m.err != "" {
		footer = m.err + "  |  " + footer
	}
	return lipgloss.JoinVertical(lipgloss.Left, m.list.View(), detail, footer)
}
