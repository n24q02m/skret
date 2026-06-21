package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretVal = "top-secret-val"

func enter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }

func runes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// sized returns a model with a non-zero window size so the list renders.
func sized(t *testing.T, m Model) Model {
	t.Helper()
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return updated.(Model)
}

func send(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	updated, cmd := m.Update(msg)
	return updated.(Model), cmd
}

func TestReveal_TogglesAndCaches(t *testing.T) {
	calls := 0
	reveal := func(_ context.Context, _ string) (string, error) {
		calls++
		return secretVal, nil
	}
	m := sized(t, NewModel([]string{"DB_URL", "API_KEY"}, reveal))

	// First reveal: value visible, reveal called once.
	m, _ = send(t, m, enter())
	assert.Contains(t, m.View(), secretVal)
	assert.Equal(t, 1, calls)

	// Second enter: hidden again (masked), reveal NOT called again.
	m, _ = send(t, m, enter())
	assert.NotContains(t, m.View(), secretVal)
	assert.Contains(t, m.View(), mask)
	assert.Equal(t, 1, calls)

	// Third enter: shown from cache, still only one reveal call.
	m, _ = send(t, m, enter())
	assert.Contains(t, m.View(), secretVal)
	assert.Equal(t, 1, calls, "reveal must be cached, not refetched")
}

func TestReveal_Error(t *testing.T) {
	reveal := func(_ context.Context, _ string) (string, error) {
		return secretVal, errors.New("boom")
	}
	m := sized(t, NewModel([]string{"DB_URL"}, reveal))

	require.NotPanics(t, func() {
		m, _ = send(t, m, enter())
	})

	out := m.View()
	assert.Contains(t, out, "failed to reveal")
	assert.NotContains(t, out, secretVal, "error view must never leak the value")
}

func TestDefault_Masked(t *testing.T) {
	reveal := func(_ context.Context, _ string) (string, error) { return secretVal, nil }
	m := sized(t, NewModel([]string{"DB_URL"}, reveal))

	out := m.View()
	assert.Contains(t, out, mask)
	assert.NotContains(t, out, secretVal)
}

func TestQuit(t *testing.T) {
	reveal := func(_ context.Context, _ string) (string, error) { return secretVal, nil }
	m := sized(t, NewModel([]string{"DB_URL"}, reveal))

	_, cmd := send(t, m, runes("q"))
	require.NotNil(t, cmd)
	msg := cmd()
	_, ok := msg.(tea.QuitMsg)
	assert.True(t, ok, "q must produce a tea.QuitMsg")
}

func TestValueSafety(t *testing.T) {
	// Masked (default) view must not contain the value.
	okReveal := func(_ context.Context, _ string) (string, error) { return secretVal, nil }
	m := sized(t, NewModel([]string{"DB_URL"}, okReveal))
	assert.NotContains(t, m.View(), secretVal, "default view must not leak value")

	// Error view must not contain the value either.
	errReveal := func(_ context.Context, _ string) (string, error) {
		return secretVal, errors.New("boom")
	}
	me := sized(t, NewModel([]string{"DB_URL"}, errReveal))
	me, _ = send(t, me, enter())
	assert.NotContains(t, me.View(), secretVal, "error view must not leak value")
}

func TestInit_NoCmd(t *testing.T) {
	reveal := func(_ context.Context, _ string) (string, error) { return secretVal, nil }
	m := NewModel([]string{"DB_URL"}, reveal)
	assert.Nil(t, m.Init())
}

func TestItem_Interface(t *testing.T) {
	it := item{key: "DB_URL"}
	assert.Equal(t, "DB_URL", it.Title())
	assert.Equal(t, "", it.Description())
	assert.Equal(t, "DB_URL", it.FilterValue())
}

func TestNavigation_DownChangesSelection(t *testing.T) {
	reveal := func(_ context.Context, key string) (string, error) { return "val-of-" + key, nil }
	m := sized(t, NewModel([]string{"DB_URL", "API_KEY"}, reveal))

	// Selected key starts at DB_URL.
	assert.Contains(t, m.View(), "Key:   DB_URL")

	// Move down: selection becomes API_KEY.
	m, _ = send(t, m, tea.KeyMsg{Type: tea.KeyDown})
	assert.Contains(t, m.View(), "Key:   API_KEY")
}

func TestFilter_KeystrokesGoToList(t *testing.T) {
	reveal := func(_ context.Context, _ string) (string, error) { return secretVal, nil }
	m := sized(t, NewModel([]string{"DB_URL", "API_KEY"}, reveal))

	// Activate the list filter with "/".
	m, _ = send(t, m, runes("/"))

	// While filtering, "q" must NOT quit; it is consumed by the filter input.
	_, cmd := send(t, m, runes("q"))
	if cmd != nil {
		if msg := cmd(); msg != nil {
			_, isQuit := msg.(tea.QuitMsg)
			assert.False(t, isQuit, "q while filtering must not quit")
		}
	}
}

func TestReveal_FooterActionChanges(t *testing.T) {
	reveal := func(_ context.Context, _ string) (string, error) { return secretVal, nil }
	m := sized(t, NewModel([]string{"DB_URL"}, reveal))

	// Initially masked: footer should say "enter reveal"
	assert.Contains(t, m.View(), "enter reveal")
	assert.NotContains(t, m.View(), "enter hide")

	// Enter to reveal: footer should change to "enter hide"
	m, _ = send(t, m, enter())
	assert.Contains(t, m.View(), "enter hide")
	assert.NotContains(t, m.View(), "enter reveal")

	// Enter to hide again: footer should revert to "enter reveal"
	m, _ = send(t, m, enter())
	assert.Contains(t, m.View(), "enter reveal")
	assert.NotContains(t, m.View(), "enter hide")
}
