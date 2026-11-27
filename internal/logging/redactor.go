package logging

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// MinRedactedValueLen is the shortest known value a Redactor replaces.
// Shorter values collide with ordinary words and numbers in diagnostic
// text, so redacting them would garble messages without protecting a
// realistic secret.
const MinRedactedValueLen = 4

// RedactString applies the secret-shape patterns used by RedactingHandler
// to s and returns the result.
func RedactString(s string) string { return redactString(s) }

// Redactor scrubs text of a growing set of known secret values (for
// example every value a long-running server has loaded) and then of the
// secret-shape patterns. It is safe for concurrent use. A nil Redactor
// applies the patterns only.
type Redactor struct {
	mu       sync.RWMutex
	values   map[string]struct{}
	replacer *strings.Replacer
}

// NewRedactor returns an empty Redactor.
func NewRedactor() *Redactor {
	return &Redactor{values: map[string]struct{}{}}
}

// Add registers values to redact. Values shorter than MinRedactedValueLen
// are ignored. The %q-escaped form of a value is registered as well, so a
// value quoted into an error message is caught too.
func (r *Redactor) Add(values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for _, v := range values {
		if len(v) < MinRedactedValueLen {
			continue
		}
		forms := []string{v}
		if q := strconv.Quote(v); q[1:len(q)-1] != v {
			forms = append(forms, q[1:len(q)-1])
		}
		for _, f := range forms {
			if _, ok := r.values[f]; !ok {
				r.values[f] = struct{}{}
				changed = true
			}
		}
	}
	if changed {
		r.replacer = nil
	}
}

// Redact returns s with every known value replaced by [REDACTED] (longest
// value first, so a value that prefixes another cannot leave a tail
// behind), then with the secret-shape patterns applied.
func (r *Redactor) Redact(s string) string {
	if r == nil {
		return redactString(s)
	}
	if rep := r.currentReplacer(); rep != nil {
		s = rep.Replace(s)
	}
	return redactString(s)
}

// currentReplacer returns the replacer for the current value set, building
// it after a change. It returns nil while no value is registered.
func (r *Redactor) currentReplacer() *strings.Replacer {
	r.mu.RLock()
	rep, n := r.replacer, len(r.values)
	r.mu.RUnlock()
	if rep != nil || n == 0 {
		return rep
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replacer == nil {
		vals := make([]string, 0, len(r.values))
		for v := range r.values {
			vals = append(vals, v)
		}
		// strings.Replacer tries the old strings in argument order at each
		// position, so the longest value must come first.
		slices.SortFunc(vals, func(a, b string) int {
			return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b))
		})
		pairs := make([]string, 0, 2*len(vals))
		for _, v := range vals {
			pairs = append(pairs, v, redacted)
		}
		r.replacer = strings.NewReplacer(pairs...)
	}
	return r.replacer
}

// ValueRedactingHandler wraps a slog.Handler and passes the message, every
// attribute value and every group name of each record through a Redactor
// before the inner handler sees it. Values added to the Redactor later are
// scrubbed from then on. Non-string values that render as text (errors,
// Stringers, arbitrary structs) are rendered and scrubbed as strings, so a
// known value cannot slip through formatting.
type ValueRedactingHandler struct {
	inner slog.Handler
	r     *Redactor
}

// NewValueRedactingHandler creates a handler that scrubs the values known
// to r (and the secret-shape patterns) from every record.
func NewValueRedactingHandler(inner slog.Handler, r *Redactor) *ValueRedactingHandler {
	return &ValueRedactingHandler{inner: inner, r: r}
}

func (h *ValueRedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *ValueRedactingHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.Redact(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h *ValueRedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = h.attr(a)
	}
	return &ValueRedactingHandler{inner: h.inner.WithAttrs(scrubbed), r: h.r}
}

func (h *ValueRedactingHandler) WithGroup(name string) slog.Handler {
	return &ValueRedactingHandler{inner: h.inner.WithGroup(h.r.Redact(name)), r: h.r}
}

// attr scrubs one attribute, recursing into groups.
func (h *ValueRedactingHandler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.r.Redact(v.String()))
	case slog.KindGroup:
		group := v.Group()
		scrubbed := make([]slog.Attr, len(group))
		for i, g := range group {
			scrubbed[i] = h.attr(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(scrubbed...)}
	case slog.KindAny:
		return slog.String(a.Key, h.r.Redact(fmt.Sprintf("%+v", v.Any())))
	}
	return slog.Attr{Key: a.Key, Value: v}
}

// Mask hides most of s for display: the first and last 4 runes with an
// ellipsis between, or "***" when s is 8 runes or shorter. It slices on
// rune boundaries so multi-byte text is never split into invalid UTF-8.
func Mask(s string) string {
	r := []rune(s)
	if len(r) > 8 {
		return string(r[:4]) + "..." + string(r[len(r)-4:])
	}
	return "***"
}
