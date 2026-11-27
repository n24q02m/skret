// Package redact masks secret values in a byte stream as it is written, for
// `skret run --redact`.
//
// A Writer runs two stages over everything written to it:
//
//  1. Literal masking: every occurrence of a secret value, of each line of a
//     multi-line value, and of the value's common encodings (its %q escape,
//     standard and URL-safe base64 with and without padding, base64 at any
//     byte offset inside a larger encoded string, and URL query/path
//     escaping) is replaced with Marker. The forms come from
//     logging.ValueNeedles, so the log redactor masks the same set.
//     Overlapping occurrences collapse into one Marker.
//  2. Pattern masking: the log redactor's secret patterns (internal/logging)
//     are applied to the result, so token-shaped strings that are not managed
//     values are masked as well.
//
// Both stages are chunk-boundary safe: output never depends on how the input
// was split across Write calls. Stage 1 holds back only bytes that are still a
// prefix of some needle (at most the longest needle minus one byte); stage 2
// holds back the text after the last whitespace byte, because no log pattern
// matches across whitespace. Everything else is passed through immediately,
// so a newline always flushes ordinary output, and Close flushes the rest.
package redact

import (
	"bytes"
	"io"
	"sort"

	"github.com/n24q02m/skret/internal/logging"
)

// Marker replaces every masked span.
const Marker = "[REDACTED]"

// maxHeld bounds the whitespace-free tail stage 2 waits on. A longer run is
// pattern-masked and flushed as is, so a token straddling that point may be
// masked in two parts (or, for the generic base64 pattern, not at all).
const maxHeld = 64 << 10

// patternWhitespace is RE2's \s class. None of the log patterns can match
// these bytes, which is what makes splitting the stream on them lossless.
const patternWhitespace = " \t\n\f\r"

// Set is an immutable collection of byte strings to mask. It is safe to share
// between Writers (for example, one for stdout and one for stderr).
type Set struct {
	byFirst [256][][]byte // needles grouped by first byte, longest first
	maxLen  [256]int      // longest needle per first byte
	count   int
}

// NewSet derives the needles for values with logging.ValueNeedles, the same
// derivation the log redactor uses. Values shorter than minLen bytes are
// skipped entirely, as are derived needles (single lines of a multi-line
// value, encoded fragments) shorter than minLen, so short, common strings do
// not mask unrelated output. A minLen below 1 selects
// logging.MinRedactedValueLen.
func NewSet(values []string, minLen int) *Set {
	if minLen < 1 {
		minLen = logging.MinRedactedValueLen
	}
	s := &Set{}
	seen := make(map[string]struct{})
	for _, v := range values {
		for _, n := range logging.ValueNeedles(v, minLen) {
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			c := n[0]
			s.byFirst[c] = append(s.byFirst[c], []byte(n))
			s.maxLen[c] = max(s.maxLen[c], len(n))
			s.count++
		}
	}
	for c := range s.byFirst {
		bucket := s.byFirst[c]
		sort.SliceStable(bucket, func(i, j int) bool { return len(bucket[i]) > len(bucket[j]) })
	}
	return s
}

// Len reports how many distinct needles the set masks.
func (s *Set) Len() int { return s.count }

// Writer masks secrets in everything written to it before passing it on to
// the destination. It is not safe for concurrent use; give each stream its
// own Writer.
type Writer struct {
	set     *Set
	dst     io.Writer
	pending []byte // stage 1 input not yet decided (a possible needle prefix)
	maskEnd int    // stage 1: pending[:maskEnd] is already known to be masked
	inMask  bool   // stage 1: a Marker was emitted for the current masked run
	held    []byte // stage 2 input after the last whitespace byte
	err     error
}

// NewWriter returns a Writer that writes masked output to dst.
func (s *Set) NewWriter(dst io.Writer) *Writer {
	return &Writer{set: s, dst: dst}
}

// Write masks p and forwards every byte that can already be decided. It
// reports len(p) on success: held-back bytes are owned by the Writer and are
// written by a later Write or by Close.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.pending = append(w.pending, p...)
	w.literal(false)
	if err := w.patterns(false); err != nil {
		w.err = err
		return 0, err
	}
	return len(p), nil
}

// Close flushes everything still held back. It does not close the
// destination. Calling Close again is a no-op.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	w.literal(true)
	w.inMask = false
	if err := w.patterns(true); err != nil {
		w.err = err
		return err
	}
	return nil
}

// literal is stage 1: it moves decided bytes from pending to held, replacing
// every byte covered by a needle occurrence. Unless final, it stops at the
// first position whose remaining bytes are a proper prefix of a needle,
// because the next Write may complete it.
func (w *Writer) literal(final bool) {
	buf := w.pending
	i, run := 0, 0 // run: start of the not-yet-copied unmasked bytes
	for ; i < len(buf); i++ {
		c := buf[i]
		if bucket := w.set.byFirst[c]; len(bucket) > 0 {
			rest := buf[i:]
			if !final && len(rest) < w.set.maxLen[c] && extendsToNeedle(bucket, rest) {
				break
			}
			if end := i + longestMatch(bucket, rest); end > w.maskEnd {
				w.maskEnd = end
			}
		}
		if i < w.maskEnd {
			if !w.inMask {
				w.held = append(w.held, buf[run:i]...)
				w.held = append(w.held, Marker...)
				w.inMask = true
			}
			run = i + 1
			continue
		}
		w.inMask = false
	}
	w.held = append(w.held, buf[run:i]...)
	w.pending = buf[:copy(buf, buf[i:])]
	w.maskEnd = max(w.maskEnd-i, 0)
}

// extendsToNeedle reports whether rest is a proper prefix of a needle.
func extendsToNeedle(bucket [][]byte, rest []byte) bool {
	for _, n := range bucket {
		if len(n) > len(rest) && bytes.HasPrefix(n, rest) {
			return true
		}
	}
	return false
}

// longestMatch returns the length of the longest needle rest starts with.
func longestMatch(bucket [][]byte, rest []byte) int {
	for _, n := range bucket { // sorted longest first
		if bytes.HasPrefix(rest, n) {
			return len(n)
		}
	}
	return 0
}

// patterns is stage 2: it applies the log redaction patterns to held text up
// to and including its last whitespace byte (all of it when final, or when
// the whitespace-free tail exceeds maxHeld) and writes the result.
func (w *Writer) patterns(final bool) error {
	cut := len(w.held)
	if !final && cut <= maxHeld {
		cut = bytes.LastIndexAny(w.held, patternWhitespace) + 1
	}
	if cut == 0 {
		return nil
	}
	if _, err := io.WriteString(w.dst, logging.RedactString(string(w.held[:cut]))); err != nil {
		return err
	}
	w.held = w.held[:copy(w.held, w.held[cut:])]
	return nil
}
