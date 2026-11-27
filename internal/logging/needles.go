package logging

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

// ValueNeedles returns every literal form of the secret value v that output
// may carry, so each redactor masks the same set:
//
//   - v itself, its %q-escaped form (a value quoted into an error message or
//     a JSON string), and for a multi-line value with LF line endings the
//     same value with CRLF line endings;
//   - for each of those, the standard and URL-safe base64 encodings (with and
//     without padding), the base64 characters that depend only on the value
//     when it is encoded inside a larger string (such as a basic auth
//     header), and the URL query and path escapes;
//   - for a multi-line value, each line on its own, without a trailing CR.
//
// It returns nil when v is shorter than minLen bytes, and drops any derived
// form shorter than minLen, so short common strings do not mask unrelated
// text. The raw value comes first; the list has no duplicates.
func ValueNeedles(v string, minLen int) []string {
	if v == "" || len(v) < minLen {
		return nil
	}
	forms := []string{v}
	if q := strconv.Quote(v); q[1:len(q)-1] != v {
		forms = append(forms, q[1:len(q)-1])
	}
	multiline := strings.Contains(v, "\n")
	if multiline && !strings.Contains(v, "\r\n") {
		forms = append(forms, strings.ReplaceAll(v, "\n", "\r\n"))
	}

	candidates := make([]string, 0, 13*len(forms))
	for _, f := range forms {
		b := []byte(f)
		candidates = append(
			candidates,
			f,
			base64.StdEncoding.EncodeToString(b),
			base64.URLEncoding.EncodeToString(b),
			base64.RawStdEncoding.EncodeToString(b),
			base64.RawURLEncoding.EncodeToString(b),
			url.QueryEscape(f),
			url.PathEscape(f),
		)
		for offset := range 3 {
			candidates = append(candidates,
				embeddedBase64(base64.RawStdEncoding, b, offset),
				embeddedBase64(base64.RawURLEncoding, b, offset))
		}
	}
	if multiline {
		for _, line := range strings.Split(v, "\n") {
			candidates = append(candidates, strings.TrimSuffix(line, "\r"))
		}
	}

	out := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, n := range candidates {
		if n == "" || len(n) < minLen {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// embeddedBase64 returns the base64 characters that depend only on v when v
// starts offset bytes into a larger encoded string and more bytes may follow:
// the characters mixing in the preceding or following bytes are dropped.
func embeddedBase64(enc *base64.Encoding, v []byte, offset int) string {
	full := enc.EncodeToString(append(make([]byte, offset), v...))
	start := (8*offset + 5) / 6        // first char with no prefix bits
	end := (8 * (offset + len(v))) / 6 // chars wholly inside v end here
	if start >= end {                  // value too short for this offset
		return ""
	}
	return full[start:end]
}
