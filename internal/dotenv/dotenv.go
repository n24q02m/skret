// Package dotenv is the single, symmetric codec for the .env line format used by
// skret's env dump, dotenv sync, and dotenv import. Encode and Decode are exact
// inverses for any value, so a secret round-trips byte-for-byte through
// sync -> import and env -> import. Values are never shell-expanded.
package dotenv

import "strings"

// needsQuoting reports whether a value cannot be written bare (unquoted) and
// read back unchanged. Empty values and any value containing whitespace, a
// quote/comment/assignment character, '$' (shell-expansion hazard for consumers),
// or a backslash must be quoted.
func needsQuoting(v string) bool {
	if v == "" {
		return true
	}
	return strings.ContainsAny(v, " \t\r\n\"'`#=$\\")
}

// Encode renders one "KEY=value" line (without trailing newline). Safe values are
// emitted bare; otherwise the value is double-quoted with C-style escapes that
// Decode (and escape-aware dotenv readers) reverse exactly.
func Encode(key, value string) string {
	if !needsQuoting(value) {
		return key + "=" + value
	}
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return key + "=" + b.String()
}

// Decode parses one dotenv line into key/value. It returns ok=false for blank
// lines and comments. A leading "export " is stripped. The key is trimmed; the
// value is taken verbatim (bare), or unescaped (double-quoted), or stripped only
// (single-quoted). Whitespace inside a bare value is preserved so equality/diff
// is byte-faithful.
func Decode(line string) (key, value string, ok bool) {
	// Trim only leading whitespace (indentation); a trailing space may be a
	// significant part of a bare value and must be preserved.
	s := strings.TrimLeft(line, " \t")
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false
	}
	s = strings.TrimPrefix(s, "export ")

	k, v, found := strings.Cut(s, "=")
	if !found {
		return "", "", false
	}
	k = strings.TrimSpace(k)
	if k == "" {
		return "", "", false
	}
	return k, decodeValue(v), true
}

func decodeValue(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return unescape(v[1 : len(v)-1])
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		// Single quotes are literal: strip only, no escape processing.
		return v[1 : len(v)-1]
	}
	// Bare value: verbatim. The line reader has already removed the trailing
	// newline/CR, and skret quotes any value with significant whitespace, so we
	// must NOT trim here (trimming silently corrupts/equates distinct values).
	return v
}

// unescape reverses the escapes written by Encode for a double-quoted value.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i == len(s)-1 {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			// Unknown escape: keep both bytes so unexpected input is not silently lost.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
