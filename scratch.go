package main

import (
	"fmt"
	"strings"
)

func isSSMPathSegment(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func ResolvePathOld(raw string) (string, bool) {
	if raw == "" || strings.HasPrefix(raw, "/") {
		return raw, false
	}
	if len(raw) < 2 || raw[1] != ':' {
		return raw, false
	}

	segs := strings.Split(strings.ReplaceAll(raw, `\`, "/"), "/")
	end := len(segs)
	start := end
	for start > 0 && isSSMPathSegment(segs[start-1]) {
		start--
	}
	if end-start >= 2 {
		return "/" + strings.Join(segs[start:end], "/"), true
	}
	return raw, true
}

func main() {
	cases := []string{
		`C:myapp`,
		`C:myapp/dev`,
		`C:\Users\foo\dev\test\foo`,
	}

	for _, c := range cases {
		o1, o2 := ResolvePathOld(c)
		fmt.Printf("MATCH for %q: %q, %t\n", c, o1, o2)
	}
}
