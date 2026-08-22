package config

import "testing"

func TestResolvePath(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantPath    string
		wantMangled bool
	}{
		{"empty passthrough", "", "", false},
		{"already absolute passthrough", "/myapp/dev", "/myapp/dev", false},
		{"bare relative passthrough (leading slash added later by NormalizeSSMPath)", "myapp/dev", "myapp/dev", false},
		{"msys-mangled forward-slash form recovered", "C:/Users/n24q02m-wpc/scoop/apps/git/2.54.0/myapp/dev", "/myapp/dev", true},
		{"msys-mangled backslash form recovered", `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev`, "/myapp/dev", true},
		{"genuine windows path with no SSM-like tail passthrough+warn", `C:\Users\bob\Documents`, `C:\Users\bob\Documents`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, mangled := ResolvePath(c.raw)
			if got != c.wantPath || mangled != c.wantMangled {
				t.Fatalf("ResolvePath(%q) = (%q,%v), want (%q,%v)", c.raw, got, mangled, c.wantPath, c.wantMangled)
			}
		})
	}
}

func TestIsSSMPathSegment(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"myapp", true},
		{"prod", true},
		{"dev", true},
		{"", false}, // coverage for s == ""
		{"MyApp", false}, // coverage for s[0] < 'a'
		{"{app}", false}, // coverage for s[0] > 'z'
		{"a@b", false}, // coverage for inner loop fail
		{"myapp-prod_2", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := isSSMPathSegment(c.in); got != c.want {
				t.Fatalf("isSSMPathSegment(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestResolvePath_Coverage(t *testing.T) {
	// The original code uses:
	// segs := strings.Split(strings.ReplaceAll(raw, `\`, "/"), "/")
	// If `raw` has no slashes, e.g. `C:abc`, it's 1 segment. `isSSMPathSegment` might be true,
	// but it would only be 1 segment, so segments >= 2 would fail.

	// Let's ensure the `if idx == -1` path is fully covered and we can hit `break` when idx == -1.
	// In the new logic, to hit `if idx == -1 { break }` while `segments` can still be >= 2,
	// we need `raw` to be something like `C:myapp/dev` (assuming `C:myapp` would match `isSSMPathSegment` - wait, it doesn't because `:` is invalid).

	// If it's `C:dev`, `isSSMPathSegment("C:dev")` is false because of `:`.

	// Wait, is there ANY case where `isSSMPathSegment(seg)` is true for a segment that came after `idx == -1`?
	// `idx == -1` means it's the very first segment in `norm`.
	// Since `len(raw) >= 2` and `raw[1] == ':'`, the first segment in `norm` will always contain `:`.
	// e.g. `C:myapp` or `C:`
	// `isSSMPathSegment` checks `c < 'a' || c > 'z'` etc., and `:` is not allowed.
	// So `isSSMPathSegment` will ALWAYS be false for the very first segment (the one with the drive letter).

	// Therefore, the loop will ALWAYS break at `if !isSSMPathSegment(seg) { break }` when `idx == -1`.
	// The `if idx == -1 { break }` right after `segments++` is ACTUALLY UNREACHABLE because `!isSSMPathSegment(seg)` will always trigger first!
}
