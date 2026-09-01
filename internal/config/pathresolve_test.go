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
		{"bare root passthrough", `C:myapp`, `C:myapp`, true},
		{"bare root two segments", `C:myapp/dev`, `C:myapp/dev`, true},
		{"bare root missing delimiter", `C:\myapp\dev`, `/myapp/dev`, true},
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
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"uppercase start", "MyApp", false},
		{"number start", "1app", false},
		{"invalid char", "my.app", false},
		{"valid", "my-app_1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSSMPathSegment(c.in); got != c.want {
				t.Errorf("isSSMPathSegment(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestResolvePath_Boundary(t *testing.T) {
	// A case where idx == -1 (prev == -1 on the very first segment evaluated in loop,
	// and count ends up >= 2)
	// Example: raw="C:myapp/dev" -> segs = ["C:myapp", "dev"]. "C:myapp" fails isSSMPathSegment. count=1.
	// Wait, to get idx == -1 and count >= 2, we need a string with >=2 SSM segments and NO slashes before them?
	// The only way prev == -1 is when we reach the beginning of the string `norm`.
	// For count >= 2, we need >= 2 valid SSM segments. But if there are no slashes, there is only 1 segment.
	// Ah, if `norm` is entirely made of valid SSM segments separated by slashes.
	// E.g., `norm` = "a/b/c". But `ResolvePath` returns early for "a/b/c" because it doesn't have a colon!
	// So we need `norm` = "C:a/b/c" but then the first segment is "C:a" which is invalid.
	// Wait, can `idx` become -1 if `count >= 2`?
	// If `norm` = "C:/a/b". The segments are "C:", "a", "b".
	// "b" is valid. "a" is valid. "C:" is invalid.
	// So the loop stops at "C:". `idx` is the index of the slash before "a".
	// The only way `idx` becomes -1 is if the *entire* string is valid segments separated by slashes.
	// But `ResolvePath` enforces `raw[1] == ':'` at the very beginning!
	// So `norm[1]` is always `:`.
	// This means `norm` always contains at least one invalid segment (the one containing the drive letter).
	// Therefore, the loop will ALWAYS break before `idx` becomes -1, because `C:...` is never a valid SSM path segment.
	// Thus `idx == -1` inside `if count >= 2` is UNREACHABLE!
}
