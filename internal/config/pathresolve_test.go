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
		{"bare root missing delimiter", `C:\myapp\dev`, "/myapp/dev", true},
		{"dotted segment breaks the tail so a lone match is not recovered", `C:\Users\x\my.app\dev`, `C:\Users\x\my.app\dev`, true},
		{"capitalized-inside segment stops the scan above the tail", `C:/Program Files/Git/myApp/myapp/dev`, "/myapp/dev", true},
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
		seg  string
		want bool
	}{
		{"myapp", true},
		{"my-app_2", true},
		{"a", true},
		{"", false},
		{"Users", false},
		{"2.54.0", false},
		{"_app", false},
		{"myApp", false},
		{"my.app", false},
		{"my app", false},
		{"c:", false},
	}
	for _, c := range cases {
		if got := isSSMPathSegment(c.seg); got != c.want {
			t.Errorf("isSSMPathSegment(%q) = %v, want %v", c.seg, got, c.want)
		}
	}
}
