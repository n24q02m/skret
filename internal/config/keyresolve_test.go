package config

import "testing"

func TestResolveKey(t *testing.T) {
	const rp = "/myapp/prod"
	cases := []struct {
		name      string
		path, key string
		want      string
		mangled   bool
	}{
		{"bare leaf joins path", rp, "DB_PASSWORD", "/myapp/prod/DB_PASSWORD", false},
		{"already fully-qualified passthrough", rp, "/myapp/prod/DB_PASSWORD", "/myapp/prod/DB_PASSWORD", false},
		{"path with trailing slash", "/myapp/prod/", "DB_PASSWORD", "/myapp/prod/DB_PASSWORD", false},
		{"msys-mangled prefix recovered", rp, "C:/Users/x/scoop/apps/git/2.54.0/myapp/prod/DB_PASSWORD", "/myapp/prod/DB_PASSWORD", true},
		{"genuine absolute outside path passthrough", rp, "/other/ns/KEY", "/other/ns/KEY", false},
		{"empty resolved path returns key", "", "DB_PASSWORD", "DB_PASSWORD", false},
		{"empty key returns key", rp, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, mangled := ResolveKey(c.path, c.key)
			if got != c.want || mangled != c.mangled {
				t.Fatalf("ResolveKey(%q,%q) = (%q,%v), want (%q,%v)", c.path, c.key, got, mangled, c.want, c.mangled)
			}
		})
	}
}
