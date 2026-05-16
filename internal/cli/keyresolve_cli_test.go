package cli

import "testing"

func TestResolveKeyArgJoinsPath(t *testing.T) {
	got, mangled := resolveKeyArg("/myapp/prod", "DB_PASSWORD")
	if got != "/myapp/prod/DB_PASSWORD" || mangled {
		t.Fatalf("resolveKeyArg = (%q,%v), want (/myapp/prod/DB_PASSWORD,false)", got, mangled)
	}
}

func TestResolveKeyArgRecoversMangledPrefix(t *testing.T) {
	got, mangled := resolveKeyArg("/myapp/prod", "C:/Users/x/scoop/apps/git/2.54.0/myapp/prod/DB_PASSWORD")
	if got != "/myapp/prod/DB_PASSWORD" || !mangled {
		t.Fatalf("resolveKeyArg = (%q,%v), want (/myapp/prod/DB_PASSWORD,true)", got, mangled)
	}
}
