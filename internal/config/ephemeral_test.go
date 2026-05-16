package config

import (
	"os"
	"testing"
)

func TestEphemeralConfig(t *testing.T) {
	cfg := EphemeralConfig(ResolveOpts{Env: "prod", Path: "/myapp/prod"})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("ephemeral config invalid: %v", err)
	}
	r, err := Resolve(cfg, ResolveOpts{Env: "prod", Path: "/myapp/prod"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Provider != "aws" || r.Path != "/myapp/prod" {
		t.Fatalf("got provider=%q path=%q, want aws /myapp/prod", r.Provider, r.Path)
	}
}

func TestNormalizeSSMPath(t *testing.T) {
	cases := map[string]string{
		"myapp/prod":  "/myapp/prod",
		"/myapp/prod": "/myapp/prod",
		"":            "",
		`C:\x\myapp`:  `C:\x\myapp`,
		"C:/x/myapp":  "C:/x/myapp",
	}
	for in, want := range cases {
		if got := NormalizeSSMPath(in); got != want {
			t.Fatalf("NormalizeSSMPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEphemeralConfigDefaultsAndRegionFromEnv(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-west-1")
	os.Unsetenv("SKRET_ENV")
	os.Unsetenv("SKRET_PROVIDER")
	cfg := EphemeralConfig(ResolveOpts{Path: "/x/prod"})
	env, ok := cfg.Environments["prod"]
	if !ok {
		t.Fatalf("expected default env %q, got %v", "prod", cfg.Environments)
	}
	if env.Provider != "aws" || env.Region != "eu-west-1" {
		t.Fatalf("got provider=%q region=%q, want aws eu-west-1", env.Provider, env.Region)
	}
}
