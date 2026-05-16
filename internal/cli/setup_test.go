package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetupNonInteractiveWritesConfigAndAuths(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	var authProvider, authMethod string
	origHook := setupAuthHook
	defer func() { setupAuthHook = origHook }()
	setupAuthHook = func(provider, method string, _ map[string]string) error {
		authProvider, authMethod = provider, method
		return nil
	}

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"setup", "--provider=aws", "--path=/myapp/prod", "--region=us-east-1", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".skret.yaml")); err != nil {
		t.Fatalf(".skret.yaml not written: %v", err)
	}
	if authProvider != "aws" || authMethod != "" {
		t.Fatalf("auth hook got provider=%q method=%q, want aws/\"\"", authProvider, authMethod)
	}
}

func TestSetupPassesOptsToAuth(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	var gotOpts map[string]string
	origHook := setupAuthHook
	defer func() { setupAuthHook = origHook }()
	setupAuthHook = func(_, _ string, o map[string]string) error { gotOpts = o; return nil }

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"setup", "--provider=aws", "--path=/myapp/prod",
		"--method=sso", "--opt", "account_id=111122223333", "--opt", "role_name=R", "--yes",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if gotOpts["account_id"] != "111122223333" || gotOpts["role_name"] != "R" {
		t.Fatalf("opts not forwarded: %+v", gotOpts)
	}
}

func TestSetupLocalProviderSkipsAuth(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	called := false
	origHook := setupAuthHook
	defer func() { setupAuthHook = origHook }()
	setupAuthHook = func(string, string, map[string]string) error { called = true; return nil }

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"setup", "--provider=local", "--file=.secrets.dev.yaml", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup local: %v", err)
	}
	if called {
		t.Fatal("local provider must not invoke auth hook")
	}
}
