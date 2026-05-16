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
