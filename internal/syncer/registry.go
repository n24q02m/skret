package syncer

import (
	"fmt"
	"golang.org/x/text/unicode/norm"
	"net/url"
	"path/filepath"
	"strings"
)

// TargetConfig is a resolved sync destination (from .skret.yaml or flags).
type TargetConfig struct {
	Type        string            // "github" | "cloudflare" | "dotenv"
	Fields      map[string]string // repo / worker / pages / account / file
	Token       string            // resolved from env; never logged
	NoOverwrite bool              // only write keys absent at the target
}

// CanonicalTargetIdentity returns the provider-semantic identity used to
// detect duplicate sync destinations before any source or target API call.
func CanonicalTargetIdentity(tc TargetConfig) (string, error) {
	typ := canonicalTargetPart(tc.Type)
	switch typ {
	case "dotenv":
		file := tc.Fields["file"]
		if file == "" {
			file = ".env"
		}
		abs, err := filepath.Abs(filepath.Clean(file))
		if err != nil {
			return "", fmt.Errorf("dotenv target path %q: %w", file, err)
		}
		return "dotenv|" + canonicalTargetPart(abs), nil
	case "github":
		repo := canonicalTargetPart(tc.Fields["repo"])
		parts := strings.Split(repo, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("github target repo %q must be owner/repo", tc.Fields["repo"])
		}
		baseURL, err := canonicalEndpoint(tc.Fields["base_url"], "https://api.github.com")
		if err != nil {
			return "", fmt.Errorf("github target base_url: %w", err)
		}
		return "github|" + baseURL + "|" + repo, nil
	case "cloudflare":
		account := canonicalTargetPart(tc.Fields["account"])
		worker := canonicalTargetPart(tc.Fields["worker"])
		pages := canonicalTargetPart(tc.Fields["pages"])
		baseURL, err := canonicalEndpoint(tc.Fields["base_url"], "https://api.cloudflare.com/client/v4")
		if err != nil {
			return "", fmt.Errorf("cloudflare target base_url: %w", err)
		}
		if account == "" {
			return "", fmt.Errorf("cloudflare target account is required")
		}
		if (worker == "") == (pages == "") {
			return "", fmt.Errorf("cloudflare target must declare exactly one worker or pages")
		}
		if worker != "" {
			return "cloudflare|" + baseURL + "|" + account + "|worker|" + worker, nil
		}
		return "cloudflare|" + baseURL + "|" + account + "|pages|" + pages, nil
	default:
		return "", fmt.Errorf("sync target type %q is not canonicalizable", tc.Type)
	}
}

// ValidateTargetIdentities rejects ambiguous target sets before constructing
// syncers or loading the authoritative source provider.
func ValidateTargetIdentities(targets []TargetConfig) error {
	seen := make(map[string]int, len(targets))
	for i, target := range targets {
		identity, err := CanonicalTargetIdentity(target)
		if err != nil {
			return fmt.Errorf("sync target %d: %w", i, err)
		}
		if previous, ok := seen[identity]; ok {
			return fmt.Errorf("sync target identity collision: targets %d and %d resolve to %q", previous, i, identity)
		}
		seen[identity] = i
	}
	return nil
}

func canonicalTargetPart(value string) string {
	return strings.ToLower(norm.NFC.String(strings.TrimSpace(value)))
}

func canonicalEndpoint(value, defaultURL string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		raw = defaultURL
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(canonicalTargetPart(raw), "/"), nil
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(norm.NFC.String(parsed.Host))
	parsed.Path = strings.TrimRight(norm.NFC.String(parsed.Path), "/")
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

// Factory builds a Syncer from a resolved TargetConfig.
type Factory func(TargetConfig) (Syncer, error)

var registry = map[string]Factory{}

// Register wires a target type to its factory. Called from each target's init().
func Register(typ string, f Factory) { registry[typ] = f }

// Build constructs one Syncer per TargetConfig, erroring clearly on unknown
// types or missing required fields.
func Build(targets []TargetConfig) ([]Syncer, error) {
	out := make([]Syncer, 0, len(targets))
	for i, tc := range targets {
		f, ok := registry[tc.Type]
		if !ok {
			return nil, fmt.Errorf("sync target %d: unknown type %q", i, tc.Type)
		}
		s, err := f(tc)
		if err != nil {
			return nil, fmt.Errorf("sync target %d (%s): %w", i, tc.Type, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func field(tc TargetConfig, k string) string {
	return tc.Fields[k]
}
