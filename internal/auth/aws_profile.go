package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/ini.v1"
)

// AWSProfileFlow enumerates and selects profiles from ~/.aws/config.
type AWSProfileFlow struct{}

// NewAWSProfileFlow creates a profile enumeration flow.
func NewAWSProfileFlow() *AWSProfileFlow { return &AWSProfileFlow{} }

// awsConfigPath returns the standard ~/.aws/config path.
func awsConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aws", "config")
}

// List returns the sorted set of AWS profile names declared in ~/.aws/config.
// The section [default] becomes "default"; [profile foo] becomes "foo".
func (f *AWSProfileFlow) List() ([]string, error) {
	path := awsConfigPath()
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("aws profile: %w", err)
	}
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("aws profile: parse %s: %w", path, err)
	}
	var names []string
	for _, s := range cfg.Sections() {
		name := s.Name()
		switch {
		case name == "default":
			names = append(names, "default")
		case strings.HasPrefix(name, "profile "):
			names = append(names, strings.TrimPrefix(name, "profile "))
		}
	}
	sort.Strings(names)
	return names, nil
}

// Login selects opts["profile"] (defaults to "default") from ~/.aws/config
// and returns a Credential that records the profile name and region.
func (f *AWSProfileFlow) Login(_ context.Context, opts map[string]string) (*Credential, error) {
	profile := opts["profile"]
	if profile == "" {
		profile = "default"
	}
	names, err := f.List()
	if err != nil {
		return nil, err
	}
	found := false
	for _, n := range names {
		if n == profile {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("aws profile: %q not found in ~/.aws/config (available: %s)", profile, strings.Join(names, ", "))
	}
	cfg, err := ini.Load(awsConfigPath())
	if err != nil {
		return nil, fmt.Errorf("aws profile: reload: %w", err)
	}
	sectionName := "profile " + profile
	if profile == "default" {
		sectionName = "default"
	}
	section := cfg.Section(sectionName)
	region := section.Key("region").String()
	return &Credential{
		Method: "profile",
		Metadata: map[string]string{
			"profile": profile,
			"region":  region,
		},
	}, nil
}
