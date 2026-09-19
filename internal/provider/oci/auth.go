package oci

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oracle/oci-go-sdk/v65/common"
	ociauth "github.com/oracle/oci-go-sdk/v65/common/auth"
)

// Environment variables honored by the auth resolver, mirroring the OCI CLI:
// instance-principal mode is selected with OCI_CLI_AUTH, API-key material can
// come from OCI_CLI_* overrides, and OCI_CLI_CONFIG_FILE / OCI_CLI_PROFILE
// redirect the config-file fallback.
const (
	EnvAuth        = "OCI_CLI_AUTH"
	EnvUser        = "OCI_CLI_USER"
	EnvTenancy     = "OCI_CLI_TENANCY"
	EnvFingerprint = "OCI_CLI_FINGERPRINT"
	EnvKeyFile     = "OCI_CLI_KEY_FILE"
	EnvPassPhrase  = "OCI_CLI_PASS_PHRASE"
	EnvRegion      = "OCI_CLI_REGION"
	EnvProfile     = "OCI_CLI_PROFILE"
	EnvConfigFile  = "OCI_CLI_CONFIG_FILE"
)

// InstancePrincipalAuth is the OCI_CLI_AUTH value that selects instance
// principal authentication (vault access via the compute instance's
// identity, no config file).
const InstancePrincipalAuth = "instance_principal"

// defaultConfigFileName is the OCI CLI config file path under $HOME.
const defaultConfigFileName = ".oci/config"

// defaultProfile is the OCI CLI config profile used when none is set.
const defaultProfile = "DEFAULT"

// envLookup abstracts os.LookupEnv for deterministic tests.
type envLookup func(string) (string, bool)

// homeDirFunc abstracts os.UserHomeDir for deterministic tests.
type homeDirFunc func() (string, error)

// authDeps holds the externals of the auth resolver, injectable for tests.
type authDeps struct {
	lookupEnv            envLookup
	homeDir              homeDirFunc
	newInstancePrincipal func() (common.ConfigurationProvider, error)
}

func defaultAuthDeps() authDeps {
	return authDeps{
		lookupEnv: func(key string) (string, bool) {
			v, ok := os.LookupEnv(key)
			return v, ok
		},
		homeDir:              os.UserHomeDir,
		newInstancePrincipal: ociauth.InstancePrincipalConfigurationProvider,
	}
}

// resolveConfigurationProvider builds the OCI SDK ConfigurationProvider,
// mirroring the OCI CLI's precedence:
//
//  1. OCI_CLI_AUTH=instance_principal — instance principal auth.
//  2. OCI_CLI_USER/TENANCY/FINGERPRINT/KEY_FILE overrides — API key from
//     the environment, composed over the config file (env wins per field).
//  3. ~/.oci/config (or OCI_CLI_CONFIG_FILE) with profile
//     OCI_CLI_PROFILE > the environment's `profile` > DEFAULT.
//
// An error is returned when no source can authenticate.
func resolveConfigurationProvider(deps authDeps, profile string) (common.ConfigurationProvider, error) {
	if mode, _ := deps.lookupEnv(EnvAuth); mode == InstancePrincipalAuth {
		p, err := deps.newInstancePrincipal()
		if err != nil {
			return nil, fmt.Errorf("oci: instance principal auth: %w", err)
		}
		return p, nil
	}

	envProvider, envOK, envErr := envConfigurationProvider(deps)
	if envErr != nil {
		return nil, envErr
	}
	fileProvider, fileOK := configFileProvider(deps, profile)

	switch {
	case envOK && fileOK:
		composed, err := common.ComposingConfigurationProvider([]common.ConfigurationProvider{envProvider, fileProvider})
		if err != nil {
			return nil, fmt.Errorf("oci: compose auth providers: %w", err)
		}
		return composed, nil
	case envOK:
		return envProvider, nil
	case fileOK:
		return fileProvider, nil
	default:
		return nil, errors.New("oci: no authentication available: create ~/.oci/config ('oci setup config'), set the OCI_CLI_* environment variables, or set OCI_CLI_AUTH=instance_principal")
	}
}

// envConfigurationProvider builds an API-key provider from OCI_CLI_*
// environment variables. ok is false when no credential material is set.
func envConfigurationProvider(deps authDeps) (p common.ConfigurationProvider, ok bool, err error) {
	user := envString(deps, EnvUser)
	tenancy := envString(deps, EnvTenancy)
	fingerprint := envString(deps, EnvFingerprint)
	keyFile := envString(deps, EnvKeyFile)
	if user == "" || tenancy == "" || fingerprint == "" || keyFile == "" {
		return nil, false, nil
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, false, fmt.Errorf("oci: read %s %q: %w", EnvKeyFile, keyFile, err)
	}
	var pass *string
	if phrase := envString(deps, EnvPassPhrase); phrase != "" {
		pass = &phrase
	}
	return common.NewRawConfigurationProvider(tenancy, user, envString(deps, EnvRegion), fingerprint, string(key), pass), true, nil
}

// configFileProvider builds the config-file provider when the OCI config
// file exists; ok is false otherwise. A missing home dir or file is an
// expected absence, not an error.
func configFileProvider(deps authDeps, profile string) (p common.ConfigurationProvider, ok bool) {
	path := envString(deps, EnvConfigFile)
	if path == "" {
		home, herr := deps.homeDir()
		if herr != nil || home == "" {
			return nil, false //nolint:nilerr // absent home dir = source unavailable
		}
		path = filepath.Join(home, defaultConfigFileName)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		return nil, false //nolint:nilerr // absent config file = source unavailable
	}
	prof := envString(deps, EnvProfile)
	if prof == "" {
		prof = profile
	}
	if prof == "" {
		prof = defaultProfile
	}
	return common.CustomProfileConfigProvider(path, prof), true
}

func envString(deps authDeps, key string) string {
	v, _ := deps.lookupEnv(key)
	return v
}
