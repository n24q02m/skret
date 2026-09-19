package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/config"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Doctor check statuses.
const (
	doctorPass = "pass"
	doctorWarn = "warn"
	doctorFail = "fail"
)

// authExpiryWarnWindow is how far ahead of expiry a credential must be to
// avoid a nearing-expiry warning from `skret doctor`.
const authExpiryWarnWindow = 24 * time.Hour

// DoctorCheck is one health-check result. The zero Remediation is omitted
// from JSON; a non-empty one reuses the errjson remediation pattern (a
// copy-pasteable fix hint produced via skret.WithRemediation semantics).
type DoctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "pass" | "warn" | "fail"
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`

	// failClass records which spec-class exit code this check contributes
	// when Status == "fail" (config=2, provider=3, auth=4, network=7).
	failClass int
}

// doctorReport is the --format json payload: {"checks":[...]}.
type doctorReport struct {
	Checks []DoctorCheck `json:"checks"`
}

// doctorLivenessProbe verifies real AWS reachability via the same credential
// resolution real operations use (skaws.Probe). Kept separate from
// awsLivenessProbe so auth-status tests and doctor tests never fight over
// one package-level override variable.
var doctorLivenessProbe = skaws.Probe

// doctorStoreFactory builds the credential store doctor reads. A variable so
// tests point doctor at a scratch store instead of the operator's real one.
var doctorStoreFactory = auth.NewStore

// doctorDeps holds the externals doctor talks to, injectable for tests.
type doctorDeps struct {
	liveness func(ctx context.Context) error
	store    *auth.Store
	now      func() time.Time
	goos     string
}

func newDoctorCmd(opts *GlobalOpts) *cobra.Command {
	var (
		format  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose config validity, provider reachability, auth, and local file health",
		Long: `Runs read-only health checks and reports one result per check.

Checks: config parse/schema, per-environment provider reachability,
stored credential state, local secrets-file permissions, and local
encryption intent. A failing check exits with its spec class (config=2,
provider=3, auth=4, network=7); warnings never fail the command.

Per-check status lines go to stderr; the summary (table format) or the
JSON report goes to stdout.`,
		Example: `  skret doctor
  skret doctor --env prod
  skret doctor --format json
  skret doctor --timeout=3s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd, opts, format, timeout)
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "reachability probe timeout per provider")
	return cmd
}

// runDoctor builds the checks, renders them, and returns the class error for
// the first failing class (fixed precedence: config, provider, auth, network)
// so main() exits with the spec §7.1 code for that class.
func runDoctor(cmd *cobra.Command, opts *GlobalOpts, format string, timeout time.Duration) error {
	deps := doctorDeps{
		liveness: doctorLivenessProbe,
		store:    doctorStoreFactory(),
		now:      time.Now,
		goos:     runtime.GOOS,
	}
	checks := runDoctorChecks(deps, opts, timeout)

	switch format {
	case "json":
		data, err := json.MarshalIndent(doctorReport{Checks: checks}, "", "  ")
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "doctor: marshal report failed", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	default:
		for _, c := range checks {
			fmt.Fprintf(cmd.ErrOrStderr(), "%-4s %s: %s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
			if c.Remediation != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "     fix: %s\n", c.Remediation)
			}
		}
		pass, warn, fail := doctorTally(checks)
		fmt.Fprintf(cmd.OutOrStdout(), "doctor: %d passed, %d warning(s), %d failed\n", pass, warn, fail)
	}

	code, failed, names := doctorFailure(checks)
	if !failed {
		return nil
	}
	var err error = skret.NewError(code, fmt.Sprintf("doctor: %d check(s) failed (%s)", len(names), strings.Join(names, ", ")), nil)
	err = skret.WithRemediation(err, doctorFirstRemediation(checks))
	return err
}

// runDoctorChecks runs every check and returns results in a deterministic
// order: config first, then one block per environment sorted by name.
func runDoctorChecks(deps doctorDeps, opts *GlobalOpts, timeout time.Duration) []DoctorCheck {
	cfgPath, err := resolveConfigFile(opts)
	if err != nil {
		return []DoctorCheck{{
			Name: "config", Status: doctorFail,
			Detail:      err.Error(),
			Remediation: configNotFoundMsg,
			failClass:   skret.ExitConfigError,
		}}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return []DoctorCheck{{
			Name: "config", Status: doctorFail,
			Detail:      err.Error(),
			Remediation: "fix .skret.yaml (or re-run 'skret init')",
			failClass:   skret.ExitConfigError,
		}}
	}
	if len(cfg.Environments) == 0 {
		return []DoctorCheck{{
			Name: "config", Status: doctorFail,
			Detail:      "no environments declared",
			Remediation: "run 'skret init' to declare one",
			failClass:   skret.ExitConfigError,
		}}
	}

	envNames := make([]string, 0, len(cfg.Environments))
	for name := range cfg.Environments {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)
	if opts.Env != "" {
		if _, ok := cfg.Environments[opts.Env]; !ok {
			return []DoctorCheck{{
				Name: "config", Status: doctorFail,
				Detail:    fmt.Sprintf("env %q not declared (available: %s)", opts.Env, strings.Join(envNames, ", ")),
				failClass: skret.ExitConfigError,
			}}
		}
		envNames = []string{opts.Env}
	}

	// Loose per-environment maps for fields the typed schema may not know
	// yet (e.g. the local encryption lane's `encrypted`). A file that passed
	// the typed Load re-parses here or yields nil; lookups on nil are safe.
	rawEnvs := loadRawEnvironments(cfgPath)

	var checks []DoctorCheck
	probeCache := map[string]error{} // provider -> liveness result
	authChecked := false             // aws credential check runs once per report
	for _, envName := range envNames {
		resolveOpts := config.ResolveOpts{
			Env:      envName,
			Provider: opts.Provider,
			Path:     opts.Path,
			Region:   opts.Region,
			Profile:  opts.Profile,
			File:     opts.File,
		}
		resolved, rerr := config.Resolve(cfg, resolveOpts)
		if rerr != nil {
			checks = append(checks, DoctorCheck{
				Name:        "config[" + envName + "]",
				Status:      doctorFail,
				Detail:      rerr.Error(),
				Remediation: "fix this environment in .skret.yaml (or re-run 'skret init')",
				failClass:   skret.ExitConfigError,
			})
			continue
		}

		switch resolved.Provider {
		case "local":
			checks = append(checks, doctorLocalChecks(deps, rawEnvs[envName], envName, resolved)...)
		case "aws":
			checks = append(checks, doctorAWSReachCheck(deps, envName, timeout, probeCache)...)
			if !authChecked {
				checks = append(checks, doctorAuthCheck(deps))
				authChecked = true
			}
		default:
			checks = append(checks, DoctorCheck{
				Name:        "provider[" + envName + "]",
				Status:      doctorFail,
				Detail:      fmt.Sprintf("unknown provider %q", resolved.Provider),
				Remediation: "supported providers: local, aws",
				failClass:   skret.ExitConfigError,
			})
		}
	}
	return checks
}

// doctorLocalChecks runs the local-provider checks for one environment:
// file loads, permissions, and encryption intent. A missing secrets file is
// only a warning — the provider treats it as an empty store and creates the
// file on first write.
func doctorLocalChecks(deps doctorDeps, rawEnv map[string]any, envName string, resolved *config.ResolvedConfig) []DoctorCheck {
	absFile, err := filepath.Abs(resolved.File)
	if err != nil {
		return []DoctorCheck{{
			Name: "provider[" + envName + "]", Status: doctorFail,
			Detail: fmt.Sprintf("resolve file path %q: %v", resolved.File, err), failClass: skret.ExitProviderError,
		}}
	}

	p, perr := local.New(resolved)
	if perr != nil {
		return []DoctorCheck{{
			Name: "provider[" + envName + "]", Status: doctorFail,
			Detail:      fmt.Sprintf("file %q unreadable: %v", absFile, perr),
			Remediation: "fix or remove the secrets file (corrupt YAML is the usual cause)",
			failClass:   skret.ExitProviderError,
		}}
	}
	secrets, lerr := p.List(context.Background(), resolved.Path)
	_ = p.Close()
	if lerr != nil {
		return []DoctorCheck{{
			Name: "provider[" + envName + "]", Status: doctorFail,
			Detail: fmt.Sprintf("list secrets failed: %v", lerr), failClass: skret.ExitProviderError,
		}}
	}

	var checks []DoctorCheck
	if _, serr := os.Stat(absFile); serr != nil {
		checks = append(checks, DoctorCheck{
			Name: "provider[" + envName + "]", Status: doctorWarn,
			Detail:      fmt.Sprintf("no secrets file yet at %q (created on first 'skret set')", absFile),
			Remediation: "run 'skret set <KEY>' to create it",
		})
	} else {
		checks = append(checks,
			DoctorCheck{
				Name: "provider[" + envName + "]", Status: doctorPass,
				Detail: fmt.Sprintf("file loads (%d secret(s))", len(secrets)),
			},
			doctorPermCheck(deps.goos, envName, absFile),
			doctorEncryptionCheck(envName, rawEnv),
		)
	}
	return checks
}

// doctorPermCheck reports local secrets-file mode tightness. Warnings never:
// Windows does not enforce unix modes, and an over-open mode is advisory.
func doctorPermCheck(goos, envName, path string) DoctorCheck {
	name := "permissions[" + envName + "]"
	if goos == "windows" {
		return DoctorCheck{Name: name, Status: doctorPass, Detail: "windows does not enforce unix file modes"}
	}
	info, err := os.Stat(path)
	if err != nil {
		return DoctorCheck{Name: name, Status: doctorWarn, Detail: fmt.Sprintf("stat failed: %v", err)}
	}
	status, detail, remediation := doctorPermStatus(goos, info.Mode().Perm())
	return DoctorCheck{Name: name, Status: status, Detail: detail, Remediation: remediation}
}

// doctorPermStatus is the mode-tightness decision, split from the file I/O so
// both OS branches are testable on any platform.
func doctorPermStatus(goos string, perm fs.FileMode) (status, detail, remediation string) {
	if goos == "windows" {
		return doctorPass, "windows does not enforce unix file modes", ""
	}
	if perm&0o077 != 0 {
		return doctorWarn,
			fmt.Sprintf("file mode %04o is group/world accessible", perm),
			fmt.Sprintf("chmod 600 (the secrets file should be owner-only, not %04o)", perm)
	}
	return doctorPass, fmt.Sprintf("mode %04o", perm), ""
}

// doctorEncryptionCheck reports the local encryption intent flag defensively:
// the field is owned by the local-encryption lane, so any shape (missing,
// bool, non-bool) must yield a check result, never a crash. A missing field
// means plaintext, which is the supported default for development.
func doctorEncryptionCheck(envName string, rawEnv map[string]any) DoctorCheck {
	name := "encryption[" + envName + "]"
	v, ok := rawEnv["encrypted"]
	if !ok {
		return DoctorCheck{
			Name: name, Status: doctorWarn,
			Detail: "plaintext (default for dev; set 'encrypted: true' in .skret.yaml to enable)",
		}
	}
	enabled, isBool := v.(bool)
	if !isBool {
		return DoctorCheck{
			Name: name, Status: doctorWarn,
			Detail:      fmt.Sprintf("'encrypted' has unsupported type %T", v),
			Remediation: "set 'encrypted: true' or remove the field",
		}
	}
	if !enabled {
		return DoctorCheck{
			Name: name, Status: doctorWarn,
			Detail: "'encrypted: false' (plaintext)",
		}
	}
	return DoctorCheck{Name: name, Status: doctorPass, Detail: "encrypted: true"}
}

// doctorAWSReachCheck probes AWS reachability once per run and reuses the
// result for every aws environment (the probe reads region/profile from the
// environment, not from per-env config).
func doctorAWSReachCheck(deps doctorDeps, envName string, timeout time.Duration, probeCache map[string]error) []DoctorCheck {
	name := "provider[" + envName + "]"
	probeRes, cached := probeCache["aws"]
	if !cached {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		probeRes = deps.liveness(ctx)
		cancel()
		probeCache["aws"] = probeRes
	}
	switch {
	case probeRes == nil:
		return []DoctorCheck{{Name: name, Status: doctorPass, Detail: "reachable (GetCallerIdentity)"}}
	case auth.IsAuthError(probeRes):
		return []DoctorCheck{{
			Name: name, Status: doctorFail,
			Detail:      fmt.Sprintf("credentials rejected: %v", probeRes),
			Remediation: "run 'skret auth login aws'",
			failClass:   skret.ExitAuthError,
		}}
	default:
		return []DoctorCheck{{
			Name: name, Status: doctorFail,
			Detail:      fmt.Sprintf("unreachable: %v", probeRes),
			Remediation: "check network and region (AWS_REGION, or --region)",
			failClass:   skret.ExitNetworkError,
		}}
	}
}

// doctorAuthCheck reports stored-credential state for aws, the only
// cred-bearing provider today. A missing credential is a warning (the SDK
// default chain may still work — the reachability check above is the
// authoritative signal), an expired credential a failure. Reintroduce a
// providerName parameter when a second cred-bearing provider lands.
func doctorAuthCheck(deps doctorDeps) DoctorCheck {
	const providerName = "aws"
	name := "auth[" + providerName + "]"
	cred, err := deps.store.Load(providerName)
	switch {
	case errors.Is(err, auth.ErrCredentialNotFound):
		return DoctorCheck{
			Name: name, Status: doctorWarn,
			Detail:      "no stored credential (SDK default chain in use)",
			Remediation: "run 'skret auth login " + providerName + "' to store one",
		}
	case err != nil:
		return DoctorCheck{
			Name: name, Status: doctorFail,
			Detail:      fmt.Sprintf("credential store unreadable: %v", err),
			Remediation: "fix the skret credential file, then run 'skret auth login " + providerName + "'",
			failClass:   skret.ExitAuthError,
		}
	}
	// Expiry uses deps.now (not cred.IsExpired's internal time.Now) so the
	// whole check is deterministic under an injected clock; production
	// deps.now is time.Now, so behavior is identical.
	if !cred.ExpiresAt.IsZero() && deps.now().After(cred.ExpiresAt) {
		return DoctorCheck{
			Name: name, Status: doctorFail,
			Detail:      fmt.Sprintf("credential expired at %s", cred.ExpiresAt.Format(time.RFC3339)),
			Remediation: "run 'skret auth login " + providerName + "'",
			failClass:   skret.ExitAuthError,
		}
	}
	if !cred.ExpiresAt.IsZero() {
		if until := cred.ExpiresAt.Sub(deps.now()); until < authExpiryWarnWindow {
			return DoctorCheck{
				Name: name, Status: doctorWarn,
				Detail:      fmt.Sprintf("credential expires in %s (at %s)", until.Round(time.Second), cred.ExpiresAt.Format(time.RFC3339)),
				Remediation: "run 'skret auth login " + providerName + "' to refresh before it lapses",
			}
		}
		return DoctorCheck{
			Name: name, Status: doctorPass,
			Detail: fmt.Sprintf("valid (method: %s, expires at %s)", cred.Method, cred.ExpiresAt.Format(time.RFC3339)),
		}
	}
	return DoctorCheck{
		Name: name, Status: doctorPass,
		Detail: fmt.Sprintf("valid (method: %s)", cred.Method),
	}
}

// loadRawEnvironments re-reads the config file loosely to observe fields the
// typed schema does not declare yet. Best-effort: any failure yields nil and
// callers treat lookups as "field absent".
func loadRawEnvironments(path string) map[string]map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw struct {
		Environments map[string]map[string]any `yaml:"environments"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	return raw.Environments
}

// doctorTally counts checks by status.
func doctorTally(checks []DoctorCheck) (pass, warn, fail int) {
	for _, c := range checks {
		switch c.Status {
		case doctorPass:
			pass++
		case doctorWarn:
			warn++
		case doctorFail:
			fail++
		}
	}
	return pass, warn, fail
}

// doctorFailure returns the exit code of the first failing class in fixed
// precedence (config, provider, auth, network), whether anything failed, and
// the names of the failing checks for the error message.
func doctorFailure(checks []DoctorCheck) (code int, failed bool, names []string) {
	for _, class := range []int{skret.ExitConfigError, skret.ExitProviderError, skret.ExitAuthError, skret.ExitNetworkError} {
		for _, c := range checks {
			if c.Status == doctorFail && c.failClass == class {
				names = append(names, c.Name)
			}
		}
		if len(names) > 0 {
			return class, true, names
		}
	}
	// Defensive: a fail check without a recognized class still fails closed.
	for _, c := range checks {
		if c.Status == doctorFail {
			return skret.ExitGenericError, true, []string{c.Name}
		}
	}
	return skret.ExitSuccess, false, nil
}

// doctorFirstRemediation returns the remediation hint of the first failing
// check, so the error envelope carries an actionable fix like any other
// failing command (errjson pattern).
func doctorFirstRemediation(checks []DoctorCheck) string {
	for _, c := range checks {
		if c.Status == doctorFail && c.Remediation != "" {
			return c.Remediation
		}
	}
	return ""
}
