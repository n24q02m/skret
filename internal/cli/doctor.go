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
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
	skoci "github.com/n24q02m/skret/internal/provider/oci"
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

// doctorStatusOf reports local encryption state (keystore.StatusOf). A
// variable so tests can inject deterministic statuses instead of depending
// on machine keyrings.
var doctorStatusOf = keystore.StatusOf

// doctorDeps holds the externals doctor talks to, injectable for tests.
type doctorDeps struct {
	liveness func(ctx context.Context) error
	store    *auth.Store
	statusOf func(filePath string, cfgEncrypted bool) (*keystore.Status, error)
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
		statusOf: doctorStatusOf,
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
		case "oci":
			checks = append(checks, doctorOCIReachCheck(envName, resolved, timeout, probeCache)...)
		default:
			checks = append(checks, DoctorCheck{
				Name:        "provider[" + envName + "]",
				Status:      doctorFail,
				Detail:      fmt.Sprintf("unknown provider %q", resolved.Provider),
				Remediation: "supported providers: local, aws, oci",
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
		// Preserve the failure's spec class and remediation (e.g. an
		// encrypted file with no key material is an auth-class failure with
		// a SKRET_AGE_KEY hint, not a generic "corrupt file").
		return []DoctorCheck{{
			Name: "provider[" + envName + "]", Status: doctorFail,
			Detail:      fmt.Sprintf("file %q unreadable: %v", absFile, perr),
			Remediation: doctorLocalFailureRemediation(perr),
			failClass:   doctorLocalFailureClass(perr),
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
			doctorEncryptionCheck(deps, envName, absFile, rawEnv),
		)
		if c := doctorExpiryCheck(deps, envName, secrets); c != nil {
			checks = append(checks, *c)
		}
	}
	return checks
}

// doctorExpiryCheck reports TTL hygiene for secrets that carry expiry
// metadata: how many are past expiry and how many fall due within the same
// 7-day window `skret list` warns at. Advisory only — an expired secret
// still works, so this never fails the run. Environments whose secrets
// carry no TTL metadata emit no check line at all.
func doctorExpiryCheck(deps doctorDeps, envName string, secrets []*provider.Secret) *DoctorCheck {
	var expired, nearing []string
	now := deps.now()
	for _, s := range secrets {
		if s.Meta.ExpiresAt.IsZero() {
			continue
		}
		switch {
		case now.After(s.Meta.ExpiresAt):
			expired = append(expired, s.Key)
		case s.Meta.ExpiresAt.Sub(now) <= nearExpiryWindow:
			nearing = append(nearing, s.Key)
		}
	}
	if len(expired) == 0 && len(nearing) == 0 {
		return nil
	}

	var detail strings.Builder
	if len(expired) > 0 {
		fmt.Fprintf(&detail, "%d past expiry (%s)", len(expired), strings.Join(expired, ", "))
	}
	if len(nearing) > 0 {
		if detail.Len() > 0 {
			detail.WriteString("; ")
		}
		fmt.Fprintf(&detail, "%d expiring within %s (%s)", len(nearing), nearExpiryWindow, strings.Join(nearing, ", "))
	}
	return &DoctorCheck{
		Name:        "expiry[" + envName + "]",
		Status:      doctorWarn,
		Detail:      detail.String(),
		Remediation: "rotate with 'skret rotate <KEY> --ttl <duration>'",
	}
}

// doctorLocalFailureClass maps a local-provider load failure to its spec
// exit class: errors that already carry a class (keystore auth/validation
// errors) keep it; anything else is a provider failure.
func doctorLocalFailureClass(err error) int {
	if code := skret.ExitCode(err); code != skret.ExitGenericError {
		return code
	}
	return skret.ExitProviderError
}

// doctorLocalFailureRemediation returns the remediation attached to the
// load failure, falling back to the generic corrupt-file hint.
func doctorLocalFailureRemediation(err error) string {
	if hint := skret.RemediationOf(err); hint != "" {
		return hint
	}
	return "fix or remove the secrets file (corrupt YAML is the usual cause)"
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

// doctorEncryptionCheck reports local at-rest encryption state via
// keystore.StatusOf: on-disk envelope reality plus key availability, keyed
// off the environment's `encrypted` intent flag. Any shape the raw config
// may hold (missing, non-bool) is tolerated — missing means plaintext
// intent, the supported default for development, and never crashes.
func doctorEncryptionCheck(deps doctorDeps, envName, filePath string, rawEnv map[string]any) DoctorCheck {
	name := "encryption[" + envName + "]"
	cfgEncrypted := false
	if v, ok := rawEnv["encrypted"]; ok {
		if b, isBool := v.(bool); isBool {
			cfgEncrypted = b
		}
	}

	st, err := deps.statusOf(filePath, cfgEncrypted)
	if err != nil {
		return DoctorCheck{
			Name: name, Status: doctorWarn,
			Detail: fmt.Sprintf("encryption state unknown: %v", err),
		}
	}

	switch {
	case st.Encrypted && st.KeyAvailable:
		detail := "encrypted"
		extras := make([]string, 0, 3)
		if st.Format != "" {
			extras = append(extras, "format "+st.Format)
		}
		if st.KDF != "" {
			extras = append(extras, "kdf "+st.KDF)
		}
		if st.KeySource != "" {
			extras = append(extras, "key from "+st.KeySource)
		}
		if len(extras) > 0 {
			detail += " (" + strings.Join(extras, ", ") + ")"
		}
		return DoctorCheck{Name: name, Status: doctorPass, Detail: detail}
	case st.Encrypted:
		return DoctorCheck{
			Name: name, Status: doctorFail,
			Detail:      "secrets file is encrypted but no key material is available non-interactively",
			Remediation: "export SKRET_AGE_KEY=<key material> (or run 'skret keys init' to store it in the OS keyring)",
			failClass:   skret.ExitAuthError,
		}
	case cfgEncrypted:
		return DoctorCheck{
			Name: name, Status: doctorWarn,
			Detail:      "'encrypted: true' is set but the secrets file is still plaintext (pre-migration state)",
			Remediation: "run 'skret keys init --encrypt-existing' to migrate the file to the encrypted envelope",
		}
	default:
		detail := "plaintext (default for dev; set 'encrypted: true' in .skret.yaml to enable)"
		if n := len(st.Warnings); n > 0 {
			shown := st.Warnings
			if len(shown) > 3 {
				shown = append(append([]string{}, shown[:3]...), fmt.Sprintf("+%d more", n-3))
			}
			detail += "; " + strings.Join(shown, "; ")
		}
		return DoctorCheck{Name: name, Status: doctorWarn, Detail: detail}
	}
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

// ociAuthConfigError marks a probe failure caused by the local OCI auth
// configuration (no config file, bad key material), not by the network.
type ociAuthConfigError struct{ err error }

func (e *ociAuthConfigError) Error() string { return e.err.Error() }
func (e *ociAuthConfigError) Unwrap() error { return e.err }

// doctorOCIReachCheck probes OCI Vault reachability once per run and reuses
// the result for every oci environment. Provider construction validates the
// auth configuration; a names-only listing (no decryption) validates the
// network path under the probe timeout.
func doctorOCIReachCheck(envName string, resolved *config.ResolvedConfig, timeout time.Duration, probeCache map[string]error) []DoctorCheck {
	name := "provider[" + envName + "]"
	probeRes, cached := probeCache["oci"]
	if !cached {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		probeRes = doctorOCIProbe(ctx, resolved)
		cancel()
		probeCache["oci"] = probeRes
	}
	var authCfgErr *ociAuthConfigError
	switch {
	case probeRes == nil:
		return []DoctorCheck{{Name: name, Status: doctorPass, Detail: "reachable (names-only listing)"}}
	case errors.As(probeRes, &authCfgErr):
		return []DoctorCheck{{
			Name: name, Status: doctorFail,
			Detail:      fmt.Sprintf("auth configuration unusable: %v", authCfgErr.err),
			Remediation: "create ~/.oci/config ('oci setup config'), set the OCI_CLI_* variables, or set OCI_CLI_AUTH=instance_principal",
			failClass:   skret.ExitAuthError,
		}}
	default:
		return []DoctorCheck{{
			Name: name, Status: doctorFail,
			Detail:      fmt.Sprintf("unreachable: %v", probeRes),
			Remediation: "check network and region (`region` in .skret.yaml or OCI_CLI_REGION)",
			failClass:   skret.ExitNetworkError,
		}}
	}
}

// doctorOCIProbe constructs the provider (auth validation) and issues a
// names-only listing (network probe).
func doctorOCIProbe(ctx context.Context, resolved *config.ResolvedConfig) error {
	p, err := skoci.New(resolved)
	if err != nil {
		return &ociAuthConfigError{err: err}
	}
	defer p.Close()
	_, err = p.ListNames(ctx, resolved.Path)
	return err
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
