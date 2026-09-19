package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// auditOptions holds the `skret audit` flag set.
type auditOptions struct {
	globals *GlobalOpts
	since   string
	key     string
	limit   int
	format  string
}

func newAuditCmd(opts *GlobalOpts) *cobra.Command {
	o := &auditOptions{globals: opts}

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the secret access audit trail (local log or AWS CloudTrail)",
		Long: `Show who changed or read secrets, when, and with which operation.

Local provider: renders the append-only JSONL audit trail
(.skret-audit.log next to the secrets file, or the configured audit_log
path). Every set/rotate/delete on the local provider appends one line with
timestamp, operation, key names, environment, and actor (SKRET_ACTOR when
set, else the OS user) -- never secret values.

AWS provider: exports CloudTrail events for SSM Parameter Store operations
(GetParameter/GetParameters/GetParametersByPath/GetParameterHistory,
PutParameter, DeleteParameter[s]). CloudTrail retains lookups for the last
90 days, so --since older than that yields whatever the service still
returns. The sweep runs one bounded LookupEvents call per event name.

Read-only by design: audit never mutates state, is fully non-interactive,
and stdout carries data only (table) or the JSON envelope (--format json).`,
		Example: `  skret audit
  skret audit --since 24h
  skret audit --key API_KEY --format json
  skret audit --provider aws --since 2026-09-01T00:00:00Z --limit 50`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.since, "since", "", "only entries newer than this (duration e.g. 24h, 30d, or RFC3339)")
	cmd.Flags().StringVar(&o.key, "key", "", "only entries for this exact key/parameter name")
	cmd.Flags().IntVar(&o.limit, "limit", 0, "show at most N entries, most recent first trimmed (0 = all)")
	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")

	return cmd
}

func (o *auditOptions) run(cmd *cobra.Command) error {
	if o.format != "table" && o.format != "json" {
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("audit: unknown --format %q (table, json)", o.format), nil)
	}
	if o.limit < 0 {
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("audit: --limit must be >= 0 (got %d)", o.limit), nil)
	}
	since, err := parseSince(o.since)
	if err != nil {
		return skret.NewError(skret.ExitValidationError, "audit: --since "+err.Error(), nil)
	}

	resolved, err := loadResolvedConfig(o.globals)
	if err != nil {
		return err
	}

	switch resolved.Provider {
	case "local":
		return o.runLocal(cmd, resolved, since)
	case "aws":
		return o.runCloudTrail(cmd, resolved, since)
	default:
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("audit: provider %q has no skret-managed audit trail (supported: local, aws)", resolved.Provider), nil)
	}
}

// runLocal renders the local provider's JSONL audit trail. It resolves
// config only -- never the provider itself -- so reading the trail never
// triggers decryption or a keystore prompt.
func (o *auditOptions) runLocal(cmd *cobra.Command, resolved *config.ResolvedConfig, since time.Time) error {
	path := local.AuditLogPathFor(resolved)

	entries, skipped, err := local.ReadAuditLog(path)
	if err != nil {
		if os.IsNotExist(err) {
			entries = nil
		} else {
			return skret.NewError(skret.ExitProviderError,
				fmt.Sprintf("audit: read %q: %v", path, err), err)
		}
	}
	if skipped > 0 {
		cmd.PrintErrf("warning: skipped %d malformed audit line(s) in %q\n", skipped, path)
	}

	entries = filterLocalEntries(entries, since, o.key, o.limit)
	return renderLocalAudit(cmd, entries, o.format)
}

// filterLocalEntries applies the since/key/limit filters in log order and
// returns entries chronologically (oldest first). --limit keeps the most
// recent N matching entries.
func filterLocalEntries(entries []local.AuditEntry, since time.Time, key string, limit int) []local.AuditEntry {
	out := make([]local.AuditEntry, 0, len(entries))
	for _, e := range entries {
		if !since.IsZero() {
			ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if err != nil || ts.Before(since) {
				continue
			}
		}
		if key != "" && !localEntryHas(e, key) {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func localEntryHas(e local.AuditEntry, key string) bool {
	for _, k := range e.KeyNames {
		if k == key {
			return true
		}
	}
	return false
}

func renderLocalAudit(cmd *cobra.Command, entries []local.AuditEntry, format string) error {
	if len(entries) == 0 {
		cmd.PrintErrln("No audit entries. Mutations (set/rotate/delete) append to the trail; see 'skret audit --help'.")
		if format != "json" {
			return nil
		}
	}
	stdout := cmd.OutOrStdout()
	if format == "json" {
		payload := make([]local.AuditEntry, 0, len(entries))
		payload = append(payload, entries...)
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "audit: encode result", err)
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tOP\tENV\tKEYS\tACTOR")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", auditTableTime(e.Timestamp), e.Op, e.Env, strings.Join(e.KeyNames, ","), e.Actor)
	}
	return w.Flush()
}

// runCloudTrail exports CloudTrail events for SSM parameter operations.
func (o *auditOptions) runCloudTrail(cmd *cobra.Command, resolved *config.ResolvedConfig, since time.Time) error {
	lookuper, err := aws.NewCloudTrailLookuper(resolved)
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "audit: init cloudtrail client failed", err)
	}

	events, err := aws.LookupParameterEvents(context.Background(), lookuper, aws.AuditLookupOpts{
		Since: since,
		Limit: o.limit,
		Key:   o.key,
	})
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "audit: cloudtrail lookup failed", err)
	}
	return renderCloudTrailAudit(cmd, events, o.format)
}

func renderCloudTrailAudit(cmd *cobra.Command, events []aws.AuditEvent, format string) error {
	if len(events) == 0 {
		cmd.PrintErrln("No CloudTrail events found. SSM parameter operations from the last 90 days appear here once the trail records them.")
		if format != "json" {
			return nil
		}
	}
	stdout := cmd.OutOrStdout()
	if format == "json" {
		payload := make([]aws.AuditEvent, 0, len(events))
		payload = append(payload, events...)
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "audit: encode result", err)
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tEVENT\tPARAMETER\tUSER\tSOURCE")
	for _, e := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", auditTableTime(e.Time), e.Event, e.Parameter, e.Username, e.SourceIP)
	}
	return w.Flush()
}

// auditTableTime renders a stored RFC3339 timestamp at second precision for
// the table (unparseable values print verbatim).
func auditTableTime(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ts
	}
	return t.UTC().Format(time.RFC3339)
}

// parseSince accepts an RFC3339 timestamp (absolute cutoff) or a positive
// duration (cutoff = now - d, Go units or day counts like 30d).
func parseSince(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	d, err := parseTTL(v)
	if err != nil {
		return time.Time{}, fmt.Errorf("expects a duration (24h, 30d) or RFC3339 timestamp: %w", err)
	}
	return time.Now().Add(-d), nil
}

// loadResolvedConfig resolves config exactly like loadProvider (discovered
// .skret.yaml, --config, or ephemeral from --path) without constructing a
// provider -- for read-only commands that must not trigger decryption.
func loadResolvedConfig(opts *GlobalOpts) (*config.ResolvedConfig, error) {
	resolveOpts := config.ResolveOpts{
		Env:      opts.Env,
		Provider: opts.Provider,
		Path:     opts.Path,
		Region:   opts.Region,
		Profile:  opts.Profile,
		File:     opts.File,
	}

	var cfg *config.Config
	cfgPath, derr := resolveConfigFile(opts)
	switch {
	case derr == nil:
		loaded, lerr := config.Load(cfgPath)
		if lerr != nil {
			return nil, skret.NewError(skret.ExitConfigError, "load config failed", lerr)
		}
		cfg = loaded
	case opts.Config != "":
		return nil, skret.NewError(skret.ExitConfigError, "load config failed", derr)
	case opts.Path != "":
		cfg = config.EphemeralConfig(resolveOpts)
	default:
		return nil, skret.NewError(skret.ExitConfigError, configNotFoundMsg, derr)
	}

	resolved, err := config.Resolve(cfg, resolveOpts)
	if err != nil {
		return nil, skret.NewError(skret.ExitConfigError, "resolve config failed", err)
	}
	return resolved, nil
}
