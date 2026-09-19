package local

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/config"
)

// AuditOp* name the operations recorded in the local audit trail. Every
// local-provider mutation appends exactly one JSONL line carrying these
// values plus key names, environment, and actor -- never secret values.
const (
	AuditOpSet    = "set"
	AuditOpRotate = "rotate"
	AuditOpDelete = "delete"
)

// AuditFileName is the default audit trail location: a sibling of the
// secrets file, so a per-environment file keeps its trail alongside it.
const AuditFileName = ".skret-audit.log"

// AuditRotateBytes is the append file's rotation threshold. When the active
// log reaches this size the next append first renames it to
// `<path>.1` (single backup, overwritten in turn), keeping any one log
// bounded while staying a plain append-only sequence between rotations.
const AuditRotateBytes = 1 << 20 // 1 MiB

// auditOpKey is the context key a rotation command uses to label its Set
// calls as "rotate" (the provider interface has no op parameter, and adding
// one would touch every provider for one call site's metadata).
type auditOpKey struct{}

// WithAuditOp stamps ctx so local-provider Set calls record op as op
// instead of "set". Unknown/empty ops fall back to "set" at read time.
func WithAuditOp(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, auditOpKey{}, op)
}

// auditOpFromCtx resolves the stamped op, defaulting to "set".
func auditOpFromCtx(ctx context.Context) string {
	if ctx != nil {
		if op, ok := ctx.Value(auditOpKey{}).(string); ok && op != "" {
			return op
		}
	}
	return AuditOpSet
}

// AuditEntry is one line of the local audit trail. KeyNames is the affected
// secret names; values are structurally excluded from this type, and the
// append path writes only these fields.
type AuditEntry struct {
	Timestamp string   `json:"timestamp"` // RFC3339Nano, UTC
	Op        string   `json:"op"`        // set | rotate | delete
	KeyNames  []string `json:"key_names"`
	Env       string   `json:"env"`   // active .skret.yaml environment
	Actor     string   `json:"actor"` // OS user or SKRET_ACTOR
}

// ReadAuditLog parses the JSONL audit trail at path. Malformed lines are
// skipped and counted (a trail must stay readable even if one line was
// truncated mid-write by a crash); returned alongside the entries.
func ReadAuditLog(path string) ([]AuditEntry, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var (
		entries []AuditEntry
		skipped int
	)
	for _, line := range splitLines(string(raw)) {
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.Op == "" {
			skipped++
			continue
		}
		entries = append(entries, e)
	}
	return entries, skipped, nil
}

// splitLines splits s on '\n' (and trims a trailing '\r' for logs written
// on or moved through Windows).
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == '\n' {
			out = append(out, trimCR(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimCR(s[start:]))
	return out
}

func trimCR(s string) string {
	if s != "" && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

// auditActor resolves who performed a mutation: SKRET_ACTOR when the caller
// (CI, an agent harness) declares it, otherwise the OS user.
func auditActor() string {
	if a := os.Getenv("SKRET_ACTOR"); a != "" {
		return sanitizeActor(a)
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return sanitizeActor(u.Username)
	}
	for _, k := range []string{"USER", "USERNAME"} {
		if u := os.Getenv(k); u != "" {
			return sanitizeActor(u)
		}
	}
	return "unknown"
}

// sanitizeActor reduces an OS identity to one display-safe token: the
// trailing component of "DOMAIN\user" (Windows usernames can arrive with
// machine prefixes and stray whitespace) with internal whitespace joined by
// dashes. Actors must never break the audit table or the JSONL line shape.
func sanitizeActor(s string) string {
	if i := strings.LastIndex(s, "\\"); i >= 0 {
		s = s[i+1:]
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "unknown"
	}
	return strings.Join(fields, "-")
}

// AuditLogPathFor returns the audit trail location for a resolved local
// config: the `audit_log` override, else the default sibling of the secrets
// file. The audit command reads through this so the CLI and the provider
// cannot disagree about where the trail lives.
func AuditLogPathFor(cfg *config.ResolvedConfig) string {
	if cfg.AuditLog != "" {
		return cfg.AuditLog
	}
	return filepath.Join(filepath.Dir(cfg.File), AuditFileName)
}

// auditLogPath returns the active trail location: the configured override,
// else the default sibling of the secrets file.
func (p *Provider) auditLogPath() string {
	if p.auditPath != "" {
		return p.auditPath
	}
	return filepath.Join(filepath.Dir(p.filePath), AuditFileName)
}

// appendAudit records one mutation. It runs while the provider write lock is
// held (callers are Set/Delete), which serializes appends within the
// process; a single O_APPEND write keeps lines whole across processes.
//
// An append failure is returned even though the secret write already
// committed: a trail that silently drops entries is worse than a loud
// failure, and the remediation ("check audit log path permissions") is
// actionable without re-running the mutation.
func (p *Provider) appendAudit(op string, keyNames ...string) error {
	path := p.auditLogPath()
	if err := rotateAuditLog(path); err != nil {
		return fmt.Errorf("audit: rotate %q: %w", path, err)
	}
	// A configured audit_log may live in a directory that does not exist
	// yet (e.g. trails/audit-dev.log); create it on first append.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("audit: create dir %q: %w", dir, err)
		}
	}
	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Op:        op,
		KeyNames:  keyNames,
		Env:       p.envName,
		Actor:     auditActor(),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %q: %w", path, err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: append %q: %w", path, err)
	}
	return f.Close()
}

// rotateAuditLog renames an at-threshold log to `<path>.1` (replacing the
// previous backup) so the next append starts fresh. A missing active log is
// not an error -- the first append simply creates it.
func rotateAuditLog(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() < AuditRotateBytes {
		return nil
	}
	return os.Rename(path, path+".1")
}
