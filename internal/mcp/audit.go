package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/n24q02m/skret/pkg/skret"
)

// auditEvent names the session audit record type.
const auditEvent = "mcp_tool_call"

// auditRecord is one session audit line: exactly one per tools/call, in
// JSON. It never carries a secret value, and key names are masked.
type auditRecord struct {
	Timestamp string   `json:"timestamp"`
	Event     string   `json:"event"`
	SessionID string   `json:"session_id"`
	Tool      string   `json:"tool"`
	Env       string   `json:"env,omitempty"`
	Keys      []string `json:"keys,omitempty"`
	Decision  string   `json:"decision"`
	Reason    string   `json:"reason,omitempty"`
	Outcome   string   `json:"outcome"`
}

// callState is what one tools/call has resolved so far; the audit record
// is built from it.
type callState struct {
	tool     string
	args     map[string]any
	env      string
	keys     []string
	wildcard bool // the call reads every key name (skret_list)
}

// newSessionID returns 128 random bits, hex-encoded. One server run is one
// session; the id ties its audit records together.
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return hex.EncodeToString(b)
}

// prepareAuditFile creates the audit file (and its directory) so an
// unwritable mcp.audit_log fails the server at startup instead of on the
// first tool call.
func prepareAuditFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return appendAuditLine(path, nil)
}

// appendAuditLine appends one line to the audit file, opening it per
// record so an external rotation or removal is picked up.
func appendAuditLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	return errors.Join(werr, f.Close())
}

// auditKeys renders the keys of a call for the audit trail: the wildcard
// for a list, else each key name redacted and then masked.
func (s *Server) auditKeys(st *callState) []string {
	if st.wildcard {
		return []string{"*"}
	}
	if len(st.keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(st.keys))
	for _, k := range st.keys {
		out = append(out, logging.Mask(s.redact(k)))
	}
	return out
}

// recordCall writes the audit record of one tool call. The record always
// goes to the audit writer (stderr by default) on a best-effort basis; when
// mcp.audit_log is set it is appended to that file too, and a failure to do
// so is returned so the caller can withhold the call's result.
func (s *Server) recordCall(st *callState, callErr error) error {
	rec := auditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     auditEvent,
		SessionID: s.sessionID,
		Tool:      s.redact(st.tool),
		Env:       s.redact(st.env),
		Keys:      s.auditKeys(st),
		Decision:  "allow",
		Outcome:   "ok",
	}
	if callErr != nil {
		rec.Outcome = "error"
	}
	if reason := denyReason(callErr); reason != "" {
		rec.Decision = "deny"
		rec.Reason = reason
	}
	line := append([]byte(mustJSON(rec)), '\n')

	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if _, err := s.auditOut.Write(line); err != nil {
		slog.Debug("skret-mcp: audit writer failed", "err", s.redact(err.Error()))
	}
	if s.auditPath == "" {
		return nil
	}
	if err := appendAuditLine(s.auditPath, line); err != nil {
		slog.Error("skret-mcp: audit file append failed", "err", s.redact(err.Error()))
		return skret.WithRemediation(
			skret.NewError(skret.ExitGenericError, "skret-mcp: failed to write the MCP audit record", err),
			"make "+s.auditPath+" (mcp.audit_log) writable again; the result of this call was withheld, but a write tool may already have changed the store, so check it with skret_get or skret_list")
	}
	return nil
}

// refuseCall audits a tools/call rejected as a protocol error and returns
// that error. The rejection stands even if the audit file fails.
func (s *Server) refuseCall(st *callState, reason string, rpcErr *rpcError) *rpcError {
	_ = s.recordCall(st, deny(reason, errors.New(rpcErr.Message))) // failure already logged; the call is refused anyway
	return rpcErr
}
