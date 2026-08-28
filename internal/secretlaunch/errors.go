package secretlaunch

import "fmt"

// ErrorCode is a stable, value-free classification for launch failures.
type ErrorCode string

const (
	ErrInvalidInput   ErrorCode = "invalid_input"
	ErrCanonical      ErrorCode = "noncanonical_manifest"
	ErrUnknownField   ErrorCode = "unknown_manifest_field"
	ErrDuplicateField ErrorCode = "duplicate_manifest_field"
	ErrSignature      ErrorCode = "signature_rejected"
	ErrTrust          ErrorCode = "trust_rejected"
	ErrExpired        ErrorCode = "manifest_expired"
	ErrNotYetValid    ErrorCode = "manifest_not_yet_valid"
	ErrTTL            ErrorCode = "manifest_ttl_rejected"
	ErrBinding        ErrorCode = "binding_mismatch"
	ErrKey            ErrorCode = "key_rejected"
	ErrFetch          ErrorCode = "secret_fetch_failed"
	ErrCrypto         ErrorCode = "envelope_rejected"
	ErrReplay         ErrorCode = "envelope_replay"
	ErrFrame          ErrorCode = "frame_rejected"
	ErrLifecycle      ErrorCode = "lifecycle_failed"
	ErrDaemon         ErrorCode = "daemon_unavailable"
	ErrRuntime        ErrorCode = "runtime_rejected"
	ErrNotInvoked     ErrorCode = "runtime_not_explicitly_invoked"
	ErrChild          ErrorCode = "child_failed"
	ErrNoProvider     ErrorCode = "provider_required"
)

// LaunchError deliberately omits the underlying error text. Providers and
// runtimes frequently include values in their native errors; preserving that
// text would make a safe diagnostic impossible.
type LaunchError struct {
	Code ErrorCode
	Key  string
}

func (e *LaunchError) Error() string {
	if e == nil {
		return "secret launch: unknown failure"
	}
	if e.Key != "" {
		return fmt.Sprintf("secret launch: %s (key %s)", e.Code, e.Key)
	}
	return fmt.Sprintf("secret launch: %s", e.Code)
}

func fail(code ErrorCode) error { return &LaunchError{Code: code} }

func failKey(code ErrorCode, key string) error {
	return &LaunchError{Code: code, Key: evidenceKey(key)}
}

func evidenceKey(key string) string {
	if key == "" || len(key) > MaxKeyLength {
		return "invalid"
	}
	for _, r := range key {
		if r == '\x00' || r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			return "invalid"
		}
	}
	return key
}

func errorCode(err error) ErrorCode {
	if e, ok := err.(*LaunchError); ok && e != nil {
		return e.Code
	}
	return ErrLifecycle
}
