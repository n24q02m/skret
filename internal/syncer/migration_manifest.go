package syncer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// StateManifestVersion identifies the canonical signed state-manifest schema.
	StateManifestVersion = 1

	// MaxStateManifestTTL bounds how long a state manifest may remain valid after
	// the injected signing clock. Replay acceptance remains executor-owned.
	MaxStateManifestTTL = 15 * time.Minute
)

// StateManifest is a detached-signature, value-free inventory of a bounded
// local state root. Files contains only relative paths, byte lengths, and
// SHA-256 digests; no file contents are projected into the manifest.
type StateManifest struct {
	Version    int                 `json:"version"`
	Role       string              `json:"role"`
	Audience   string              `json:"audience"`
	SourceRoot string              `json:"source_root"`
	Files      []StateManifestFile `json:"files"`
	Nonce      string              `json:"nonce"`
	ExpiresAt  time.Time           `json:"expires_at"`
	Signature  []byte              `json:"signature"`
}

// StateManifestFile is one regular file in a StateManifest. Path is a
// normalized slash-separated path relative to StateManifest.SourceRoot.
type StateManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// CanonicalSigningBytes returns deterministic JSON over every authority-bearing
// field except the detached Signature. The source root is absolute and file
// rows are sorted by normalized relative path before signing.
func (m *StateManifest) CanonicalSigningBytes() ([]byte, error) {
	if m == nil {
		return nil, stateManifestError("missing manifest")
	}
	if err := validateStateManifestFields(m); err != nil {
		return nil, err
	}
	canonical := stateManifestSigningDocument{
		Version:    m.Version,
		Role:       m.Role,
		Audience:   m.Audience,
		SourceRoot: m.SourceRoot,
		Files:      m.Files,
		Nonce:      m.Nonce,
		ExpiresAt:  m.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, stateManifestError("canonical encoding failed")
	}
	return encoded, nil
}

// CanonicalBytes is an alias for callers that need the exact bytes signed by
// BuildStateManifest.
func (m *StateManifest) CanonicalBytes() ([]byte, error) {
	return m.CanonicalSigningBytes()
}

// CanonicalStateManifestBytes returns the exact bytes signed for m.
func CanonicalStateManifestBytes(m *StateManifest) ([]byte, error) {
	return m.CanonicalSigningBytes()
}

type stateManifestSigningDocument struct {
	Version    int                 `json:"version"`
	Role       string              `json:"role"`
	Audience   string              `json:"audience"`
	SourceRoot string              `json:"source_root"`
	Files      []StateManifestFile `json:"files"`
	Nonce      string              `json:"nonce"`
	ExpiresAt  string              `json:"expires_at"`
}

// BuildStateManifest scans root without following symlinks, hashes every
// regular file, and signs the deterministic metadata-only document with
// Ed25519. The supplied clock makes expiry validation deterministic.
func BuildStateManifest(
	root, role, audience, nonce string,
	expiresAt time.Time,
	signer ed25519.PrivateKey,
	now time.Time,
) (*StateManifest, error) {
	if err := validateStateManifestRequired(role, "role"); err != nil {
		return nil, err
	}
	if err := validateStateManifestRequired(audience, "audience"); err != nil {
		return nil, err
	}
	if err := validateStateManifestRequired(nonce, "nonce"); err != nil {
		return nil, err
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, stateManifestError("invalid signer")
	}
	if err := validateStateManifestExpiry(expiresAt, now); err != nil {
		return nil, err
	}
	canonicalRoot, err := canonicalizeStateManifestRoot(root)
	if err != nil {
		return nil, err
	}
	files, err := scanStateManifestRoot(canonicalRoot)
	if err != nil {
		return nil, err
	}
	manifest := &StateManifest{
		Version:    StateManifestVersion,
		Role:       role,
		Audience:   audience,
		SourceRoot: canonicalRoot,
		Files:      files,
		Nonce:      nonce,
		ExpiresAt:  expiresAt.UTC(),
	}
	canonical, err := manifest.CanonicalSigningBytes()
	if err != nil {
		return nil, err
	}
	manifest.Signature = ed25519.Sign(signer, canonical)
	return manifest, nil
}

// VerifyStateManifest validates the detached signature and then re-scans the
// expected bounded root. Verification succeeds only when role, audience,
// source-root identity, expiry, signature, exact file set, sizes, and digests
// all match.
func VerifyStateManifest(
	manifest *StateManifest,
	root, role, audience string,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if manifest == nil {
		return stateManifestError("missing manifest")
	}
	if err := validateStateManifestFields(manifest); err != nil {
		return err
	}
	if err := validateStateManifestRequired(role, "role"); err != nil {
		return err
	}
	if err := validateStateManifestRequired(audience, "audience"); err != nil {
		return err
	}
	if err := validateStateManifestExpiry(manifest.ExpiresAt, now); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return stateManifestError("invalid verifier key")
	}
	canonicalRoot, err := canonicalizeStateManifestRoot(root)
	if err != nil {
		return err
	}
	if manifest.SourceRoot != canonicalRoot {
		return stateManifestError("source root mismatch")
	}
	if manifest.Role != role {
		return stateManifestError("role mismatch")
	}
	if manifest.Audience != audience {
		return stateManifestError("audience mismatch")
	}
	if len(manifest.Signature) != ed25519.SignatureSize {
		return stateManifestError("invalid signature")
	}
	canonical, err := manifest.CanonicalSigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, manifest.Signature) {
		return stateManifestError("invalid signature")
	}
	actualFiles, err := scanStateManifestRoot(canonicalRoot)
	if err != nil {
		return err
	}
	if !sameStateManifestFiles(manifest.Files, actualFiles) {
		return stateManifestError("source files do not match manifest")
	}
	return nil
}

func validateStateManifestFields(m *StateManifest) error {
	if m.Version != StateManifestVersion {
		return stateManifestError("unsupported version")
	}
	if err := validateStateManifestRequired(m.Role, "role"); err != nil {
		return err
	}
	if err := validateStateManifestRequired(m.Audience, "audience"); err != nil {
		return err
	}
	if err := validateStateManifestRequired(m.Nonce, "nonce"); err != nil {
		return err
	}
	if err := validateStateManifestRootField(m.SourceRoot); err != nil {
		return err
	}
	if err := validateStateManifestTimestamp(m.ExpiresAt); err != nil {
		return err
	}
	if len(m.Files) == 0 {
		return stateManifestError("file set is empty")
	}
	previous := ""
	for index, file := range m.Files {
		if err := validateStateManifestFile(file); err != nil {
			return err
		}
		if index > 0 && file.Path <= previous {
			return stateManifestError("file rows are not strictly sorted")
		}
		previous = file.Path
	}
	return nil
}

func validateStateManifestRequired(value, name string) error {
	if strings.TrimSpace(value) == "" {
		return stateManifestError(name + " is required")
	}
	if !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
		return stateManifestError("invalid " + name)
	}
	return nil
}

func validateStateManifestRootField(root string) error {
	if err := validateStateManifestRequired(root, "source root"); err != nil {
		return err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return stateManifestError("source root is not canonical")
	}
	return nil
}

func validateStateManifestTimestamp(expiresAt time.Time) error {
	if expiresAt.IsZero() {
		return stateManifestError("expiry is required")
	}
	if _, err := expiresAt.MarshalJSON(); err != nil {
		return stateManifestError("invalid expiry")
	}
	return nil
}

func validateStateManifestExpiry(expiresAt, now time.Time) error {
	if err := validateStateManifestTimestamp(expiresAt); err != nil {
		return err
	}
	if !expiresAt.After(now) {
		return stateManifestError("expiry is not in the future")
	}
	if expiresAt.Sub(now) > MaxStateManifestTTL {
		return stateManifestError("expiry exceeds maximum TTL")
	}
	return nil
}

func validateStateManifestFile(file StateManifestFile) error {
	if !validStateManifestPath(file.Path) {
		return stateManifestError("invalid file path")
	}
	if file.Size < 0 {
		return stateManifestError("invalid file size")
	}
	if !validStateManifestSHA256(file.SHA256) {
		return stateManifestError("invalid file digest")
	}
	return nil
}

func validStateManifestPath(value string) bool {
	if value == "" || value == "." || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
		return false
	}
	if strings.ContainsRune(value, '\\') || strings.ContainsRune(value, ':') || pathpkg.IsAbs(value) {
		return false
	}
	if pathpkg.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return !filepath.IsAbs(filepath.FromSlash(value))
}

func validStateManifestSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalizeStateManifestRoot(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" || !utf8.ValidString(raw) || strings.ContainsRune(raw, '\x00') {
		return "", stateManifestError("invalid source root")
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", stateManifestError("invalid source root")
	}
	canonical := filepath.Clean(absolute)
	if !filepath.IsAbs(canonical) {
		return "", stateManifestError("invalid source root")
	}
	if err := rejectStateManifestSymlinkAncestors(canonical); err != nil {
		return "", err
	}
	info, err := os.Lstat(canonical)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", stateManifestError("invalid source root")
	}
	return canonical, nil
}

func rejectStateManifestSymlinkAncestors(root string) error {
	for current := root; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return stateManifestError("invalid source root")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return stateManifestError("symlink source roots are not allowed")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func scanStateManifestRoot(root string) ([]StateManifestFile, error) {
	files := make([]StateManifestFile, 0)
	err := filepath.WalkDir(root, func(currentPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil {
			return stateManifestError("source root scan failed")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return stateManifestError("symlink entries are not allowed")
		}
		if currentPath == root {
			if !entry.IsDir() {
				return stateManifestError("invalid source root")
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return stateManifestError("non-regular entries are not allowed")
		}
		relative, err := filepath.Rel(root, currentPath)
		if err != nil {
			return stateManifestError("source path resolution failed")
		}
		normalized := filepath.ToSlash(relative)
		if !validStateManifestPath(normalized) {
			return stateManifestError("invalid file path")
		}
		size, digest, err := hashStateManifestFile(currentPath)
		if err != nil {
			return err
		}
		files = append(files, StateManifestFile{Path: normalized, Size: size, SHA256: digest})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, stateManifestError("source root is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func hashStateManifestFile(path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", stateManifestError("file read failed")
	}
	digest := sha256.New()
	size, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size < 0 {
		return 0, "", stateManifestError("file read failed")
	}
	sum := digest.Sum(nil)
	return size, hex.EncodeToString(sum), nil
}

func sameStateManifestFiles(expected, actual []StateManifestFile) bool {
	if len(expected) != len(actual) {
		return false
	}
	for index := range expected {
		if expected[index] != actual[index] {
			return false
		}
	}
	return true
}

func stateManifestError(message string) error {
	return errors.New("state manifest: " + message)
}
