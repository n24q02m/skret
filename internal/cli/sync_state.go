package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

type syncStateMigrateOptions struct {
	to            string
	stateManifest string
	journal       string
	state         string
	publicKey     string
	role          string
	audience      string
	operationID   string
	execute       bool
	format        string
}

type syncStateMigrateResult struct {
	Target         string `json:"target"`
	Phase          string `json:"phase"`
	StatePath      string `json:"state_path"`
	BackupPath     string `json:"backup_path,omitempty"`
	JournalPath    string `json:"journal_path"`
	ManifestDigest string `json:"manifest_digest"`
	SourceHash     string `json:"source_hash"`
	SourceSize     int64  `json:"source_size"`
	DesiredHash    string `json:"desired_hash,omitempty"`
	DesiredSize    int64  `json:"desired_size,omitempty"`
}

func newSyncStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync-state",
		Short: "Inspect and migrate local sync state",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newSyncStateMigrateCmd())
	return cmd
}

func newSyncStateMigrateCmd() *cobra.Command {
	o := &syncStateMigrateOptions{}
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate one signed local sync-state file to v2",
		Long: `Verify a signed, value-free state manifest and migrate one local v1
state file to v2. Without --execute this command only verifies the manifest and
source hash; it never writes state, backup, or journal files. The execute path
performs the verified local migration and does not submit an executor request.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&o.to, "to", "v2", "migration target (only v2 is supported)")
	flags.StringVar(&o.stateManifest, "state-manifest", "", "path to the signed state manifest")
	flags.StringVar(&o.journal, "journal", "", "path for the migration journal")
	flags.StringVar(&o.state, "state", "", "state file path or manifest-relative file row (optional when the manifest has exactly one file)")
	flags.StringVar(&o.publicKey, "public-key", "", "Ed25519 public key as hex or a path containing raw/hex key bytes")
	flags.StringVar(&o.role, "role", "", "expected manifest role")
	flags.StringVar(&o.audience, "audience", "", "expected manifest audience")
	flags.StringVar(&o.operationID, "operation-id", "", "operation identifier for --execute")
	flags.BoolVar(&o.execute, "execute", false, "perform the verified local v1-to-v2 migration")
	flags.StringVar(&o.format, "format", "table", "output format (table, json)")
	return cmd
}

func (o *syncStateMigrateOptions) run(cmd *cobra.Command) error {
	if o.to != "v2" {
		return syncStateMigrateValidationError("unsupported migration target; only v2 is supported")
	}
	if o.format != "table" && o.format != "json" {
		return syncStateMigrateValidationError("invalid format %q; expected table or json", o.format)
	}
	if strings.TrimSpace(o.stateManifest) == "" {
		return syncStateMigrateValidationError("--state-manifest is required")
	}
	if strings.TrimSpace(o.journal) == "" {
		return syncStateMigrateValidationError("--journal is required")
	}
	if strings.TrimSpace(o.publicKey) == "" {
		return syncStateMigrateValidationError("--public-key is required")
	}
	if o.execute {
		if strings.TrimSpace(o.role) == "" {
			return syncStateMigrateValidationError("--role is required with --execute")
		}
		if strings.TrimSpace(o.audience) == "" {
			return syncStateMigrateValidationError("--audience is required with --execute")
		}
		if err := validateCLIStateMigrationOperationID(o.operationID); err != nil {
			return syncStateMigrateValidationError("invalid --operation-id")
		}
	}

	manifest, err := readCLIStateManifest(o.stateManifest)
	if err != nil {
		return syncStateMigrateError("read state manifest", err)
	}
	publicKey, err := readCLIStateMigrationPublicKey(o.publicKey)
	if err != nil {
		return syncStateMigrateError("read public key", err)
	}
	role := strings.TrimSpace(o.role)
	if role == "" {
		role = manifest.Role
	}
	audience := strings.TrimSpace(o.audience)
	if audience == "" {
		audience = manifest.Audience
	}
	statePath, row, err := resolveCLIStateMigrationPath(manifest, o.state)
	if err != nil {
		return syncStateMigrateError("resolve state path", err)
	}
	journalPath, err := normalizeCLIStateMigrationPath(o.journal)
	if err != nil {
		return syncStateMigrateError("resolve journal path", err)
	}

	now := time.Now().UTC()
	if o.execute {
		if err := syncer.MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, role, audience, o.operationID, now); err != nil {
			return syncStateMigrateError("execute state migration", err)
		}
		journal, err := readCLIStateMigrationJournal(journalPath)
		if err != nil {
			return syncStateMigrateError("read committed migration journal", err)
		}
		if journal.Phase != syncer.StateMigrationPhaseCommitted {
			return syncStateMigrateValidationError("migration did not reach committed phase")
		}
		result := syncStateMigrateResult{
			Target:         o.to,
			Phase:          string(journal.Phase),
			StatePath:      journal.SourcePath,
			BackupPath:     journal.BackupPath,
			JournalPath:    journal.JournalPath,
			ManifestDigest: journal.ManifestDigest,
			SourceHash:     journal.SourceHash,
			SourceSize:     journal.SourceSize,
			DesiredHash:    journal.DesiredHash,
			DesiredSize:    journal.DesiredSize,
		}
		return writeCLIStateMigrationResult(cmd, result, o.format)
	}

	if err := syncer.VerifyStateManifest(manifest, manifest.SourceRoot, role, audience, publicKey, now); err != nil {
		return syncStateMigrateError("verify state manifest", err)
	}
	source, err := readCLIStateMigrationSource(statePath)
	if err != nil {
		return syncStateMigrateError("read source state", err)
	}
	sourceHash := cliStateMigrationHash(source)
	if int64(len(source)) != row.Size || sourceHash != row.SHA256 {
		return syncStateMigrateValidationError("source hash or size does not match manifest")
	}
	manifestDigest, err := cliStateMigrationManifestDigest(manifest)
	if err != nil {
		return syncStateMigrateError("digest state manifest", err)
	}
	result := syncStateMigrateResult{
		Target:         o.to,
		Phase:          "verified",
		StatePath:      statePath,
		JournalPath:    journalPath,
		ManifestDigest: manifestDigest,
		SourceHash:     sourceHash,
		SourceSize:     int64(len(source)),
	}
	return writeCLIStateMigrationResult(cmd, result, o.format)
}

func readCLIStateManifest(path string) (*syncer.StateManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest syncer.StateManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&manifest); err != nil {
		return nil, errors.New("invalid state manifest JSON")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("state manifest contains trailing data")
	}
	return &manifest, nil
}

func readCLIStateMigrationPublicKey(value string) (ed25519.PublicKey, error) {
	candidate := strings.TrimSpace(value)
	if decoded, ok := decodeCLIStateMigrationPublicKeyHex(candidate); ok {
		return ed25519.PublicKey(decoded), nil
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return nil, errors.New("public key must be Ed25519 hex or a regular file path")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("public key path is not a regular file")
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		return nil, errors.New("read public key file failed")
	}
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), data...)), nil
	}
	if decoded, ok := decodeCLIStateMigrationPublicKeyHex(strings.TrimSpace(string(data))); ok {
		return ed25519.PublicKey(decoded), nil
	}
	return nil, errors.New("public key must contain a raw or hex Ed25519 public key")
}

func decodeCLIStateMigrationPublicKeyHex(value string) ([]byte, bool) {
	if len(value) != ed25519.PublicKeySize*2 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, false
	}
	return decoded, true
}

func resolveCLIStateMigrationPath(manifest *syncer.StateManifest, requested string) (string, syncer.StateManifestFile, error) {
	if manifest == nil {
		return "", syncer.StateManifestFile{}, errors.New("missing state manifest")
	}
	root := filepath.Clean(manifest.SourceRoot)
	if root == "." || !filepath.IsAbs(root) {
		return "", syncer.StateManifestFile{}, errors.New("manifest source root is not absolute")
	}

	rowPath := ""
	if strings.TrimSpace(requested) == "" {
		if len(manifest.Files) != 1 {
			return "", syncer.StateManifestFile{}, errors.New("--state is required unless manifest contains exactly one file")
		}
		rowPath = manifest.Files[0].Path
	} else {
		input := filepath.FromSlash(requested)
		cleanInput := filepath.Clean(input)
		if strings.ContainsRune(input, 0) || cleanInput != input {
			return "", syncer.StateManifestFile{}, errors.New("state path contains traversal or non-canonical components")
		}
		if filepath.IsAbs(input) {
			rel, err := filepath.Rel(root, input)
			if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", syncer.StateManifestFile{}, errors.New("state path escapes manifest root")
			}
			rowPath = filepath.ToSlash(rel)
		} else {
			if input == "." || strings.HasPrefix(input, ".."+string(filepath.Separator)) {
				return "", syncer.StateManifestFile{}, errors.New("state path escapes manifest root")
			}
			rowPath = filepath.ToSlash(input)
		}
	}

	var matched syncer.StateManifestFile
	matches := 0
	for _, row := range manifest.Files {
		if row.Path == rowPath {
			matched = row
			matches++
		}
	}
	if matches != 1 {
		if matches == 0 {
			return "", syncer.StateManifestFile{}, errors.New("state path is not an exact manifest file row")
		}
		return "", syncer.StateManifestFile{}, errors.New("state path matches ambiguous manifest rows")
	}
	statePath := filepath.Join(root, filepath.FromSlash(matched.Path))
	if filepath.Clean(statePath) != statePath {
		return "", syncer.StateManifestFile{}, errors.New("manifest state row escapes source root")
	}
	return statePath, matched, nil
}

func normalizeCLIStateMigrationPath(path string) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", errors.New("path contains NUL")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("path is not resolvable")
	}
	if filepath.Clean(absolute) != absolute {
		return "", errors.New("path is not canonical")
	}
	return absolute, nil
}

func readCLIStateMigrationSource(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("state path is not a regular file")
	}
	return os.ReadFile(path)
}

func readCLIStateMigrationJournal(path string) (*syncer.StateMigrationJournal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var journal syncer.StateMigrationJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return nil, errors.New("invalid migration journal JSON")
	}
	return &journal, nil
}

func cliStateMigrationHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func cliStateMigrationManifestDigest(manifest *syncer.StateManifest) (string, error) {
	canonical, err := manifest.CanonicalSigningBytes()
	if err != nil {
		return "", err
	}
	return "sha256:" + cliStateMigrationHash(canonical), nil
}

func validateCLIStateMigrationOperationID(value string) error {
	if value == "" || value == "." || value == ".." || len(value) > 128 || strings.TrimSpace(value) != value {
		return errors.New("invalid operation id")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return errors.New("invalid operation id")
	}
	return nil
}

func writeCLIStateMigrationResult(cmd *cobra.Command, result syncStateMigrateResult, format string) error {
	if format == "json" {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return syncStateMigrateError("encode result", err)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
		return err
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(),
		"target: %s\nphase: %s\nstate_path: %s\n", result.Target, result.Phase, result.StatePath)
	if err != nil {
		return err
	}
	if result.BackupPath != "" {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "backup_path: %s\n", result.BackupPath); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(),
		"journal_path: %s\nmanifest_digest: %s\nsource_hash: %s\nsource_size: %d\n",
		result.JournalPath, result.ManifestDigest, result.SourceHash, result.SourceSize); err != nil {
		return err
	}
	if result.DesiredHash != "" {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "desired_hash: %s\ndesired_size: %d\n", result.DesiredHash, result.DesiredSize)
	}
	return err
}

func syncStateMigrateValidationError(format string, args ...interface{}) error {
	return skret.NewError(skret.ExitValidationError, "sync-state migrate: "+fmt.Sprintf(format, args...), nil)
}

func syncStateMigrateError(operation string, err error) error {
	return skret.NewError(skret.ExitGenericError, "sync-state migrate: "+operation, err)
}
