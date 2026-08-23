package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	to              string
	stateManifest   string
	journal         string
	state           string
	publicKey       string
	role            string
	audience        string
	operationID     string
	execute         bool
	remoteExecute   bool
	executorURL     string
	operatorSession string
	signingKey      string
	format          string
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
	ResponseHash   string `json:"response_hash,omitempty"`
	ResponseSize   int64  `json:"response_size,omitempty"`
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
state file to v2. Without --execute or --remote-execute this command only
verifies the manifest and source hash; it never writes state, backup, or journal
files. The --execute path performs the verified local migration offline and
does not submit an executor request. The --remote-execute path submits only a
metadata request to the authenticated Hub executor-envelope route and never
mutates local state.`,
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
	flags.StringVar(&o.operationID, "operation-id", "", "operation identifier for --execute or --remote-execute")
	flags.BoolVar(&o.execute, "execute", false, "perform the verified local v1-to-v2 migration offline")
	flags.BoolVar(&o.remoteExecute, "remote-execute", false, "submit a signed metadata-only migration request to Hub; never mutate local state")
	flags.StringVar(&o.executorURL, "executor-url", "", "Hub origin for --remote-execute")
	flags.StringVar(&o.operatorSession, "operator-session", "", "operator session cookie for --remote-execute [env: SKRET_OPERATOR_SESSION_COOKIE]")
	flags.StringVar(&o.signingKey, "signing-key", "", "path containing a raw or hex Ed25519 private signing key for --remote-execute")
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
	if o.remoteExecute {
		if o.execute {
			return syncStateMigrateValidationError("--execute and --remote-execute are mutually exclusive")
		}
		if strings.TrimSpace(o.role) == "" {
			return syncStateMigrateValidationError("--role is required with --remote-execute")
		}
		if strings.TrimSpace(o.audience) == "" {
			return syncStateMigrateValidationError("--audience is required with --remote-execute")
		}
		if err := validateCLIStateMigrationOperationID(o.operationID); err != nil {
			return syncStateMigrateValidationError("invalid --operation-id")
		}
		if strings.TrimSpace(o.executorURL) == "" {
			return syncStateMigrateValidationError("--executor-url is required with --remote-execute")
		}
		if strings.TrimSpace(o.operatorSession) == "" && strings.TrimSpace(os.Getenv("SKRET_OPERATOR_SESSION_COOKIE")) == "" {
			return syncStateMigrateValidationError("--operator-session or SKRET_OPERATOR_SESSION_COOKIE is required with --remote-execute")
		}
		if strings.TrimSpace(o.signingKey) == "" {
			return syncStateMigrateValidationError("--signing-key is required with --remote-execute")
		}
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

	var (
		signingKey      ed25519.PrivateKey
		operatorSession string
		err             error
	)
	if o.remoteExecute {
		signingKey, err = readCLIStateMigrationPrivateKey(o.signingKey)
		if err != nil {
			return syncStateMigrateError("read signing key", err)
		}
		operatorSession = o.operatorSession
		if operatorSession == "" {
			operatorSession = os.Getenv("SKRET_OPERATOR_SESSION_COOKIE")
		}
	}

	manifest, stateManifestBytes, err := readCLIStateManifestWithBytes(o.stateManifest)
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
	if o.remoteExecute {
		response, err := submitCLIStateMigrationRequest(
			cmd,
			o.executorURL,
			operatorSession,
			signingKey,
			manifestDigest,
			stateManifestBytes,
			role,
			audience,
			o.operationID,
			statePath,
			journalPath,
			o.to,
			sourceHash,
			int64(len(source)),
			now,
		)
		if err != nil {
			return syncStateMigrateError("submit remote executor request", err)
		}
		result.Phase = "submitted"
		result.ResponseHash = cliStateMigrationHash(response)
		result.ResponseSize = int64(len(response))
	}
	return writeCLIStateMigrationResult(cmd, result, o.format)
}

func readCLIStateManifest(path string) (*syncer.StateManifest, error) {
	manifest, _, err := readCLIStateManifestWithBytes(path)
	return manifest, err
}

func readCLIStateManifestWithBytes(path string) (*syncer.StateManifest, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if err := detectJSONDuplicateKeys(data); err != nil {
		return nil, nil, err
	}
	var manifest syncer.StateManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, nil, errors.New("invalid state manifest JSON")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("state manifest contains trailing data")
	}
	if err := validateCLIStateManifestSignature(data); err != nil {
		return nil, nil, err
	}
	return &manifest, data, nil
}

func detectJSONDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		isObject     bool
		expectingKey bool
		keys         map[string]struct{}
	}
	var stack []frame

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("invalid state manifest JSON")
		}

		if len(stack) == 0 {
			switch delim := tok.(type) {
			case json.Delim:
				if delim == '{' {
					stack = append(stack, frame{isObject: true, expectingKey: true, keys: make(map[string]struct{})})
				} else if delim == '[' {
					stack = append(stack, frame{isObject: false})
				} else {
					return errors.New("invalid state manifest JSON")
				}
			default:
				// Primitive root token
			}
			continue
		}

		top := &stack[len(stack)-1]
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if top.isObject {
					if top.expectingKey {
						return errors.New("invalid state manifest JSON")
					}
					top.expectingKey = true
				}
				stack = append(stack, frame{isObject: true, expectingKey: true, keys: make(map[string]struct{})})
			case '[':
				if top.isObject {
					if top.expectingKey {
						return errors.New("invalid state manifest JSON")
					}
					top.expectingKey = true
				}
				stack = append(stack, frame{isObject: false})
			case '}':
				if !top.isObject || !top.expectingKey {
					return errors.New("invalid state manifest JSON")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].isObject {
					stack[len(stack)-1].expectingKey = true
				}
			case ']':
				if top.isObject {
					return errors.New("invalid state manifest JSON")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].isObject {
					stack[len(stack)-1].expectingKey = true
				}
			}
		default:
			if top.isObject {
				if top.expectingKey {
					key, ok := t.(string)
					if !ok {
						return errors.New("invalid state manifest JSON")
					}
					if _, exists := top.keys[key]; exists {
						return errors.New("state manifest contains duplicate JSON keys")
					}
					top.keys[key] = struct{}{}
					top.expectingKey = false
				} else {
					top.expectingKey = true
				}
			}
		}
	}

	if len(stack) != 0 {
		return errors.New("invalid state manifest JSON")
	}
	return nil
}

func validateCLIStateManifestSignature(data []byte) error {
	var raw struct {
		Signature *string `json:"signature"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil || raw.Signature == nil {
		return errors.New("invalid state manifest JSON")
	}
	sig := *raw.Signature
	if len(sig) != 88 || !strings.HasSuffix(sig, "==") {
		return errors.New("state manifest signature is not canonical standard base64")
	}
	for i := range 86 {
		c := sig[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
			return errors.New("state manifest signature is not canonical standard base64")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return errors.New("state manifest signature is invalid")
	}
	if base64.StdEncoding.EncodeToString(decoded) != sig {
		return errors.New("state manifest signature is not canonical standard base64")
	}
	return nil
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

func readCLIStateMigrationPrivateKey(path string) (ed25519.PrivateKey, error) {
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return nil, errors.New("signing key path is required")
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return nil, errors.New("signing key must be a regular file path")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("signing key path is not a regular file")
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		return nil, errors.New("read signing key file failed")
	}
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), data...)), nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key must contain a raw or hex Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
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

type cliStateMigrationRequest struct {
	OperationID    string `json:"operation_id"`
	StatePath      string `json:"state_path"`
	JournalPath    string `json:"journal_path"`
	ManifestDigest string `json:"manifest_digest"`
	Target         string `json:"target"`
	SourceHash     string `json:"source_hash"`
	SourceSize     int64  `json:"source_size"`
	StateManifest  []byte `json:"state_manifest"`
}

func submitCLIStateMigrationRequest(
	cmd *cobra.Command,
	executorURL, operatorSession string,
	signingKey ed25519.PrivateKey,
	manifestDigest string,
	stateManifest []byte,
	role, audience, operationID, statePath, journalPath, target, sourceHash string,
	sourceSize int64,
	now time.Time,
) ([]byte, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, errors.New("generate executor request nonce failed")
	}
	body, err := json.Marshal(cliStateMigrationRequest{
		OperationID:    operationID,
		StatePath:      statePath,
		JournalPath:    journalPath,
		ManifestDigest: manifestDigest,
		Target:         target,
		SourceHash:     sourceHash,
		SourceSize:     sourceSize,
		StateManifest:  stateManifest,
	})
	if err != nil {
		return nil, errors.New("encode executor migration request failed")
	}
	client := syncer.NewEnvelopeClient(executorURL, signingKey)
	client.OperatorSessionCookie = operatorSession
	client.Clock = func() time.Time { return now }
	return client.Submit(
		cmd.Context(),
		manifestDigest,
		role,
		audience,
		hex.EncodeToString(nonceBytes),
		now.Add(5*time.Minute),
		body,
	)
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
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "desired_hash: %s\ndesired_size: %d\n", result.DesiredHash, result.DesiredSize); err != nil {
			return err
		}
	}
	if result.ResponseHash != "" {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "response_hash: %s\nresponse_size: %d\n", result.ResponseHash, result.ResponseSize)
	}
	return err
}

func syncStateMigrateValidationError(format string, args ...interface{}) error {
	return skret.NewError(skret.ExitValidationError, "sync-state migrate: "+fmt.Sprintf(format, args...), nil)
}

func syncStateMigrateError(operation string, err error) error {
	return skret.NewError(skret.ExitGenericError, "sync-state migrate: "+operation, err)
}
