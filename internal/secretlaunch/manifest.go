package secretlaunch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

const (
	ManifestVersion = "v2"
	MaxKeyLength    = 256
	MaxValueLength  = 1 << 20
	MaxFrameLength  = MaxValueLength + 4096
	MaxManifestTTL  = 15 * time.Minute

	// Heartbeats are a control-channel protocol, not Docker health checks.
	// Keep their deadline comfortably above the cadence so a valid health
	// interval cannot starve the secret channel.
	HeartbeatSafetyFactor  uint32 = 3
	MaxHeartbeatIntervalMS uint32 = 5 * 60 * 1000
	MaxHeartbeatTimeoutMS  uint32 = 15 * 60 * 1000
)

// Manifest is the complete signed launch authority. It contains identities
// and metadata only; secret values are never represented here.
type Manifest struct {
	Version    string             `json:"version"`
	RuntimeID  string             `json:"runtime_id"`
	Role       string             `json:"role"`
	Generation uint64             `json:"generation"`
	IssuedAt   int64              `json:"issued_at"`
	ExpiresAt  int64              `json:"expires_at"`
	Nonce      string             `json:"nonce"`
	Services   []ServiceAuthority `json:"services"`
	Digests    ArtifactDigests    `json:"digests"`
}

type ServiceAuthority struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	User          string            `json:"user"`
	Argv          []string          `json:"argv"`
	Environment   map[string]string `json:"environment"`
	Labels        map[string]string `json:"labels"`
	Networks      []string          `json:"networks"`
	Restart       string            `json:"restart"`
	OpenStdin     bool              `json:"open_stdin"`
	Health        HealthSpec        `json:"health"`
	Dependencies  []string          `json:"dependencies"`
	Keys          []ManifestKey     `json:"keys"`
	WrapperDigest string            `json:"wrapper_digest"`
	Child         ChildSpec         `json:"child"`
}

type ManifestKey struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Env     string `json:"env"`
}
type ChildSpec struct {
	Argv        []string          `json:"argv"`
	User        string            `json:"user"`
	Environment map[string]string `json:"environment"`
}

type HealthSpec struct {
	Command             []string `json:"command"`
	IntervalMS          uint32   `json:"interval_ms"`
	TimeoutMS           uint32   `json:"timeout_ms"`
	Retries             uint32   `json:"retries"`
	HeartbeatIntervalMS uint32   `json:"heartbeat_interval_ms"`
	HeartbeatTimeoutMS  uint32   `json:"heartbeat_timeout_ms"`
}

type ArtifactDigests struct {
	Helper     string `json:"helper"`
	Supervisor string `json:"supervisor"`
	Compose    string `json:"compose"`
}

// SignedManifest is a canonical envelope around a manifest. The signature is
// over the canonical manifest bytes, never over this wrapper's formatting.
type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	KeyID     string   `json:"key_id"`
	Signature string   `json:"signature"`
}

type LaunchBinding struct {
	RuntimeID  string
	Service    string
	Role       string
	Generation uint64
	ExpiresAt  int64
	Nonce      string
}

type TrustPolicy struct {
	AllowedSigningKeys map[string]ed25519.PublicKey
	AllowedVersions    map[string]bool
	AllowedRuntimeIDs  map[string]bool
	AllowedRoles       map[string]bool
	KeyVersions        map[string]map[string]bool
}

type TrustDocument struct {
	Keys        map[string]string          `json:"keys"`
	Versions    []string                   `json:"versions"`
	RuntimeIDs  []string                   `json:"runtime_ids"`
	Roles       []string                   `json:"roles"`
	KeyVersions map[string]map[string]bool `json:"key_versions"`
}

func (m Manifest) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m.canonicalBytesUnchecked()
}

func (m Manifest) canonicalBytesUnchecked() ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fail(ErrCanonical)
	}
	return b, nil
}

func (m Manifest) Digest() ([32]byte, error) {
	var zero [32]byte
	b, err := m.CanonicalBytes()
	if err != nil {
		return zero, err
	}
	return sha256.Sum256(b), nil
}

func (m Manifest) Service(name string) (ServiceAuthority, bool) {
	for i := range m.Services {
		service := &m.Services[i]
		if service.Name == name {
			return *service, true
		}
	}
	return ServiceAuthority{}, false
}

func (m Manifest) MatchBinding(binding LaunchBinding) error {
	if binding.RuntimeID == "" || binding.Service == "" {
		return fail(ErrBinding)
	}
	if m.RuntimeID != binding.RuntimeID {
		return fail(ErrBinding)
	}
	if _, ok := m.Service(binding.Service); !ok {
		return fail(ErrBinding)
	}
	if binding.Role != "" && m.Role != binding.Role {
		return fail(ErrBinding)
	}
	if binding.Generation != 0 && m.Generation != binding.Generation {
		return fail(ErrBinding)
	}
	if binding.ExpiresAt != 0 && m.ExpiresAt != binding.ExpiresAt {
		return fail(ErrBinding)
	}
	if binding.Nonce != "" && m.Nonce != binding.Nonce {
		return fail(ErrBinding)
	}
	return nil
}

func (m Manifest) Validate() error {
	if m.Version != ManifestVersion || !validServiceName(m.RuntimeID) || !validServiceName(m.Role) || m.Generation == 0 {
		return fail(ErrInvalidInput)
	}
	if m.IssuedAt <= 0 || m.ExpiresAt <= m.IssuedAt || m.ExpiresAt-m.IssuedAt > int64(MaxManifestTTL/time.Second) {
		return fail(ErrTTL)
	}
	if !validNonce(m.Nonce) || len(m.Services) == 0 || len(m.Services) > 256 {
		return fail(ErrInvalidInput)
	}
	last := ""
	for i := range m.Services {
		service := &m.Services[i]
		if service.Name <= last || validateServiceAuthority(service) != nil {
			return fail(ErrInvalidInput)
		}
		last = service.Name
	}
	for _, digest := range []string{m.Digests.Helper, m.Digests.Supervisor, m.Digests.Compose} {
		if !validDigest(digest) {
			return fail(ErrInvalidInput)
		}
	}
	return nil
}

func (m Manifest) ValidateAt(now time.Time) error {
	if err := m.Validate(); err != nil {
		return err
	}
	unix := now.Unix()
	if unix < m.IssuedAt {
		return fail(ErrNotYetValid)
	}
	if unix >= m.ExpiresAt {
		return fail(ErrExpired)
	}
	return nil
}

func validateServiceAuthority(service *ServiceAuthority) error {
	if !validServiceName(service.Name) || !pinnedImage(service.Image) || service.User == "" ||
		strings.IndexByte(service.User, 0) >= 0 || service.Restart != "no" || !service.OpenStdin || !validDigest(service.WrapperDigest) {
		return fail(ErrInvalidInput)
	}
	if err := validArguments(service.Argv); err != nil {
		return err
	}
	if len(service.Child.Argv) == 0 || service.Child.User == "" || strings.IndexByte(service.Child.User, 0) >= 0 || validArguments(service.Child.Argv) != nil {
		return fail(ErrInvalidInput)
	}
	if !equalStringMap(service.Child.Environment, service.Environment) {
		return fail(ErrInvalidInput)
	}
	if err := validHealth(service.Health); err != nil {
		return err
	}
	if len(service.Keys) == 0 || len(service.Keys) > 1024 {
		return fail(ErrInvalidInput)
	}
	last := ""
	envNames := make(map[string]struct{}, len(service.Keys))
	for _, key := range service.Keys {
		if !validKeyName(key.Name) || !validProviderVersion(key.Version) || !validEnvName(key.Env) || key.Name <= last {
			return failKey(ErrKey, key.Name)
		}
		if _, collision := service.Environment[key.Env]; collision {
			return failKey(ErrKey, key.Name)
		}
		if _, exists := envNames[key.Env]; exists {
			return failKey(ErrKey, key.Name)
		}
		envNames[key.Env] = struct{}{}
		last = key.Name
	}
	last = ""
	for _, dependency := range service.Dependencies {
		if !validServiceName(dependency) || dependency == service.Name || dependency <= last {
			return fail(ErrInvalidInput)
		}
		last = dependency
	}
	last = ""
	for _, network := range service.Networks {
		if !validServiceName(network) || network <= last {
			return fail(ErrInvalidInput)
		}
		last = network
	}
	for key, value := range service.Environment {
		if !validEnvName(key) || secretLikeName(key) || strings.IndexByte(value, 0) >= 0 {
			return failKey(ErrInvalidInput, key)
		}
	}
	for key, value := range service.Labels {
		if key == "" || strings.HasPrefix(key, "com.skret.secret-launch") || secretLikeName(key) ||
			secretLikeName(value) || strings.IndexByte(key, 0) >= 0 || strings.IndexByte(value, 0) >= 0 {
			return failKey(ErrInvalidInput, key)
		}
	}
	return nil
}

func validArguments(values []string) error {
	if len(values) == 0 || len(values) > 1024 {
		return fail(ErrInvalidInput)
	}
	for _, value := range values {
		if value == "" || strings.IndexByte(value, 0) >= 0 {
			return fail(ErrInvalidInput)
		}
	}
	return nil
}

func validHealth(health HealthSpec) error {
	if health.IntervalMS == 0 || health.TimeoutMS == 0 || health.Retries == 0 {
		return fail(ErrInvalidInput)
	}
	if health.HeartbeatIntervalMS == 0 ||
		health.HeartbeatTimeoutMS == 0 ||
		health.HeartbeatIntervalMS > MaxHeartbeatIntervalMS ||
		health.HeartbeatTimeoutMS > MaxHeartbeatTimeoutMS ||
		health.HeartbeatIntervalMS > ^uint32(0)/HeartbeatSafetyFactor ||
		health.HeartbeatTimeoutMS < health.HeartbeatIntervalMS*HeartbeatSafetyFactor {
		return fail(ErrInvalidInput)
	}
	return validArguments(health.Command)
}

func pinnedImage(value string) bool {
	prefix, digest, ok := strings.Cut(value, "@")
	return ok && prefix != "" && validDigest(digest)
}

func ValidateTrustPolicy(policy TrustPolicy) error {
	if len(policy.AllowedSigningKeys) == 0 || len(policy.AllowedVersions) == 0 ||
		len(policy.AllowedRuntimeIDs) == 0 || len(policy.AllowedRoles) == 0 || len(policy.KeyVersions) == 0 {
		return fail(ErrTrust)
	}
	for keyID, key := range policy.AllowedSigningKeys {
		if keyID == "" || len(key) != ed25519.PublicKeySize {
			return fail(ErrTrust)
		}
	}
	return nil
}

func VerifyManifest(manifest Manifest, signature []byte, keyID string, policy TrustPolicy, now time.Time) error {
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		return err
	}
	if err := manifest.ValidateAt(now); err != nil {
		return err
	}
	if err := ValidateTrustPolicy(policy); err != nil {
		return err
	}
	public, ok := policy.AllowedSigningKeys[keyID]
	if !ok || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, canonical, signature) {
		return fail(ErrSignature)
	}
	if !policy.AllowedVersions[manifest.Version] || !policy.AllowedRuntimeIDs[manifest.RuntimeID] || !policy.AllowedRoles[manifest.Role] {
		return fail(ErrTrust)
	}
	for i := range manifest.Services {
		service := &manifest.Services[i]
		for _, key := range service.Keys {
			versions, ok := policy.KeyVersions[key.Name]
			if !ok || !versions[key.Version] {
				return failKey(ErrKey, key.Name)
			}
		}
	}
	return nil
}

func SignManifest(manifest Manifest, keyID string, private ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize || keyID == "" {
		return nil, fail(ErrInvalidInput)
	}
	if err := manifest.ValidateAt(now); err != nil {
		return nil, err
	}
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		return nil, err
	}
	signed := SignedManifest{
		Manifest:  manifest,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical)),
	}
	return json.Marshal(signed)
}

func ParseManifest(data []byte) (Manifest, error) {
	if err := validateJSONObject(data); err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fail(ErrUnknownField)
	}
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil || !bytes.Equal(canonical, data) {
		return Manifest{}, fail(ErrCanonical)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ParseSignedManifest(data []byte) (SignedManifest, error) {
	if err := validateJSONObject(data); err != nil {
		return SignedManifest{}, err
	}
	var signed SignedManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedManifest{}, fail(ErrUnknownField)
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, data) {
		return SignedManifest{}, fail(ErrCanonical)
	}
	manifestBytes, err := signed.Manifest.canonicalBytesUnchecked()
	if err != nil {
		return SignedManifest{}, err
	}
	if _, err := ParseManifest(manifestBytes); err != nil {
		return SignedManifest{}, err
	}
	if signed.KeyID == "" || signed.Signature == "" {
		return SignedManifest{}, fail(ErrSignature)
	}
	return signed, nil
}

func VerifySignedManifest(data []byte, policy TrustPolicy, now time.Time) (Manifest, error) {
	signed, err := ParseSignedManifest(data)
	if err != nil {
		return Manifest{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Manifest{}, fail(ErrSignature)
	}
	if err := VerifyManifest(signed.Manifest, signature, signed.KeyID, policy, now); err != nil {
		return Manifest{}, err
	}
	return signed.Manifest, nil
}

func LoadTrustDocument(data []byte) (TrustPolicy, error) {
	if err := validateJSONObject(data); err != nil {
		return TrustPolicy{}, err
	}
	var document TrustDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return TrustPolicy{}, fail(ErrTrust)
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, data) {
		return TrustPolicy{}, fail(ErrCanonical)
	}
	policy := TrustPolicy{
		AllowedSigningKeys: make(map[string]ed25519.PublicKey, len(document.Keys)),
		AllowedVersions:    boolSet(document.Versions),
		AllowedRuntimeIDs:  boolSet(document.RuntimeIDs),
		AllowedRoles:       boolSet(document.Roles),
		KeyVersions:        document.KeyVersions,
	}
	for keyID, encoded := range document.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return TrustPolicy{}, fail(ErrTrust)
		}
		policy.AllowedSigningKeys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	if err := ValidateTrustPolicy(policy); err != nil {
		return TrustPolicy{}, err
	}
	return policy, nil
}

func boolSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	last := ""
	for _, value := range values {
		if value == "" || value <= last {
			return map[string]bool{}
		}
		result[value] = true
		last = value
	}
	return result
}

func mustMarshal(value any) []byte {
	b, _ := json.Marshal(value)
	return b
}

func validNonce(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		alphaNumeric := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !alphaNumeric && !strings.ContainsRune("._~-", r) {
			return false
		}
	}
	return true
}

func validKeyName(value string) bool {
	if value == "" || len(value) > MaxKeyLength {
		return false
	}
	for _, r := range value {
		if r == 0 || r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			return false
		}
	}
	return true
}

func validEnvName(value string) bool {
	if value == "" || len(value) > MaxKeyLength {
		return false
	}
	for i, r := range value {
		firstCharacter := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_'
		subsequentCharacter := firstCharacter || (r >= '0' && r <= '9')
		if (i == 0 && !firstCharacter) || (i > 0 && !subsequentCharacter) {
			return false
		}
	}
	return true
}

func validServiceName(value string) bool {
	if value == "" || len(value) > MaxKeyLength {
		return false
	}
	for _, r := range value {
		valid := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if !valid {
			return false
		}
	}
	return true
}

func equalStringMap(first, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for key, value := range first {
		if second[key] != value {
			return false
		}
	}
	return true
}

func validProviderVersion(value string) bool {
	version, err := strconv.ParseInt(value, 10, 64)
	return err == nil && version > 0 && strconv.FormatInt(version, 10) == value
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		valid := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !valid {
			return false
		}
	}
	return true
}

func validateJSONObject(data []byte) error {
	if len(data) == 0 || !json.Valid(data) {
		return fail(ErrCanonical)
	}
	scanner := jsonScanner{data: data}
	if err := scanner.value(); err != nil {
		return err
	}
	scanner.space()
	if scanner.pos != len(data) {
		return fail(ErrCanonical)
	}
	if data[scanner.firstNonSpace()] != '{' {
		return fail(ErrInvalidInput)
	}
	return nil
}

type jsonScanner struct {
	data []byte
	pos  int
}

func (s *jsonScanner) firstNonSpace() int {
	for i, b := range s.data {
		if !isJSONSpace(b) {
			return i
		}
	}
	return len(s.data)
}

func (s *jsonScanner) space() {
	for s.pos < len(s.data) && isJSONSpace(s.data[s.pos]) {
		s.pos++
	}
}

func (s *jsonScanner) value() error {
	s.space()
	if s.pos >= len(s.data) {
		return fail(ErrCanonical)
	}
	switch s.data[s.pos] {
	case '{':
		return s.object()
	case '[':
		return s.array()
	case '"':
		_, err := s.string()
		return err
	case 't':
		return s.literal("true")
	case 'f':
		return s.literal("false")
	case 'n':
		return s.literal("null")
	default:
		return s.number()
	}
}

func (s *jsonScanner) object() error {
	s.pos++
	s.space()
	seen := map[string]struct{}{}
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		return nil
	}
	for {
		s.space()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return fail(ErrCanonical)
		}
		key, err := s.string()
		if err != nil {
			return err
		}
		if _, ok := seen[key]; ok {
			return failKey(ErrDuplicateField, key)
		}
		seen[key] = struct{}{}
		s.space()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return fail(ErrCanonical)
		}
		s.pos++
		if err := s.value(); err != nil {
			return err
		}
		s.space()
		if s.pos >= len(s.data) {
			return fail(ErrCanonical)
		}
		if s.data[s.pos] == '}' {
			s.pos++
			return nil
		}
		if s.data[s.pos] != ',' {
			return fail(ErrCanonical)
		}
		s.pos++
	}
}

func (s *jsonScanner) array() error {
	s.pos++
	s.space()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		return nil
	}
	for {
		if err := s.value(); err != nil {
			return err
		}
		s.space()
		if s.pos >= len(s.data) {
			return fail(ErrCanonical)
		}
		if s.data[s.pos] == ']' {
			s.pos++
			return nil
		}
		if s.data[s.pos] != ',' {
			return fail(ErrCanonical)
		}
		s.pos++
		s.space()
	}
}

func (s *jsonScanner) string() (string, error) {
	start := s.pos
	s.pos++
	for s.pos < len(s.data) {
		if s.data[s.pos] == '\\' {
			s.pos += 2
			continue
		}
		if s.data[s.pos] == '"' {
			s.pos++
			var value string
			if err := json.Unmarshal(s.data[start:s.pos], &value); err != nil {
				return "", fail(ErrCanonical)
			}
			return value, nil
		}
		s.pos++
	}
	return "", fail(ErrCanonical)
}

func (s *jsonScanner) literal(literal string) error {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(literal)) {
		return fail(ErrCanonical)
	}
	s.pos += len(literal)
	return nil
}

func (s *jsonScanner) number() error {
	start := s.pos
	for s.pos < len(s.data) {
		b := s.data[s.pos]
		if b == ',' || b == ']' || b == '}' || isJSONSpace(b) {
			break
		}
		s.pos++
	}
	if start == s.pos {
		return fail(ErrCanonical)
	}
	if _, err := strconv.ParseFloat(string(s.data[start:s.pos]), 64); err != nil {
		return fail(ErrCanonical)
	}
	return nil
}

func isJSONSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}
