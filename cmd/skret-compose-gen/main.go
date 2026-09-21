// Command skret-compose-gen generates the three signed secret-launch artifacts
// consumed by skret-compose-supervisor: a signed manifest, a trust document,
// and a canonical rendered model. It reads a resolved docker-compose file
// (run `docker compose config` first so interpolation is already expanded),
// converts each selected service into a ServiceAuthority, binds the model
// digest into the manifest, and signs the manifest with an Ed25519 key.
//
// The tool never contacts Docker, a provider, or a VM; it is an offline
// signer. Every artifact is written byte-exact canonical JSON so the
// supervisor's DisallowUnknownFields + re-encode equality checks pass.
package main

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/n24q02m/skret/internal/secretlaunch"
)

// repeatedFlag collects repeatable flag values.
type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type options struct {
	composePath   string
	services      string
	runtimeID     string
	outDir        string
	manifestRole  string
	signKeyID     string
	generation    uint64
	ttl           time.Duration
	now           int64
	nonce         string
	helperDigest  string
	superDigest   string
	defaultUser   string
	helperPath    string
	manifestPath  string
	trustPath     string
	secretVersion string
	healthCmd     string
	healthInt     time.Duration
	healthTO      time.Duration
	healthRetries uint
	hbInterval    time.Duration
	hbTimeout     time.Duration

	keys           repeatedFlag
	pubkeys        repeatedFlag
	roles          repeatedFlag
	runtimeIDs     repeatedFlag
	wrapperDigests repeatedFlag
	images         repeatedFlag
	secrets        repeatedFlag
	childArgv      repeatedFlag
	childUser      repeatedFlag
	healthCmds     repeatedFlag
	keyVersions    repeatedFlag
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, diagnostics io.Writer) int {
	var opt options
	flags := flag.NewFlagSet("skret-compose-gen", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	flags.StringVar(&opt.composePath, "compose", "", "resolved docker-compose YAML path (required)")
	flags.StringVar(&opt.services, "services", "", "comma-separated service names to include (required)")
	flags.StringVar(&opt.runtimeID, "runtime", "", "runtime binding, e.g. oci-vm-prod (required)")
	flags.StringVar(&opt.outDir, "out", "", "output directory for manifest.json, trust.json, model.json (required)")
	flags.Var(&opt.keys, "key", "Ed25519 signing key, repeatable: keyID=source or bare source; source is a file path, hex, or base64 (64-byte private key or 32-byte seed)")
	flags.Var(&opt.pubkeys, "pubkey", "trust-only public key, repeatable: keyID=base64")
	flags.Var(&opt.roles, "role", "allowed role for the trust document, repeatable; first value is the manifest role unless --manifest-role is set")
	flags.StringVar(&opt.manifestRole, "manifest-role", "", "manifest role override (default: first --role)")
	flags.Var(&opt.runtimeIDs, "runtime-id", "additional allowed runtime_id for the trust document, repeatable")
	flags.StringVar(&opt.signKeyID, "sign-key", "", "key ID that signs the manifest (default: first --key)")
	flags.Uint64Var(&opt.generation, "generation", 0, "manifest generation (default: --now unix seconds)")
	flags.DurationVar(&opt.ttl, "ttl", 10*time.Minute, "manifest validity window (max 15m)")
	flags.Int64Var(&opt.now, "now", 0, "issue time as unix seconds (default: current time)")
	flags.StringVar(&opt.nonce, "nonce", "", "manifest nonce (default: random)")
	flags.StringVar(&opt.helperDigest, "helper-digest", "", "sha256:<hex> of the skret-secret-helper binary (required)")
	flags.StringVar(&opt.superDigest, "supervisor-digest", "", "sha256:<hex> of the skret-compose-supervisor binary (required)")
	flags.Var(&opt.wrapperDigests, "wrapper-digest", "wrapper image digest, repeatable: sha256:<hex> for all services or service=sha256:<hex>")
	flags.Var(&opt.images, "image", "digest-pinned image override, repeatable: service=image@sha256:<hex>")
	flags.StringVar(&opt.defaultUser, "default-user", "root", "container user when the compose service sets none")
	flags.StringVar(&opt.helperPath, "helper-path", "/usr/local/bin/skret-secret-helper", "helper binary path inside the wrapper image")
	flags.StringVar(&opt.manifestPath, "manifest-path", "", "manifest path inside the wrapper image (default /etc/skret/secret-launch/<runtime>.manifest.json)")
	flags.StringVar(&opt.trustPath, "trust-path", "", "trust path inside the wrapper image (default /etc/skret/secret-launch/<runtime>.trust.json)")
	flags.Var(&opt.secrets, "secret", "secret key mapping, repeatable: service=ENV=NAME[:VERSION] (NAME is the provider key, ENV the injected variable)")
	flags.StringVar(&opt.secretVersion, "secret-version", "1", "provider version for auto-detected secret environment entries")
	flags.Var(&opt.childArgv, "child-argv", "child argv override, repeatable: service=<json array>")
	flags.Var(&opt.childUser, "child-user", "child user override, repeatable: service=user (default: service user)")
	flags.Var(&opt.healthCmds, "health-cmd", "health check command override, repeatable: service=<json array>")
	flags.StringVar(&opt.healthCmd, "default-health-cmd", "/bin/true", "health check command when the compose service sets none")
	flags.DurationVar(&opt.healthInt, "health-interval", 30*time.Second, "default health check interval")
	flags.DurationVar(&opt.healthTO, "health-timeout", 5*time.Second, "default health check timeout")
	flags.UintVar(&opt.healthRetries, "health-retries", 3, "default health check retries")
	flags.DurationVar(&opt.hbInterval, "heartbeat-interval", time.Second, "secret-channel heartbeat interval")
	flags.DurationVar(&opt.hbTimeout, "heartbeat-timeout", 5*time.Second, "secret-channel heartbeat timeout (>= 3x interval)")
	flags.Var(&opt.keyVersions, "key-version", "extra allowed provider key version, repeatable: NAME=VERSION")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if err := generate(&opt, stdout); err != nil {
		fmt.Fprintln(diagnostics, "compose-gen:", err)
		return 1
	}
	return 0
}

func generate(opt *options, stdout io.Writer) error {
	if opt.composePath == "" || opt.services == "" || opt.runtimeID == "" || opt.outDir == "" {
		return fmt.Errorf("--compose, --services, --runtime, and --out are required")
	}
	if !validDigest(opt.helperDigest) || !validDigest(opt.superDigest) {
		return fmt.Errorf("--helper-digest and --supervisor-digest must be sha256:<64 lowercase hex>")
	}
	if len(opt.keys) == 0 {
		return fmt.Errorf("at least one --key signing key is required")
	}
	if len(opt.roles) == 0 && opt.manifestRole == "" {
		return fmt.Errorf("at least one --role (or --manifest-role) is required")
	}
	now := time.Now()
	if opt.now != 0 {
		now = time.Unix(opt.now, 0)
	}
	if opt.ttl <= 0 || opt.ttl > secretlaunch.MaxManifestTTL {
		return fmt.Errorf("--ttl must be in (0, %s]", secretlaunch.MaxManifestTTL)
	}
	if opt.manifestPath == "" {
		opt.manifestPath = "/etc/skret/secret-launch/" + opt.runtimeID + ".manifest.json"
	}
	if opt.trustPath == "" {
		opt.trustPath = "/etc/skret/secret-launch/" + opt.runtimeID + ".trust.json"
	}

	compose, err := loadCompose(opt.composePath)
	if err != nil {
		return err
	}
	selected, err := selectServices(compose, opt.services)
	if err != nil {
		return err
	}
	signing, keyOrder, trustKeys, err := loadKeys(opt.keys, opt.pubkeys)
	if err != nil {
		return err
	}
	signKeyID := opt.signKeyID
	if signKeyID == "" {
		signKeyID = keyOrder[0]
	}
	private, ok := signing[signKeyID]
	if !ok {
		return fmt.Errorf("sign key %q is not among --key entries", signKeyID)
	}

	svcOpts, globalWrapper, err := parseServiceOverrides(opt)
	if err != nil {
		return err
	}
	authorities := make([]secretlaunch.ServiceAuthority, 0, len(selected))
	for _, name := range selected {
		authority, err := buildAuthority(name, compose.Services[name], opt, svcOpts[name], globalWrapper, selected)
		if err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
		authorities = append(authorities, *authority)
	}

	model := secretlaunch.RenderedModel{RuntimeID: opt.runtimeID}
	for i := range authorities {
		model.Services = append(model.Services, specFromAuthority(&authorities[i]))
	}
	digest, err := secretlaunch.ModelDigest(model)
	if err != nil {
		return fmt.Errorf("model digest: %w", err)
	}
	model.ComposeDigest = digest

	role := opt.manifestRole
	if role == "" {
		role = opt.roles[0]
	}
	nonce := opt.nonce
	if nonce == "" {
		nonce = randomNonce()
	}
	generation := opt.generation
	if generation == 0 {
		generation = uint64(now.Unix())
	}
	manifest := secretlaunch.Manifest{
		Version:    secretlaunch.ManifestVersion,
		RuntimeID:  opt.runtimeID,
		Role:       role,
		Generation: generation,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(opt.ttl).Unix(),
		Nonce:      nonce,
		Services:   authorities,
		Digests: secretlaunch.ArtifactDigests{
			Helper:     opt.helperDigest,
			Supervisor: opt.superDigest,
			Compose:    model.ComposeDigest,
		},
	}
	signed, err := secretlaunch.SignManifest(manifest, signKeyID, private, now)
	if err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}

	trust, err := buildTrust(opt, trustKeys, authorities)
	if err != nil {
		return err
	}
	trustBytes, err := json.Marshal(trust)
	if err != nil {
		return fmt.Errorf("trust document: %w", err)
	}
	modelBytes, err := json.Marshal(model)
	if err != nil {
		return fmt.Errorf("model: %w", err)
	}

	if err := os.MkdirAll(opt.outDir, 0o755); err != nil {
		return err
	}
	outputs := map[string][]byte{
		"manifest.json": signed,
		"trust.json":    trustBytes,
		"model.json":    modelBytes,
	}
	for name, data := range outputs {
		if err := os.WriteFile(filepath.Join(opt.outDir, name), data, 0o644); err != nil {
			return err
		}
	}
	if err := selfCheck(opt.outDir, now); err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	fmt.Fprintf(stdout, "wrote %s, %s, %s to %s\n", "manifest.json", "trust.json", "model.json", opt.outDir)
	fmt.Fprintf(stdout, "compose_digest=%s\n", model.ComposeDigest)
	fmt.Fprintln(stdout, "self-check: signed manifest verifies against trust document; model binds to manifest")
	return nil
}

// selfCheck reloads the written artifacts through the exact parse/verify path
// the supervisor uses.
func selfCheck(dir string, now time.Time) error {
	trustBytes, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if err != nil {
		return err
	}
	policy, err := secretlaunch.LoadTrustDocument(trustBytes)
	if err != nil {
		return err
	}
	signed, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	manifest, err := secretlaunch.VerifySignedManifest(signed, policy, now)
	if err != nil {
		return err
	}
	modelBytes, err := os.ReadFile(filepath.Join(dir, "model.json"))
	if err != nil {
		return err
	}
	model, err := secretlaunch.ParseRenderedModel(modelBytes)
	if err != nil {
		return err
	}
	return secretlaunch.ValidateManifestModel(manifest, model)
}

// --- compose parsing -------------------------------------------------------

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Image       string         `yaml:"image"`
	User        string         `yaml:"user"`
	Command     yaml.Node      `yaml:"command"`
	Entrypoint  yaml.Node      `yaml:"entrypoint"`
	Environment yaml.Node      `yaml:"environment"`
	Labels      yaml.Node      `yaml:"labels"`
	Networks    yaml.Node      `yaml:"networks"`
	DependsOn   yaml.Node      `yaml:"depends_on"`
	Restart     string         `yaml:"restart"`
	Healthcheck *composeHealth `yaml:"healthcheck"`
}

type composeHealth struct {
	Test     yaml.Node `yaml:"test"`
	Interval string    `yaml:"interval"`
	Timeout  string    `yaml:"timeout"`
	Retries  uint32    `yaml:"retries"`
	Disable  bool      `yaml:"disable"`
}

func loadCompose(path string) (*composeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var compose composeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, fmt.Errorf("compose parse: %w", err)
	}
	if len(compose.Services) == 0 {
		return nil, fmt.Errorf("compose file declares no services")
	}
	return &compose, nil
}

func selectServices(compose *composeFile, csv string) ([]string, error) {
	var names []string
	for _, name := range strings.Split(csv, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := compose.Services[name]; !ok {
			return nil, fmt.Errorf("service %q not present in compose file", name)
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("--services selected nothing")
	}
	sort.Strings(names)
	return names, nil
}

// stringOrList accepts a scalar or a sequence of scalars.
func stringOrList(node *yaml.Node) ([]string, error) {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return nil, nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return []string{node.Value}, nil
	case yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("expected scalar list item")
			}
			out = append(out, item.Value)
		}
		return out, nil
	}
	return nil, fmt.Errorf("expected scalar or list")
}

// commandOrList accepts a compose command/entrypoint node: a sequence is used
// verbatim; a scalar is wrapped as ["/bin/sh", "-c", value] matching compose
// shell-form semantics.
func commandOrList(node *yaml.Node) ([]string, error) {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind == yaml.ScalarNode {
		return []string{"/bin/sh", "-c", node.Value}, nil
	}
	return stringOrList(node)
}

// mapOrList accepts a mapping or a sequence of KEY=VALUE scalars. When bareOK
// is set, a bare KEY in list form maps to an empty value (label semantics);
// otherwise it is an error (environment semantics).
func mapOrList(node *yaml.Node, bareOK bool) (map[string]string, error) {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return nil, nil
	}
	out := map[string]string{}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if value.Tag == "!!null" {
				if bareOK {
					out[key.Value] = ""
					continue
				}
				return nil, fmt.Errorf("%s has no value; resolve it with `docker compose config` or map it via --secret", key.Value)
			}
			out[key.Value] = value.Value
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("expected KEY=VALUE scalar")
			}
			key, value, found := strings.Cut(item.Value, "=")
			if !found {
				if bareOK {
					out[item.Value] = ""
					continue
				}
				return nil, fmt.Errorf("%s has no value; resolve it with `docker compose config` or map it via --secret", item.Value)
			}
			out[key] = value
		}
	default:
		return nil, fmt.Errorf("expected mapping or KEY=VALUE list")
	}
	return out, nil
}

// listOrMapKeys accepts a sequence or a mapping and returns sorted keys/items.
func listOrMapKeys(node *yaml.Node) ([]string, error) {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return nil, nil
	}
	var out []string
	switch node.Kind {
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("expected scalar list item")
			}
			out = append(out, item.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			out = append(out, node.Content[i].Value)
		}
	default:
		return nil, fmt.Errorf("expected list or mapping")
	}
	sort.Strings(out)
	return out, nil
}

func parseDurationMS(value string) (uint32, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		if seconds, numErr := strconv.ParseFloat(value, 64); numErr == nil {
			d = time.Duration(seconds * float64(time.Second))
		} else {
			return 0, fmt.Errorf("duration %q: %w", value, err)
		}
	}
	if d <= 0 || d > time.Duration(^uint32(0))*time.Millisecond {
		return 0, fmt.Errorf("duration %q out of range", value)
	}
	return uint32(d / time.Millisecond), nil
}

// --- service conversion ----------------------------------------------------

type serviceOverrides struct {
	image     string
	wrapper   string
	childArgv []string
	childUser string
	healthCmd []string
	secrets   []secretlaunch.ManifestKey
}

func parseServiceOverrides(opt *options) (map[string]*serviceOverrides, string, error) {
	out := map[string]*serviceOverrides{}
	get := func(name string) *serviceOverrides {
		if out[name] == nil {
			out[name] = &serviceOverrides{}
		}
		return out[name]
	}
	var globalWrapper string
	for _, entry := range opt.wrapperDigests {
		if name, digest, found := strings.Cut(entry, "="); found && strings.HasPrefix(digest, "sha256:") {
			get(name).wrapper = digest
		} else if strings.HasPrefix(entry, "sha256:") {
			globalWrapper = entry
		} else {
			return nil, "", fmt.Errorf("--wrapper-digest %q: want sha256:<hex> or service=sha256:<hex>", entry)
		}
	}
	for _, entry := range opt.images {
		name, image, found := strings.Cut(entry, "=")
		if !found {
			return nil, "", fmt.Errorf("--image %q: want service=image@sha256:<hex>", entry)
		}
		get(name).image = image
	}
	for _, entry := range opt.childArgv {
		name, raw, found := strings.Cut(entry, "=")
		if !found {
			return nil, "", fmt.Errorf("--child-argv %q: want service=<json array>", entry)
		}
		var argv []string
		if err := json.Unmarshal([]byte(raw), &argv); err != nil || len(argv) == 0 {
			return nil, "", fmt.Errorf("--child-argv %q: invalid json array", entry)
		}
		get(name).childArgv = argv
	}
	for _, entry := range opt.childUser {
		name, user, found := strings.Cut(entry, "=")
		if !found || user == "" {
			return nil, "", fmt.Errorf("--child-user %q: want service=user", entry)
		}
		get(name).childUser = user
	}
	for _, entry := range opt.healthCmds {
		name, raw, found := strings.Cut(entry, "=")
		if !found {
			return nil, "", fmt.Errorf("--health-cmd %q: want service=<json array>", entry)
		}
		var cmd []string
		if err := json.Unmarshal([]byte(raw), &cmd); err != nil || len(cmd) == 0 {
			return nil, "", fmt.Errorf("--health-cmd %q: invalid json array", entry)
		}
		get(name).healthCmd = cmd
	}
	for _, entry := range opt.secrets {
		name, rest, found := strings.Cut(entry, "=")
		if !found {
			return nil, "", fmt.Errorf("--secret %q: want service=ENV=NAME[:VERSION]", entry)
		}
		env, keyName, found := strings.Cut(rest, "=")
		if !found || env == "" || keyName == "" {
			return nil, "", fmt.Errorf("--secret %q: want service=ENV=NAME[:VERSION]", entry)
		}
		key := secretlaunch.ManifestKey{Env: env, Version: opt.secretVersion}
		if keyName, version, hasVersion := strings.Cut(keyName, ":"); hasVersion {
			key.Name, key.Version = keyName, version
		} else {
			key.Name = keyName
		}
		get(name).secrets = append(get(name).secrets, key)
	}
	return out, globalWrapper, nil
}

func buildAuthority(name string, svc composeService, opt *options, ov *serviceOverrides, globalWrapper string, selected []string) (*secretlaunch.ServiceAuthority, error) {
	if ov == nil {
		ov = &serviceOverrides{}
	}
	if ov.wrapper == "" {
		ov.wrapper = globalWrapper
	}
	image := ov.image
	if image == "" {
		image = svc.Image
	}
	prefix, digest, pinned := strings.Cut(image, "@")
	if !pinned || prefix == "" || !validDigest(digest) {
		return nil, fmt.Errorf("image %q is not digest-pinned (want image@sha256:<hex>); override with --image", image)
	}
	user := svc.User
	if user == "" {
		user = opt.defaultUser
	}
	if user == "" {
		return nil, fmt.Errorf("no user; set compose user or --default-user")
	}

	env, err := mapOrList(&svc.Environment, false)
	if err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}
	keys := append([]secretlaunch.ManifestKey(nil), ov.secrets...)
	for key, value := range env {
		if strings.Contains(value, "${") {
			return nil, fmt.Errorf("environment %s still contains interpolation; run `docker compose config` first", key)
		}
		if strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("environment %s contains NUL", key)
		}
		if secretLike(key) {
			keys = append(keys, secretlaunch.ManifestKey{Name: key, Version: opt.secretVersion, Env: key})
			delete(env, key)
		}
	}
	for _, key := range keys {
		delete(env, key.Env)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	if len(keys) == 0 {
		return nil, fmt.Errorf("no secret keys; map at least one via --secret or a secret-named environment entry")
	}

	labels, err := mapOrList(&svc.Labels, true)
	if err != nil {
		return nil, fmt.Errorf("labels: %w", err)
	}
	for key, value := range labels {
		if strings.HasPrefix(key, "com.skret.secret-launch") {
			delete(labels, key)
			continue
		}
		if secretLike(key) || secretLike(value) {
			return nil, fmt.Errorf("label %q looks secret-like; move it to --secret or drop it", key)
		}
	}

	networks, err := listOrMapKeys(&svc.Networks)
	if err != nil {
		return nil, fmt.Errorf("networks: %w", err)
	}
	dependencies, err := listOrMapKeys(&svc.DependsOn)
	if err != nil {
		return nil, fmt.Errorf("depends_on: %w", err)
	}
	inScope := map[string]bool{}
	for _, n := range selected {
		inScope[n] = true
	}
	filtered := dependencies[:0]
	for _, dep := range dependencies {
		if inScope[dep] {
			filtered = append(filtered, dep)
		}
	}
	dependencies = filtered

	health, err := buildHealth(svc.Healthcheck, opt, ov)
	if err != nil {
		return nil, err
	}

	childArgv := ov.childArgv
	if childArgv == nil {
		entrypoint, err := commandOrList(&svc.Entrypoint)
		if err != nil {
			return nil, fmt.Errorf("entrypoint: %w", err)
		}
		command, err := commandOrList(&svc.Command)
		if err != nil {
			return nil, fmt.Errorf("command: %w", err)
		}
		childArgv = append(append([]string(nil), entrypoint...), command...)
	}
	if len(childArgv) == 0 {
		return nil, fmt.Errorf("no child argv; set compose entrypoint/command or --child-argv")
	}
	childUser := ov.childUser
	if childUser == "" {
		childUser = user
	}
	if !validDigest(ov.wrapper) {
		return nil, fmt.Errorf("no valid wrapper digest; pass --wrapper-digest sha256:<hex> or service=sha256:<hex>")
	}

	argv := []string{
		opt.helperPath,
		"--manifest", opt.manifestPath,
		"--trust", opt.trustPath,
		"--runtime", opt.runtimeID,
		"--service", name,
	}
	return &secretlaunch.ServiceAuthority{
		Name:          name,
		Image:         image,
		User:          user,
		Argv:          argv,
		Environment:   env,
		Labels:        labels,
		Networks:      networks,
		Restart:       "no",
		OpenStdin:     true,
		Health:        *health,
		Dependencies:  dependencies,
		Keys:          keys,
		WrapperDigest: ov.wrapper,
		Child: secretlaunch.ChildSpec{
			Argv:        childArgv,
			User:        childUser,
			Environment: env,
		},
	}, nil
}

func buildHealth(hc *composeHealth, opt *options, ov *serviceOverrides) (*secretlaunch.HealthSpec, error) {
	health := &secretlaunch.HealthSpec{
		Command:             []string{opt.healthCmd},
		IntervalMS:          uint32(opt.healthInt / time.Millisecond),
		TimeoutMS:           uint32(opt.healthTO / time.Millisecond),
		Retries:             uint32(opt.healthRetries),
		HeartbeatIntervalMS: uint32(opt.hbInterval / time.Millisecond),
		HeartbeatTimeoutMS:  uint32(opt.hbTimeout / time.Millisecond),
	}
	if hc != nil && !hc.Disable {
		if test, err := stringOrList(&hc.Test); err != nil {
			return nil, fmt.Errorf("healthcheck.test: %w", err)
		} else if len(test) > 0 {
			switch test[0] {
			case "CMD":
				health.Command = append([]string(nil), test[1:]...)
			case "CMD-SHELL":
				health.Command = []string{"/bin/sh", "-c", strings.Join(test[1:], " ")}
			case "NONE":
				// keep default
			default:
				health.Command = append([]string(nil), test...)
			}
			if len(health.Command) == 0 {
				health.Command = []string{opt.healthCmd}
			}
		}
		if ms, err := parseDurationMS(hc.Interval); err != nil {
			return nil, fmt.Errorf("healthcheck.interval: %w", err)
		} else if ms > 0 {
			health.IntervalMS = ms
		}
		if ms, err := parseDurationMS(hc.Timeout); err != nil {
			return nil, fmt.Errorf("healthcheck.timeout: %w", err)
		} else if ms > 0 {
			health.TimeoutMS = ms
		}
		if hc.Retries > 0 {
			health.Retries = hc.Retries
		}
	}
	if ov.healthCmd != nil {
		health.Command = ov.healthCmd
	}
	if health.IntervalMS == 0 || health.TimeoutMS == 0 || health.Retries == 0 {
		return nil, fmt.Errorf("health interval, timeout, and retries must be non-zero")
	}
	if health.HeartbeatIntervalMS == 0 || health.HeartbeatTimeoutMS < health.HeartbeatIntervalMS*secretlaunch.HeartbeatSafetyFactor {
		return nil, fmt.Errorf("heartbeat timeout must be >= %dx heartbeat interval", secretlaunch.HeartbeatSafetyFactor)
	}
	return health, nil
}

// specFromAuthority mirrors secretlaunch.serviceSpecFromAuthority (unexported).
func specFromAuthority(authority *secretlaunch.ServiceAuthority) secretlaunch.ServiceSpec {
	keys := make([]string, 0, len(authority.Keys))
	for _, key := range authority.Keys {
		keys = append(keys, key.Name)
	}
	return secretlaunch.ServiceSpec{
		Name:          authority.Name,
		Image:         authority.Image,
		User:          authority.User,
		Argv:          authority.Argv,
		Environment:   authority.Environment,
		Labels:        authority.Labels,
		Networks:      authority.Networks,
		Restart:       authority.Restart,
		OpenStdin:     authority.OpenStdin,
		Health:        authority.Health,
		Dependencies:  authority.Dependencies,
		SecretKeys:    keys,
		WrapperDigest: authority.WrapperDigest,
		Child:         authority.Child,
	}
}

// --- keys and trust --------------------------------------------------------

func loadKeys(entries, pubkeys []string) (map[string]ed25519.PrivateKey, []string, map[string]string, error) {
	signing := map[string]ed25519.PrivateKey{}
	var order []string
	trust := map[string]string{}
	for _, entry := range entries {
		keyID, source, named := "", entry, false
		// Split keyID=source only when the tail parses as a key or is an
		// existing file; a bare base64 source can itself end in '=' padding.
		if head, tail, found := strings.Cut(entry, "="); found && head != "" {
			if _, err := parsePrivateKey(tail); err == nil {
				keyID, source, named = head, tail, true
			} else if info, statErr := os.Stat(tail); statErr == nil && info.Mode().IsRegular() {
				keyID, source, named = head, tail, true
			}
		}
		private, err := parsePrivateKey(source)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("--key %q: %w", entry, err)
		}
		if !named {
			sum := sha256.Sum256(private.Public().(ed25519.PublicKey))
			keyID = "ed25519-" + hex.EncodeToString(sum[:4])
		}
		if _, dup := signing[keyID]; dup {
			return nil, nil, nil, fmt.Errorf("--key %q: duplicate key ID %q", entry, keyID)
		}
		signing[keyID] = private
		order = append(order, keyID)
		trust[keyID] = base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	}
	for _, entry := range pubkeys {
		keyID, encoded, found := strings.Cut(entry, "=")
		if !found || keyID == "" {
			return nil, nil, nil, fmt.Errorf("--pubkey %q: want keyID=base64", entry)
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, nil, nil, fmt.Errorf("--pubkey %q: invalid base64 ed25519 public key", entry)
		}
		trust[keyID] = encoded
	}
	return signing, order, trust, nil
}

func parsePrivateKey(source string) (ed25519.PrivateKey, error) {
	var raw []byte
	if info, err := os.Stat(source); err == nil && info.Mode().IsRegular() {
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		raw = data
	} else {
		raw = []byte(strings.TrimSpace(source))
	}
	text := strings.TrimSpace(string(raw))
	for _, decode := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
	} {
		if decoded, err := decode(text); err == nil {
			raw = decoded
			break
		}
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	}
	return nil, fmt.Errorf("want %d-byte private key or %d-byte seed (hex/base64/file)", ed25519.PrivateKeySize, ed25519.SeedSize)
}

func buildTrust(opt *options, keys map[string]string, authorities []secretlaunch.ServiceAuthority) (*secretlaunch.TrustDocument, error) {
	runtimeIDs := map[string]bool{opt.runtimeID: true}
	for _, id := range opt.runtimeIDs {
		runtimeIDs[id] = true
	}
	roles := map[string]bool{}
	for _, role := range opt.roles {
		roles[role] = true
	}
	if opt.manifestRole != "" {
		roles[opt.manifestRole] = true
	}
	keyVersions := map[string]map[string]bool{}
	for i := range authorities {
		for _, key := range authorities[i].Keys {
			if keyVersions[key.Name] == nil {
				keyVersions[key.Name] = map[string]bool{}
			}
			keyVersions[key.Name][key.Version] = true
		}
	}
	for _, entry := range opt.keyVersions {
		name, version, found := strings.Cut(entry, "=")
		if !found || name == "" || version == "" {
			return nil, fmt.Errorf("--key-version %q: want NAME=VERSION", entry)
		}
		if keyVersions[name] == nil {
			keyVersions[name] = map[string]bool{}
		}
		keyVersions[name][version] = true
	}
	return &secretlaunch.TrustDocument{
		Keys:        keys,
		Versions:    []string{secretlaunch.ManifestVersion},
		RuntimeIDs:  sortedKeys(runtimeIDs),
		Roles:       sortedKeys(roles),
		KeyVersions: keyVersions,
	}, nil
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func randomNonce() string {
	var buf [24]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf[:])
}

// validDigest mirrors the supervisor's sha256:<64 lowercase hex> check.
func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// secretLike mirrors the supervisor's secret-name heuristic so generated
// artifacts never carry secret-shaped environment or label entries.
func secretLike(value string) bool {
	upper := strings.ToUpper(value)
	for _, marker := range []string{"SECRET", "PASSWORD", "TOKEN", "CREDENTIAL", "PRIVATE_KEY", "API_KEY"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}
