package secretlaunch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type RenderedModel struct {
	RuntimeID     string        `json:"runtime_id"`
	ComposeDigest string        `json:"compose_digest"`
	Services      []ServiceSpec `json:"services"`
}

type ServiceSpec struct {
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
	SecretKeys    []string          `json:"secret_keys"`
	WrapperDigest string            `json:"wrapper_digest"`
	Child         ChildSpec         `json:"child"`
}

type Container struct {
	ID      string
	Name    string
	Labels  map[string]string
	Running bool
	Healthy bool
}

type ContainerState struct {
	Container
	ExitCode int
}

type Runtime interface {
	Render(ctx context.Context, model RenderedModel) (RenderedModel, error)
	List(ctx context.Context, labels map[string]string) ([]Container, error)
	Inspect(ctx context.Context, id string) (ContainerState, error)
	Create(ctx context.Context, spec ServiceSpec, labels map[string]string) (Container, error)
	Attach(ctx context.Context, id string) (io.ReadWriteCloser, error)
	Start(ctx context.Context, id string) error
	Kill(ctx context.Context, id string) error
	Remove(ctx context.Context, id string, force bool) error
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

type AttachRunner interface {
	Attach(ctx context.Context, name string, args ...string) (io.ReadWriteCloser, error)
}

type DockerRuntime struct {
	Binary         string
	Runner         CommandRunner
	AttachRunner   AttachRunner
	ExplicitInvoke bool
}

func NewDockerRuntime(binary string, runner CommandRunner, attach AttachRunner, explicitlyInvoked bool) *DockerRuntime {
	return &DockerRuntime{Binary: binary, Runner: runner, AttachRunner: attach, ExplicitInvoke: explicitlyInvoked}
}

func (d *DockerRuntime) invoke(ctx context.Context, args ...string) ([]byte, error) {
	if d == nil || !d.ExplicitInvoke {
		return nil, fail(ErrNotInvoked)
	}
	if d.Runner == nil || d.Binary == "" {
		return nil, fail(ErrRuntime)
	}
	stdout, _, err := d.Runner.Run(ctx, d.Binary, args...)
	if err != nil {
		return nil, fail(ErrDaemon)
	}
	return stdout, nil
}

func (d *DockerRuntime) Render(_ context.Context, model RenderedModel) (RenderedModel, error) {
	if err := ValidateRenderedModel(model); err != nil {
		return RenderedModel{}, err
	}
	return model, nil
}

func (d *DockerRuntime) List(ctx context.Context, labels map[string]string) ([]Container, error) {
	keys := sortedMapKeys(labels)
	args := make([]string, 0, 5+2*len(keys))
	args = append(args, "ps", "--all", "--no-trunc")
	for _, key := range keys {
		args = append(args, "--filter", "label="+key+"="+labels[key])
	}
	args = append(args, "--format", "{{json .}}")
	stdout, err := d.invoke(ctx, args...)
	if err != nil {
		return nil, err
	}
	var result []Container
	for _, line := range bytes.Split(stdout, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var row struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Labels string `json:"Labels"`
			State  string `json:"State"`
		}
		if json.Unmarshal(line, &row) != nil || row.ID == "" {
			return nil, fail(ErrRuntime)
		}
		result = append(result, Container{ID: row.ID, Name: row.Names, Labels: parseDockerLabels(row.Labels), Running: strings.HasPrefix(strings.ToLower(row.State), "up")})
	}
	return result, nil
}

func (d *DockerRuntime) Inspect(ctx context.Context, id string) (ContainerState, error) {
	if !validContainerID(id) {
		return ContainerState{}, fail(ErrRuntime)
	}
	stdout, err := d.invoke(ctx, "inspect", "--format", "{{json .}}", id)
	if err != nil {
		return ContainerState{}, err
	}
	var row struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Running  bool `json:"Running"`
			ExitCode int  `json:"ExitCode"`
			Health   *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	if json.Unmarshal(bytes.TrimSpace(stdout), &row) != nil || row.ID == "" {
		return ContainerState{}, fail(ErrRuntime)
	}
	healthy := row.State.Health != nil && strings.EqualFold(row.State.Health.Status, "healthy")
	return ContainerState{Container: Container{ID: row.ID, Name: strings.TrimPrefix(row.Name, "/"), Labels: row.Config.Labels, Running: row.State.Running, Healthy: healthy}, ExitCode: row.State.ExitCode}, nil
}

func (d *DockerRuntime) Create(ctx context.Context, spec ServiceSpec, labels map[string]string) (Container, error) {
	if err := validateServiceSpec(&spec); err != nil {
		return Container{}, err
	}
	args := []string{"create", "--name", spec.Name, "--restart", "no", "--interactive", "--attach", "stdin"}
	if spec.User != "" {
		args = append(args, "--user", spec.User)
	}
	for _, network := range spec.Networks {
		args = append(args, "--network", network)
	}
	for _, key := range sortedMapKeys(spec.Environment) {
		args = append(args, "--env", key+"="+spec.Environment[key])
	}
	mergedLabels := cloneLabels(spec.Labels)
	for key, value := range labels {
		if _, collision := mergedLabels[key]; collision {
			return Container{}, fail(ErrRuntime)
		}
		mergedLabels[key] = value
	}
	for _, key := range sortedMapKeys(mergedLabels) {
		args = append(args, "--label", key+"="+mergedLabels[key])
	}
	if len(spec.Health.Command) > 0 {
		args = append(args, "--health-cmd", strings.Join(spec.Health.Command, " "), "--health-interval", strconv.Itoa(int(spec.Health.IntervalMS))+"ms", "--health-timeout", strconv.Itoa(int(spec.Health.TimeoutMS))+"ms", "--health-retries", strconv.Itoa(int(spec.Health.Retries)))
	}
	args = append(args, "--", spec.Image)
	args = append(args, spec.Argv...)
	stdout, err := d.invoke(ctx, args...)
	if err != nil {
		return Container{}, err
	}
	id := strings.TrimSpace(string(stdout))
	if !validContainerID(id) {
		return Container{}, fail(ErrRuntime)
	}
	return Container{ID: id, Name: spec.Name, Labels: mergedLabels}, nil
}

func (d *DockerRuntime) Attach(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	if !validContainerID(id) || d == nil || !d.ExplicitInvoke || d.AttachRunner == nil || d.Binary == "" {
		if d == nil || !d.ExplicitInvoke {
			return nil, fail(ErrNotInvoked)
		}
		return nil, fail(ErrRuntime)
	}
	return d.AttachRunner.Attach(ctx, d.Binary, "attach", id)
}

func (d *DockerRuntime) Start(ctx context.Context, id string) error {
	if !validContainerID(id) {
		return fail(ErrRuntime)
	}
	_, err := d.invoke(ctx, "start", id)
	return err
}

func (d *DockerRuntime) Kill(ctx context.Context, id string) error {
	if !validContainerID(id) {
		return fail(ErrRuntime)
	}
	_, err := d.invoke(ctx, "kill", id)
	return err
}

func (d *DockerRuntime) Remove(ctx context.Context, id string, force bool) error {
	if !validContainerID(id) {
		return fail(ErrRuntime)
	}
	args := []string{"rm"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, id)
	_, err := d.invoke(ctx, args...)
	return err
}

func ParseRenderedModel(data []byte) (RenderedModel, error) {
	if err := validateJSONObject(data); err != nil {
		return RenderedModel{}, fail(ErrRuntime)
	}
	var model RenderedModel
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&model); err != nil {
		return RenderedModel{}, fail(ErrRuntime)
	}
	canonical, err := json.Marshal(model)
	if err != nil || !bytes.Equal(canonical, data) {
		return RenderedModel{}, fail(ErrRuntime)
	}
	if err := ValidateRenderedModel(model); err != nil {
		return RenderedModel{}, err
	}
	return model, nil
}

func ModelDigest(model RenderedModel) (string, error) {
	if err := validateModelStructure(model); err != nil {
		return "", err
	}
	body := struct {
		RuntimeID string        `json:"runtime_id"`
		Services  []ServiceSpec `json:"services"`
	}{RuntimeID: model.RuntimeID, Services: model.Services}
	canonical, err := json.Marshal(body)
	if err != nil {
		return "", fail(ErrRuntime)
	}
	digest := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func ValidateRenderedModel(model RenderedModel) error {
	expected, err := ModelDigest(model)
	if err != nil {
		return err
	}
	if model.ComposeDigest != expected {
		return fail(ErrBinding)
	}
	return nil
}

func validateModelStructure(model RenderedModel) error {
	if !validServiceName(model.RuntimeID) || len(model.Services) == 0 || len(model.Services) > 256 {
		return fail(ErrRuntime)
	}
	last := ""
	for i := range model.Services {
		service := &model.Services[i]
		if service.Name <= last {
			return fail(ErrRuntime)
		}
		if err := validateServiceSpec(service); err != nil {
			return err
		}
		last = service.Name
	}
	return nil
}

func validateServiceSpec(service *ServiceSpec) error {
	if !validServiceName(service.Name) || !pinnedImage(service.Image) || service.User == "" ||
		strings.IndexByte(service.User, 0) >= 0 || service.Restart != "no" || !service.OpenStdin ||
		!validDigest(service.WrapperDigest) || validArguments(service.Argv) != nil ||
		service.Child.User == "" || strings.IndexByte(service.Child.User, 0) >= 0 ||
		validArguments(service.Child.Argv) != nil || validHealth(service.Health) != nil ||
		!equalStringMap(service.Child.Environment, service.Environment) {
		return fail(ErrRuntime)
	}
	last := ""
	for _, dependency := range service.Dependencies {
		if !validServiceName(dependency) || dependency == service.Name || dependency <= last {
			return fail(ErrRuntime)
		}
		last = dependency
	}
	last = ""
	for _, network := range service.Networks {
		if !validServiceName(network) || network <= last {
			return fail(ErrRuntime)
		}
		last = network
	}
	last = ""
	for _, key := range service.SecretKeys {
		if !validKeyName(key) || key <= last {
			return failKey(ErrRuntime, key)
		}
		last = key
	}
	for key, value := range service.Environment {
		if !validEnvName(key) || secretLikeName(key) || strings.IndexByte(value, 0) >= 0 {
			return failKey(ErrRuntime, key)
		}
	}
	for key, value := range service.Labels {
		if key == "" || strings.HasPrefix(key, "com.skret.secret-launch") || secretLikeName(key) ||
			secretLikeName(value) || strings.IndexByte(key, 0) >= 0 || strings.IndexByte(value, 0) >= 0 {
			return failKey(ErrRuntime, key)
		}
	}
	return nil
}

func ValidateManifestModel(manifest Manifest, model RenderedModel) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := ValidateRenderedModel(model); err != nil {
		return err
	}
	if manifest.RuntimeID != model.RuntimeID || manifest.Digests.Compose != model.ComposeDigest ||
		len(manifest.Services) != len(model.Services) {
		return fail(ErrBinding)
	}
	for index := range manifest.Services {
		expected := serviceSpecFromAuthority(&manifest.Services[index])
		if !reflect.DeepEqual(expected, model.Services[index]) {
			return fail(ErrBinding)
		}
	}
	return nil
}

func serviceSpecFromAuthority(authority *ServiceAuthority) ServiceSpec {
	keys := make([]string, 0, len(authority.Keys))
	for _, key := range authority.Keys {
		keys = append(keys, key.Name)
	}
	return ServiceSpec{
		Name:          authority.Name,
		Image:         authority.Image,
		User:          authority.User,
		Argv:          cloneStrings(authority.Argv),
		Environment:   cloneLabels(authority.Environment),
		Labels:        cloneLabels(authority.Labels),
		Networks:      cloneStrings(authority.Networks),
		Restart:       authority.Restart,
		OpenStdin:     authority.OpenStdin,
		Health:        authority.Health,
		Dependencies:  cloneStrings(authority.Dependencies),
		SecretKeys:    keys,
		WrapperDigest: authority.WrapperDigest,
		Child: ChildSpec{
			Argv:        cloneStrings(authority.Child.Argv),
			User:        authority.Child.User,
			Environment: cloneLabels(authority.Child.Environment),
		},
	}
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func secretLikeName(value string) bool {
	upper := strings.ToUpper(value)
	for _, marker := range []string{"SECRET", "PASSWORD", "TOKEN", "CREDENTIAL", "PRIVATE_KEY", "API_KEY"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

func OwnershipLabels(manifest Manifest) map[string]string {
	digest, err := manifest.Digest()
	if err != nil {
		return map[string]string{}
	}
	return map[string]string{
		"com.skret.secret-launch":            ManifestVersion,
		"com.skret.secret-launch.runtime":    manifest.RuntimeID,
		"com.skret.secret-launch.role":       manifest.Role,
		"com.skret.secret-launch.generation": strconv.FormatUint(manifest.Generation, 10),
		"com.skret.secret-launch.nonce":      manifest.Nonce,
		"com.skret.secret-launch.manifest":   fmt.Sprintf("sha256:%x", digest[:]),
	}
}

// OwnershipScopeLabels identifies the stable runtime/role namespace shared by
// all generations of one launch. Generation, nonce, and manifest digest are
// intentionally excluded so reconciliation can discover older owned
// containers before creating the current generation.
func OwnershipScopeLabels(manifest Manifest) map[string]string {
	return map[string]string{
		"com.skret.secret-launch":         ManifestVersion,
		"com.skret.secret-launch.runtime": manifest.RuntimeID,
		"com.skret.secret-launch.role":    manifest.Role,
	}
}

func olderOwnedGeneration(labels map[string]string, scope map[string]string, service ServiceSpec, current uint64) bool {
	if !ContainsLabels(labels, scope) || labels["com.skret.secret-launch.service"] != service.Name {
		return false
	}
	generation, err := strconv.ParseUint(labels["com.skret.secret-launch.generation"], 10, 64)
	if err != nil || generation == 0 || generation >= current ||
		!validNonce(labels["com.skret.secret-launch.nonce"]) ||
		!validDigest(labels["com.skret.secret-launch.manifest"]) {
		return false
	}

	expected := cloneLabels(service.Labels)
	for key, value := range scope {
		expected[key] = value
	}
	expected["com.skret.secret-launch.generation"] = labels["com.skret.secret-launch.generation"]
	expected["com.skret.secret-launch.nonce"] = labels["com.skret.secret-launch.nonce"]
	expected["com.skret.secret-launch.manifest"] = labels["com.skret.secret-launch.manifest"]
	expected["com.skret.secret-launch.service"] = service.Name
	return ExactLabels(labels, expected)
}

func LaunchLabels(manifest Manifest, service ServiceSpec) map[string]string {
	labels := OwnershipLabels(manifest)
	labels["com.skret.secret-launch.service"] = service.Name
	return labels
}

func ServiceLabels(manifest Manifest, service ServiceSpec) map[string]string {
	labels := cloneLabels(service.Labels)
	for key, value := range LaunchLabels(manifest, service) {
		labels[key] = value
	}
	return labels
}

func ContainsLabels(actual, required map[string]string) bool {
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func ExactLabels(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func parseDockerLabels(value string) map[string]string {
	result := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(entry, "=")
		if ok && key != "" {
			result[key] = val
		}
	}
	return result
}

func validContainerID(value string) bool {
	if value == "" || len(value) > 128 || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	for _, r := range value {
		if r == ' ' || r == '\r' || r == '\n' || r == '\t' {
			return false
		}
	}
	return true
}
