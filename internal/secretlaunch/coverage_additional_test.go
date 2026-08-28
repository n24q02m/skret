package secretlaunch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	skprovider "github.com/n24q02m/skret/internal/provider"
)

var errCoverage = errors.New("coverage failure")

type coverageCommandRunner struct {
	mu      sync.Mutex
	calls   [][]string
	handler func([]string) ([]byte, error)
}

func (r *coverageCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	call := append([]string{name}, args...)
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), call...))
	handler := r.handler
	r.mu.Unlock()
	if handler == nil {
		return nil, nil, nil
	}
	out, err := handler(call)
	return append([]byte(nil), out...), nil, err
}

func (r *coverageCommandRunner) lastCall() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return nil
	}
	return append([]string(nil), r.calls[len(r.calls)-1]...)
}

type coverageDuplex struct {
	mu          sync.Mutex
	readData    []byte
	readOffset  int
	writes      [][]byte
	failAtWrite int
	closed      bool
	closeOnce   sync.Once
	closedCh    chan struct{}
	onWrite     func(int, []byte) error
}

func newCoverageDuplex(readData []byte) *coverageDuplex {
	return &coverageDuplex{readData: append([]byte(nil), readData...), closedCh: make(chan struct{})}
}

func (s *coverageDuplex) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOffset >= len(s.readData) {
		if s.closed {
			return 0, io.ErrClosedPipe
		}
		return 0, io.EOF
	}
	n := copy(p, s.readData[s.readOffset:])
	s.readOffset += n
	return n, nil
}

func (s *coverageDuplex) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	index := len(s.writes) + 1
	copyOfP := append([]byte(nil), p...)
	if s.onWrite != nil {
		if err := s.onWrite(index, copyOfP); err != nil {
			return 0, err
		}
	}
	if s.failAtWrite == index {
		return 0, errCoverage
	}
	s.writes = append(s.writes, copyOfP)
	return len(p), nil
}

func (s *coverageDuplex) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.closedCh)
	})
	return nil
}

func (s *coverageDuplex) snapshotWrites() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]byte, len(s.writes))
	for i := range s.writes {
		result[i] = append([]byte(nil), s.writes[i]...)
	}
	return result
}

type coverageAttachRunner struct {
	stream *coverageDuplex
	calls  [][]string
}

func (r *coverageAttachRunner) Attach(_ context.Context, name string, args ...string) (io.ReadWriteCloser, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.stream == nil {
		r.stream = newCoverageDuplex(nil)
	}
	return r.stream, nil
}

type coverageChild struct {
	mu        sync.Mutex
	done      chan struct{}
	waitErr   error
	code      int
	signalErr error
	killErr   error
	killed    bool
	signals   []os.Signal
}

func newCoverageChild(code int, waitErr error, finished bool) *coverageChild {
	child := &coverageChild{done: make(chan struct{}), waitErr: waitErr, code: code}
	if finished {
		close(child.done)
	}
	return child
}

func (c *coverageChild) Wait() error {
	<-c.done
	return c.waitErr
}

func (c *coverageChild) Signal(signal os.Signal) error {
	c.mu.Lock()
	c.signals = append(c.signals, signal)
	err := c.signalErr
	c.mu.Unlock()
	return err
}

func (c *coverageChild) KillTree() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.killed = true
	if c.killErr != nil {
		return c.killErr
	}
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return nil
}

func (c *coverageChild) ExitCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

type coverageStarter struct {
	mu      sync.Mutex
	child   ChildProcess
	err     error
	started chan struct{}
	once    sync.Once
	values  SecretSet
}

func (s *coverageStarter) Start(_ context.Context, _ ChildSpec, values SecretSet) (ChildProcess, error) {
	s.mu.Lock()
	s.values = SecretSet{items: make(map[string]SecretBuffer, len(values.items))}
	for key, item := range values.items {
		s.values.items[key] = SecretBuffer{Key: item.Key, Version: item.Version, Env: item.Env, Bytes: append([]byte(nil), item.Bytes...)}
	}
	child, err := s.child, s.err
	s.mu.Unlock()
	if s.started != nil {
		s.once.Do(func() { close(s.started) })
	}
	return child, err
}

func TestCoverageStartFuncExecChildAndEnvironmentBoundaries(t *testing.T) {
	if _, err := StartFunc(nil).Start(context.Background(), ChildSpec{}, SecretSet{}); errorCode(err) != ErrChild {
		t.Fatalf("nil StartFunc code = %v", errorCode(err))
	}
	called := false
	started := StartFunc(func(_ context.Context, spec ChildSpec, values SecretSet) (ChildProcess, error) {
		called = spec.User == "current" && values.Len() == 0
		return newCoverageChild(0, nil, true), nil
	})
	if _, err := started.Start(context.Background(), ChildSpec{User: "current"}, SecretSet{}); err != nil || !called {
		t.Fatalf("StartFunc forwarding failed: err=%v called=%v", err, called)
	}
	if _, err := (ExecStarter{}).Start(context.Background(), ChildSpec{}, SecretSet{}); errorCode(err) != ErrChild {
		t.Fatalf("empty argv code = %v", errorCode(err))
	}
	invalid := SecretSet{items: map[string]SecretBuffer{"APP_TOKEN": {Key: "APP_TOKEN", Env: "BAD-NAME"}}}
	if _, err := (ExecStarter{}).Start(context.Background(), ChildSpec{Argv: []string{os.Args[0]}, User: "current"}, invalid); errorCode(err) != ErrKey {
		t.Fatalf("invalid environment code = %v", errorCode(err))
	}
	if _, err := (ExecStarter{}).Start(context.Background(), ChildSpec{Argv: []string{"definitely-missing-secretlaunch-command-coverage"}, User: "current"}, SecretSet{}); errorCode(err) != ErrChild {
		t.Fatal("missing child command was not classified")
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	child, err := (ExecStarter{}).Start(context.Background(), ChildSpec{Argv: []string{goBinary, "version"}, User: "current", Environment: map[string]string{"COVERAGE_CHILD": "yes"}}, SecretSet{})
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil || child.ExitCode() != 0 {
		t.Fatalf("child wait = %v code=%d", err, child.ExitCode())
	}
	var nilChild *execChild
	if nilChild.Wait() == nil || nilChild.Signal(os.Interrupt) == nil || nilChild.KillTree() == nil || nilChild.ExitCode() != -1 {
		t.Fatal("nil execChild boundary was not fail-closed")
	}
}

func TestCoverageProcessPlatformHooksAndEnvironmentFiltering(t *testing.T) {
	command := &exec.Cmd{}
	if err := configureProcessGroup(command); err != nil {
		t.Fatal(err)
	}
	if err := applyChildUser(command, "current"); err != nil {
		t.Fatal(err)
	}
	if errorCode(applyChildUser(command, "definitely-no-such-user-coverage")) != ErrChild {
		t.Fatalf("invalid child user code = %v", errorCode(applyChildUser(command, "definitely-no-such-user-coverage")))
	}
	if errorCode(signalProcessTree(nil, os.Interrupt)) != ErrChild || errorCode(killProcessTree(nil)) != ErrChild {
		t.Fatal("nil process tree operations were not rejected")
	}
	values := SecretSet{items: map[string]SecretBuffer{
		"APP_TOKEN": {Key: "APP_TOKEN", Version: "1", Bytes: []byte("coverage-value")},
	}}
	result := filteredEnvironment([]string{"PATH=/bin", "NO_EQUALS", "HOME=/tmp", "AWS_SECRET_ACCESS_KEY=drop", "PATH=/last"}, map[string]string{"LANG": "C", "LOG_LEVEL": "info"}, values)
	if !strings.Contains(strings.Join(result, "\x00"), "APP_TOKEN=coverage-value") || strings.Contains(strings.Join(result, "\x00"), "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("filtered environment = %v", result)
	}
	if !sortEnvironment(result) {
		t.Fatal("filtered environment was not sorted")
	}
	if errorCode(validateSecretEnvironment(SecretSet{items: map[string]SecretBuffer{"bad": {Key: "BAD KEY"}}})) != ErrKey {
		t.Fatal("invalid key fallback environment was accepted")
	}
}

func sortEnvironment(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}

func TestCoverageDockerRuntimeListInspectAttachLifecycleAndErrors(t *testing.T) {
	runner := &coverageCommandRunner{}
	runner.handler = func(call []string) ([]byte, error) {
		switch call[1] {
		case "ps":
			return []byte("{\"ID\":\"cid-up\",\"Names\":\"api\",\"Labels\":\"a=b,c=bad=x,noval\",\"State\":\"Up 2 seconds\"}\n{\"ID\":\"cid-down\",\"Names\":\"db\",\"Labels\":\"\",\"State\":\"Exited (1)\"}\n"), nil
		case "inspect":
			return []byte("{\"Id\":\"cid-up\",\"Name\":\"/api\",\"Config\":{\"Labels\":{\"owner\":\"coverage\"}},\"State\":{\"Running\":true,\"ExitCode\":0,\"Health\":{\"Status\":\"healthy\"}}}"), nil
		case "start", "kill", "rm":
			return nil, nil
		case "create":
			return []byte("created-id\n"), nil
		default:
			return nil, nil
		}
	}
	attach := &coverageAttachRunner{stream: newCoverageDuplex(nil)}
	docker := NewDockerRuntime("docker", runner, attach, true)
	containers, err := docker.List(context.Background(), map[string]string{"z": "last", "a": "first"})
	if err != nil || len(containers) != 2 || !containers[0].Running || containers[1].Running || containers[0].Labels["c"] != "bad=x" {
		t.Fatalf("list = %#v err=%v", containers, err)
	}
	listCall := runner.lastCall()
	if strings.Join(listCall, " ") != "docker ps --all --no-trunc --filter label=a=first --filter label=z=last --format {{json .}}" {
		t.Fatalf("list command = %v", listCall)
	}
	state, err := docker.Inspect(context.Background(), "cid-up")
	if err != nil || state.Name != "api" || !state.Healthy || state.ExitCode != 0 || !state.Running {
		t.Fatalf("inspect = %#v err=%v", state, err)
	}
	_, err = docker.Inspect(context.Background(), "bad id")
	if errorCode(err) != ErrRuntime {
		t.Fatal("invalid inspect id was accepted")
	}
	if _, err := docker.Attach(context.Background(), "cid-up"); err != nil || len(attach.calls) != 1 || attach.calls[0][1] != "attach" {
		t.Fatalf("attach = %v calls=%v", err, attach.calls)
	}
	_, err = NewDockerRuntime("docker", runner, nil, true).Attach(context.Background(), "cid-up")
	if errorCode(err) != ErrRuntime {
		t.Fatal("missing attach runner was accepted")
	}
	_, err = NewDockerRuntime("docker", runner, attach, false).Attach(context.Background(), "cid-up")
	if errorCode(err) != ErrNotInvoked {
		t.Fatal("implicit attach was accepted")
	}
	if err := docker.Start(context.Background(), "cid-up"); err != nil {
		t.Fatal(err)
	}
	if err := docker.Kill(context.Background(), "cid-up"); err != nil {
		t.Fatal(err)
	}
	if err := docker.Remove(context.Background(), "cid-up", true); err != nil {
		t.Fatal(err)
	}
	if err := docker.Remove(context.Background(), "cid-up", false); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error { return docker.Start(context.Background(), "") },
		func() error { return docker.Kill(context.Background(), "bad id") },
		func() error { return docker.Remove(context.Background(), "bad id", false) },
	} {
		if errorCode(operation()) != ErrRuntime {
			t.Fatal("invalid lifecycle id was accepted")
		}
	}
	if _, err := docker.Create(context.Background(), fixtureModel().Services[0], map[string]string{"com.example.component": "collision"}); errorCode(err) != ErrRuntime {
		t.Fatal("label collision was accepted")
	}
	badIDRunner := &coverageCommandRunner{handler: func([]string) ([]byte, error) { return []byte("bad id\n"), nil }}
	if _, err := NewDockerRuntime("docker", badIDRunner, attach, true).Create(context.Background(), fixtureModel().Services[0], nil); errorCode(err) != ErrRuntime {
		t.Fatal("invalid created container id was accepted")
	}
	if _, err := NewDockerRuntime("docker", &coverageCommandRunner{handler: func([]string) ([]byte, error) { return nil, errCoverage }}, attach, true).List(context.Background(), nil); errorCode(err) != ErrDaemon {
		t.Fatal("daemon error was not classified")
	}
	if _, err := NewDockerRuntime("", runner, attach, true).List(context.Background(), nil); errorCode(err) != ErrRuntime {
		t.Fatal("missing Docker binary was accepted")
	}
}

func TestCoverageDockerRuntimeRejectsMalformedRowsAndNilInvocation(t *testing.T) {
	malformedList := &coverageCommandRunner{handler: func(call []string) ([]byte, error) {
		if call[1] == "ps" {
			return []byte(`{"Names":"missing-id"}`), nil
		}
		return nil, nil
	}}
	docker := NewDockerRuntime("docker", malformedList, nil, true)
	if _, err := docker.List(context.Background(), nil); errorCode(err) != ErrRuntime {
		t.Fatal("malformed list row was accepted")
	}
	malformedInspect := &coverageCommandRunner{handler: func([]string) ([]byte, error) {
		return []byte(`not-json`), nil
	}}
	if _, err := NewDockerRuntime("docker", malformedInspect, nil, true).Inspect(context.Background(), "cid"); errorCode(err) != ErrRuntime {
		t.Fatal("malformed inspect row was accepted")
	}
	unhealthy := &coverageCommandRunner{handler: func([]string) ([]byte, error) {
		return []byte(`{"Id":"cid","Name":"worker","Config":{"Labels":null},"State":{"Running":false,"ExitCode":4}}`), nil
	}}
	state, err := NewDockerRuntime("docker", unhealthy, nil, true).Inspect(context.Background(), "cid")
	if err != nil || state.Healthy || state.Running || state.ExitCode != 4 || state.Name != "worker" {
		t.Fatalf("unhealthy inspect=%+v err=%v", state, err)
	}
	var nilDocker *DockerRuntime
	if _, err := nilDocker.List(context.Background(), nil); errorCode(err) != ErrNotInvoked {
		t.Fatal("nil Docker runtime list was accepted")
	}
	if _, err := NewDockerRuntime("docker", nil, nil, true).List(context.Background(), nil); errorCode(err) != ErrRuntime {
		t.Fatal("nil command runner was accepted")
	}
	model := fixtureModel()
	model.Services[0].Restart = "always"
	if _, err := docker.Render(context.Background(), model); errorCode(err) != ErrRuntime {
		t.Fatal("invalid model render was accepted")
	}
}

func TestCoverageParseRenderedModelAndValidationBoundaries(t *testing.T) {
	model := fixtureModel()
	canonical, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRenderedModel(canonical)
	if err != nil || parsed.RuntimeID != model.RuntimeID || !reflectDeepEqualServices(parsed.Services, model.Services) {
		t.Fatalf("parsed model = %#v err=%v", parsed, err)
	}
	unknown := append([]byte(nil), canonical[:len(canonical)-1]...)
	unknown = append(unknown, []byte(`,"unknown":1}`)...)
	for _, input := range [][]byte{[]byte(" " + string(canonical)), unknown, append(canonical, '\n'), []byte("[]"), []byte("null")} {
		if _, err := ParseRenderedModel(input); errorCode(err) != ErrRuntime {
			t.Fatalf("invalid model input %q code=%v", input, errorCode(err))
		}
	}
	invalid := model
	invalid.Services[0].Labels = map[string]string{"DB_PASSWORD": "coverage"}
	if err := ValidateRenderedModel(invalid); errorCode(err) != ErrRuntime {
		t.Fatalf("invalid model labels code=%v", errorCode(err))
	}
	for _, mutate := range []func(*ServiceSpec){
		func(s *ServiceSpec) { s.Dependencies = []string{"api", "db"} },
		func(s *ServiceSpec) { s.Networks = []string{"z", "a"} },
		func(s *ServiceSpec) { s.SecretKeys = []string{"APP_TOKEN", "APP_TOKEN"} },
		func(s *ServiceSpec) { s.Environment = map[string]string{"LOG\x00": "x"} },
		func(s *ServiceSpec) { s.Labels = map[string]string{"com.skret.secret-launch.bad": "x"} },
		func(s *ServiceSpec) { s.Child.User = "current\x00" },
	} {
		candidate := fixtureModel()
		mutate(&candidate.Services[0])
		if err := ValidateRenderedModel(candidate); errorCode(err) != ErrRuntime {
			t.Fatalf("model mutation was accepted: %#v", candidate.Services[0])
		}
	}
}

func reflectDeepEqualServices(a, b []ServiceSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Image != b[i].Image || !equalStringMap(a[i].Environment, b[i].Environment) {
			return false
		}
	}
	return true
}

func TestCoverageProviderAdapterSecretSetAndFetchFailures(t *testing.T) {
	_, err := FetchFunc(nil).Fetch(context.Background(), "APP_TOKEN", "1")
	if errorCode(err) != ErrNoProvider {
		t.Fatal("nil FetchFunc was accepted")
	}
	base := &coverageBaseProvider{}
	if _, err := NewSkretProvider(nil); errorCode(err) != ErrNoProvider {
		t.Fatal("nil general provider was accepted")
	}
	if _, err := NewSkretProvider(base); errorCode(err) != ErrNoProvider {
		t.Fatal("unversioned general provider was accepted")
	}
	versioned := &coverageVersionedProvider{coverageBaseProvider: coverageBaseProvider{}, result: &skprovider.Secret{Key: "APP_TOKEN", Version: 7, Value: "coverage-secret"}}
	adapter, err := NewSkretProvider(versioned)
	if err != nil {
		t.Fatal(err)
	}
	value, err := adapter.Fetch(context.Background(), "APP_TOKEN", "7")
	if err != nil || string(value) != "coverage-secret" || versioned.lastKey != "APP_TOKEN" || versioned.lastVersion != 7 {
		t.Fatalf("adapter fetch value=%q err=%v key=%q version=%d", value, err, versioned.lastKey, versioned.lastVersion)
	}
	for _, candidate := range []*SkretProvider{nil, {Provider: nil}} {
		if _, err := candidate.Fetch(context.Background(), "APP_TOKEN", "7"); errorCode(err) != ErrFetch {
			t.Fatal("invalid adapter was accepted")
		}
	}
	for _, key := range []string{"", "BAD KEY"} {
		if _, err := adapter.Fetch(context.Background(), key, "7"); errorCode(err) != ErrFetch {
			t.Fatal("invalid key was accepted")
		}
	}
	if _, err := adapter.Fetch(context.Background(), "APP_TOKEN", "latest"); errorCode(err) != ErrFetch {
		t.Fatal("non-numeric version was accepted")
	}
	for _, bad := range []*skprovider.Secret{
		{Key: "OTHER", Version: 7, Value: "x"},
		{Key: "APP_TOKEN", Version: 8, Value: "x"},
		nil,
	} {
		versioned.result = bad
		if _, err := adapter.Fetch(context.Background(), "APP_TOKEN", "7"); errorCode(err) != ErrFetch {
			t.Fatal("mismatched versioned result was accepted")
		}
	}
	versioned.err = errCoverage
	if _, err := adapter.Fetch(context.Background(), "APP_TOKEN", "7"); errorCode(err) != ErrFetch {
		t.Fatal("provider error was not classified")
	}
	set := SecretSet{items: map[string]SecretBuffer{"APP_TOKEN": {Key: "APP_TOKEN", Version: "1", Env: "APP_TOKEN", Bytes: []byte("copy")}}}
	copyOfItem, ok := set.Get("APP_TOKEN")
	if !ok {
		t.Fatal("secret set item missing")
	}
	copyOfItem.Bytes[0] = 'X'
	if string(set.items["APP_TOKEN"].Bytes) != "copy" {
		t.Fatal("SecretSet.Get did not isolate bytes")
	}
	if _, ok := set.Get("missing"); ok {
		t.Fatal("missing SecretSet item reported present")
	}
	set.Zeroize()
	if set.Len() != 0 {
		t.Fatal("SecretSet was not emptied")
	}
	tooLarge := bytes.Repeat([]byte{'x'}, MaxValueLength+1)
	if _, err := FetchSecrets(context.Background(), FetchFunc(func(context.Context, string, string) ([]byte, error) { return tooLarge, nil }), []ManifestKey{{Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"}}); errorCode(err) != ErrFetch {
		t.Fatal("oversized provider value was accepted")
	}
	if !bytes.Equal(tooLarge, make([]byte, len(tooLarge))) {
		t.Fatal("oversized provider value was not zeroized")
	}
}

func TestCoverageRegularFileSuccessAndBoundedErrors(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "artifact"
	contents := []byte("coverage-artifact")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := ReadRegularFile(path, int64(len(contents)))
	if err != nil || !bytes.Equal(read, contents) {
		t.Fatalf("read = %q err=%v", read, err)
	}
	for _, candidate := range []struct {
		path string
		max  int64
	}{{"", 1}, {path, 0}, {path + ".missing", 100}, {dir, 100}, {path, int64(len(contents) - 1)}} {
		if _, err := ReadRegularFile(candidate.path, candidate.max); errorCode(err) != ErrInvalidInput {
			t.Fatalf("invalid regular read %#v code=%v", candidate, errorCode(err))
		}
	}
	if err := VerifyRegularFileDigest(path, digestForBytes(contents), int64(len(contents))); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		expected string
		max      int64
	}{
		{"", 100},
		{"sha256:bad", 100},
		{digestForBytes(contents), int64(len(contents) - 1)},
	} {
		if err := VerifyRegularFileDigest(path, candidate.expected, candidate.max); errorCode(err) != ErrInvalidInput {
			t.Fatalf("invalid digest input %#v code=%v", candidate, errorCode(err))
		}
	}
	if err := VerifyRegularFileDigest(path, digestForBytes([]byte("different")), 100); errorCode(err) != ErrBinding {
		t.Fatalf("wrong digest code=%v", errorCode(err))
	}
}

func TestCoverageTrackedStreamsAndSupervisorSessionReplacement(t *testing.T) {
	var nilStream *trackedStream
	if _, err := nilStream.Read(make([]byte, 1)); err != io.ErrClosedPipe {
		t.Fatalf("nil tracked read err=%v", err)
	}
	if _, err := nilStream.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("nil tracked write err=%v", err)
	}
	if !nilStream.isClosed() || nilStream.Close() != nil {
		t.Fatal("nil tracked stream boundary failed")
	}
	underlying := newCoverageDuplex([]byte("read"))
	tracked := newTrackedStream(underlying)
	buffer := make([]byte, 4)
	if n, err := tracked.Read(buffer); err != nil || n != 4 || string(buffer) != "read" {
		t.Fatalf("tracked read n=%d err=%v data=%q", n, err, buffer)
	}
	if n, err := tracked.Write([]byte("write")); err != nil || n != 5 {
		t.Fatalf("tracked write n=%d err=%v", n, err)
	}
	if err := tracked.Close(); err != nil || !tracked.isClosed() || tracked.Close() != nil {
		t.Fatal("tracked close was not idempotent")
	}
	if _, err := tracked.Write([]byte("after")); err != io.ErrClosedPipe {
		t.Fatalf("closed tracked write err=%v", err)
	}
	supervisor := NewSupervisor(newFakeRuntime(), FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil }))
	first := newTrackedStream(newCoverageDuplex(nil))
	second := newTrackedStream(newCoverageDuplex(nil))
	supervisor.trackSession("cid", first)
	supervisor.trackSession("cid", second)
	if !first.isClosed() || !supervisor.hasSession("cid") {
		t.Fatal("session replacement did not close the old stream and retain the new stream")
	}
	supervisor.closeSession("cid")
	if supervisor.hasSession("cid") || !second.isClosed() {
		t.Fatal("session close did not remove and close stream")
	}
	if supervisor.now().IsZero() {
		t.Fatal("default supervisor clock was invalid")
	}
}

func TestCoverageSupervisorDependencyChecksAndRecoveryBoundaries(t *testing.T) {
	manifest, model := coverageTwoServiceFixture()
	runtime := newFakeRuntime()
	supervisor := NewSupervisor(runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil }))
	api := model.Services[0]
	db := model.Services[1]
	all := map[string]ServiceSpec{"api": api, "db": db}
	if err := supervisor.checkDependencies(context.Background(), api, all, manifest); errorCode(err) != ErrRuntime {
		t.Fatalf("missing dependency code=%v", errorCode(err))
	}
	runtime.containers["cid-db"] = ContainerState{Container: Container{ID: "cid-db", Name: "db", Labels: ServiceLabels(manifest, db), Running: true, Healthy: true}}
	if err := supervisor.checkDependencies(context.Background(), api, all, manifest); err != nil {
		t.Fatalf("healthy dependency rejected: %v", err)
	}
	runtime.containers["cid-db"] = ContainerState{Container: Container{ID: "cid-db", Name: "db", Labels: ServiceLabels(manifest, db), Running: false, Healthy: false}}
	if err := supervisor.checkDependencies(context.Background(), api, all, manifest); errorCode(err) != ErrRuntime {
		t.Fatalf("unhealthy dependency code=%v", errorCode(err))
	}
	runtime.listErr = errCoverage
	if err := supervisor.checkDependencies(context.Background(), api, all, manifest); err != errCoverage {
		t.Fatalf("dependency list error=%v", err)
	}
	runtime.listErr = nil
	if err := supervisor.checkDependencies(context.Background(), api, map[string]ServiceSpec{"api": api}, manifest); errorCode(err) != ErrRuntime {
		t.Fatalf("unknown dependency code=%v", errorCode(err))
	}
	if err := validateDependencies([]ServiceSpec{{Name: "api", Dependencies: []string{"missing"}}}, map[string]ServiceSpec{}); errorCode(err) != ErrRuntime {
		t.Fatal("unknown ordered dependency was accepted")
	}
	invalidRuntime := &coverageRuntime{fakeRuntime: newFakeRuntime(), renderErr: errCoverage}
	if _, err := NewSupervisor(invalidRuntime, supervisor.Provider).Reconcile(context.Background(), model, manifest); err != errCoverage {
		t.Fatalf("render error=%v", err)
	}
	if _, err := (&Supervisor{}).Reconcile(context.Background(), model, manifest); errorCode(err) != ErrNoProvider {
		t.Fatal("nil supervisor dependencies were accepted")
	}
	if _, err := supervisor.ScavengeOrphans(context.Background(), nil); errorCode(err) != ErrRuntime {
		t.Fatal("empty scavenge labels were accepted")
	}
	runtime.listErr = fail(ErrDaemon)
	waitErr := supervisor.reconcileWithRecovery(context.Background(), model, manifest)
	if errorCode(waitErr) != ErrDaemon {
		t.Fatalf("recovery without waiter code=%v", errorCode(waitErr))
	}
	supervisor.WaitDaemon = func(context.Context) error { return errCoverage }
	if err := supervisor.reconcileWithRecovery(context.Background(), model, manifest); errorCode(err) != ErrDaemon {
		t.Fatalf("recovery waiter error code=%v", errorCode(err))
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := supervisor.reconcileWithRecovery(cancelled, model, manifest); err != context.Canceled {
		t.Fatalf("canceled recovery err=%v", err)
	}
}

type coverageRuntime struct {
	*fakeRuntime
	renderErr  error
	inspectErr error
	createErr  error
}

func (r *coverageRuntime) Render(ctx context.Context, model RenderedModel) (RenderedModel, error) {
	if r.renderErr != nil {
		return RenderedModel{}, r.renderErr
	}
	return r.fakeRuntime.Render(ctx, model)
}

func (r *coverageRuntime) Inspect(ctx context.Context, id string) (ContainerState, error) {
	if r.inspectErr != nil {
		return ContainerState{}, r.inspectErr
	}
	return r.fakeRuntime.Inspect(ctx, id)
}

func (r *coverageRuntime) Create(ctx context.Context, spec ServiceSpec, labels map[string]string) (Container, error) {
	if r.createErr != nil {
		return Container{}, r.createErr
	}
	return r.fakeRuntime.Create(ctx, spec, labels)
}

func coverageTwoServiceFixture() (Manifest, RenderedModel) {
	manifest := fixtureManifest()
	db := fixtureAuthority()
	db.Name = "db"
	db.Image = "registry.example/db@sha256:" + strings.Repeat("2", 64)
	db.Argv = []string{"/usr/local/bin/skret-secret-helper", "--runtime", "docker-prod", "--service", "db"}
	db.Labels = map[string]string{"com.example.component": "db"}
	db.WrapperDigest = digestFixture("d")
	db.Child = ChildSpec{Argv: []string{"/app/db"}, User: "current", Environment: map[string]string{"LOG_LEVEL": "info"}}
	api := fixtureAuthority()
	api.Dependencies = []string{"db"}
	manifest.Services = []ServiceAuthority{api, db}
	model := RenderedModel{RuntimeID: manifest.RuntimeID, Services: []ServiceSpec{serviceSpecFromAuthority(&api), serviceSpecFromAuthority(&db)}}
	digest, _ := ModelDigest(model)
	model.ComposeDigest = digest
	manifest.Digests.Compose = digest
	return manifest, model
}

func TestCoverageSupervisorReusesHealthySessionAndCleansFailures(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()
	providerCalls := 0
	provider := FetchFunc(func(context.Context, string, string) ([]byte, error) { providerCalls++; return []byte("x"), nil })
	runtime := newFakeRuntime()
	runtime.containers["existing"] = ContainerState{Container: Container{ID: "existing", Name: "api", Labels: ServiceLabels(manifest, model.Services[0]), Running: true, Healthy: true}, ExitCode: 0}
	supervisor := NewSupervisor(runtime, provider)
	supervisor.trackSession("existing", newTrackedStream(newCoverageDuplex(nil)))
	result, err := supervisor.Reconcile(context.Background(), model, manifest)
	if err != nil || len(result.Reused) != 1 || providerCalls != 0 {
		t.Fatalf("reuse result=%+v err=%v providerCalls=%d", result, err, providerCalls)
	}
	cases := []struct {
		name      string
		runtime   *coverageRuntime
		senderErr error
	}{
		{"remove", &coverageRuntime{fakeRuntime: newFakeRuntime()}, nil},
		{"attach", &coverageRuntime{fakeRuntime: newFakeRuntime()}, nil},
		{"start", &coverageRuntime{fakeRuntime: newFakeRuntime()}, nil},
		{"send", &coverageRuntime{fakeRuntime: newFakeRuntime()}, errCoverage},
	}
	cases[0].runtime.containers["old"] = ContainerState{Container: Container{ID: "old", Name: "api", Labels: ServiceLabels(manifest, model.Services[0])}}
	cases[0].runtime.removeErr = errCoverage
	cases[1].runtime.attachErr = errCoverage
	cases[2].runtime.startErr = errCoverage
	for i := range cases {
		caseItem := &cases[i]
		caseItem.runtime.calls = nil
		s := NewSupervisor(caseItem.runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil }))
		if caseItem.senderErr != nil {
			s.Send = func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error {
				return caseItem.senderErr
			}
		}
		_, gotErr := s.Reconcile(context.Background(), model, manifest)
		if gotErr == nil {
			t.Fatalf("%s failure unexpectedly succeeded", caseItem.name)
		}
		if caseItem.name == "remove" && gotErr != errCoverage {
			t.Fatalf("remove error=%v", gotErr)
		}
		if caseItem.name != "remove" && errorCode(gotErr) == ErrNoProvider {
			t.Fatalf("%s returned unrelated error=%v", caseItem.name, gotErr)
		}
	}
	if err := NewSupervisor(runtime, provider).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageSendEnvelopeBindingWritesAndHeartbeat(t *testing.T) {
	manifest := fixtureManifest()
	service := manifest.Services[0]
	values := SecretSet{items: map[string]SecretBuffer{service.Keys[0].Name: {Key: service.Keys[0].Name, Version: service.Keys[0].Version, Env: service.Keys[0].Env, Bytes: []byte("coverage-value")}}}
	stream, peer := newCoverageEnvelopeStream(t, manifest, service, values)
	ctx, cancel := context.WithCancel(context.Background())
	if err := SendEnvelope(ctx, stream, manifest, service, values); err != nil {
		cancel()
		t.Fatalf("SendEnvelope error=%v", err)
	}
	writes := stream.snapshotWrites()
	if len(writes) < 2 || string(writes[0][:4]) != handshakeMagic {
		cancel()
		t.Fatalf("envelope writes=%d", len(writes))
	}
	canonical, _ := manifest.canonicalBytesUnchecked()
	key, err := peer.Derive(writes[0][4:], canonical)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	receiver, err := NewSession(key, canonical)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	frame, err := receiver.Open(writes[1])
	if err != nil || frame.Key != service.Keys[0].Name || string(frame.Value) != "coverage-value" {
		cancel()
		t.Fatalf("secret frame=%+v err=%v", frame, err)
	}
	Zeroize(frame.Value)
	select {
	case <-stream.closedCh:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("heartbeat/stream close did not occur")
	}
	cancel()
	receiver.Close()
	peer.Close()
	for _, writes := range []int{1, 2} {
		badValues := SecretSet{items: map[string]SecretBuffer{service.Keys[0].Name: {Key: service.Keys[0].Name, Version: service.Keys[0].Version, Env: service.Keys[0].Env, Bytes: []byte("coverage-value")}}}
		badStream, badPeer := newCoverageEnvelopeStream(t, manifest, service, badValues)
		badStream.failAtWrite = writes
		if err := SendEnvelope(context.Background(), badStream, manifest, service, badValues); errorCode(err) != ErrCrypto {
			t.Fatalf("write %d error=%v", writes, err)
		}
		badPeer.Close()
		badValues.Zeroize()
	}
	if errorCode(SendEnvelope(context.Background(), nil, manifest, service, SecretSet{})) != ErrCrypto {
		t.Fatal("nil envelope stream was accepted")
	}
	wrongService := service
	wrongService.Name = "other"
	wrongValues := SecretSet{items: map[string]SecretBuffer{service.Keys[0].Name: {Key: service.Keys[0].Name, Version: service.Keys[0].Version, Env: service.Keys[0].Env, Bytes: []byte("coverage-value")}}}
	if errorCode(SendEnvelope(context.Background(), newCoverageDuplex(nil), manifest, wrongService, wrongValues)) != ErrBinding {
		t.Fatal("unbound service envelope was accepted")
	}
	wrongValues.Zeroize()
	values.Zeroize()
}

func newCoverageEnvelopeStream(t *testing.T, manifest Manifest, service ServiceAuthority, values SecretSet) (*coverageDuplex, *Handshake) {
	t.Helper()
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	peerMessage, err := EncodeHandshake(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	stream := newCoverageDuplex(peerMessage)
	stream.onWrite = func(index int, local []byte) error {
		if index == 1 {
			key, deriveErr := peer.Derive(local[4:], canonical)
			if deriveErr != nil {
				return deriveErr
			}
			session, sessionErr := NewSession(key, canonical)
			if sessionErr != nil {
				return sessionErr
			}
			wire, sealErr := session.Seal(Frame{Kind: SecretMessage, Key: service.Keys[0].Name, Version: service.Keys[0].Version, Value: values.items[service.Keys[0].Name].Bytes})
			session.Close()
			if sealErr != nil {
				return sealErr
			}
			stream.readData = append(stream.readData, wire...)
		}
		if index == 3 {
			go func() { _ = stream.Close() }()
		}
		return nil
	}
	return stream, peer
}

func TestCoverageReadWireFrameAndContextBoundaries(t *testing.T) {
	if _, err := readWireFrame(nil); err == nil {
		t.Fatal("nil wire reader was accepted")
	}
	badHeader := make([]byte, frameHeaderSize)
	copy(badHeader, "BAD!")
	if _, err := readWireFrame(bytes.NewReader(badHeader)); err == nil {
		t.Fatal("bad wire magic was accepted")
	}
	oversized := make([]byte, frameHeaderSize)
	copy(oversized, frameMagic)
	binary.BigEndian.PutUint32(oversized[29:33], MaxValueLength+17)
	if _, err := readWireFrame(bytes.NewReader(oversized)); err == nil {
		t.Fatal("oversized wire frame was accepted")
	}
	manifest := fixtureManifest()
	wire, sender, receiver := secretWire(t, manifest)
	sender.Close()
	receiver.Close()
	decoded, err := readWireFrameContext(context.Background(), bytes.NewReader(wire))
	if err != nil || !bytes.Equal(decoded, wire) {
		t.Fatalf("context wire read err=%v", err)
	}
	Zeroize(decoded)
	peer, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	message, _ := EncodeHandshake(peer.PublicKey())
	readPeer, err := readHandshakeContext(context.Background(), bytes.NewReader(message))
	if err != nil || !bytes.Equal(readPeer, peer.PublicKey()) {
		t.Fatalf("context handshake read err=%v", err)
	}
	Zeroize(readPeer)
	peer.Close()
	var nilContext context.Context
	if _, err := readHandshakeContext(nilContext, bytes.NewReader(message)); errorCode(err) != ErrLifecycle {
		t.Fatal("nil handshake context was accepted")
	}
	if _, err := readWireFrameContext(nilContext, bytes.NewReader(wire)); errorCode(err) != ErrLifecycle {
		t.Fatal("nil wire context was accepted")
	}
}

type coverageBlockingReader struct {
	data    []byte
	offset  int
	blocked chan struct{}
	release chan struct{}
	once    sync.Once
}

func newCoverageBlockingReader(data []byte) *coverageBlockingReader {
	return &coverageBlockingReader{data: append([]byte(nil), data...), blocked: make(chan struct{}), release: make(chan struct{})}
}

func (r *coverageBlockingReader) Read(p []byte) (int, error) {
	if r.offset < len(r.data) {
		n := copy(p, r.data[r.offset:])
		r.offset += n
		return n, nil
	}
	r.once.Do(func() { close(r.blocked) })
	<-r.release
	return 0, io.EOF
}

type coverageHandshakeStream struct {
	*coverageDuplex
	blocked chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *coverageHandshakeStream) Read(p []byte) (int, error) {
	n, err := s.coverageDuplex.Read(p)
	if err != io.EOF || n != 0 {
		return n, err
	}
	s.once.Do(func() { close(s.blocked) })
	<-s.release
	return 0, io.EOF
}

func coverageSessionData(t *testing.T, manifest Manifest, frames ...Frame) ([]byte, *Session) {
	t.Helper()
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	shared := bytes.Repeat([]byte{8}, 32)
	sender, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	var result []byte
	for _, frame := range frames {
		var wire []byte
		var sealErr error
		if frame.Kind == HeartbeatMessage {
			wire, sealErr = sender.SealHeartbeat()
		} else {
			wire, sealErr = sender.Seal(frame)
		}
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		result = append(result, wire...)
	}
	sender.Close()
	return result, receiver
}

func coverageHelper(t *testing.T, child ChildProcess, starterErr error) (*Helper, Manifest, *coverageStarter) {
	t.Helper()
	manifest, signed, policy, _ := signedFixture(t)
	starter := &coverageStarter{child: child, err: starterErr}
	helper, err := NewHelperAt(signed, policy, starter, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: manifest.Services[0].Name}); err != nil {
		t.Fatal(err)
	}
	return helper, manifest, starter
}

func TestCoverageHelperValidationAndRunFrameBranches(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	if _, err := NewHelperAt(nil, policy, &coverageStarter{}, time.Now()); errorCode(err) != ErrInvalidInput {
		t.Fatal("empty signed manifest was accepted")
	}
	if _, err := NewHelperAt(signed, policy, nil, time.Now()); errorCode(err) != ErrInvalidInput {
		t.Fatal("nil child starter was accepted")
	}
	helper, _, _ := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	var nilHelper *Helper
	if errorCode(nilHelper.Bind(LaunchBinding{})) != ErrBinding {
		t.Fatal("nil helper binding was accepted")
	}
	if errorCode(helper.Bind(LaunchBinding{})) != ErrBinding {
		t.Fatal("empty launch binding was accepted")
	}
	var nilContext context.Context
	if _, err := helper.Run(nilContext, nil, nil); err == nil {
		t.Fatal("nil helper run inputs were accepted")
	}
	if _, err := helper.RunHandshake(nilContext, nil); err == nil {
		t.Fatal("nil helper handshake inputs were accepted")
	}

	heartbeat, receiver := coverageSessionData(
		t, manifest,
		Frame{Kind: HeartbeatMessage},
		Frame{Kind: SecretMessage, Key: "OTHER", Version: "1", Value: []byte("x")},
	)
	if _, err := helper.Run(context.Background(), bytes.NewReader(heartbeat), receiver); errorCode(err) != ErrKey {
		t.Fatalf("heartbeat/unknown key code=%v", errorCode(err))
	}
	receiver.Close()

	duplicate, receiver := coverageSessionData(
		t, manifest,
		Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")},
		Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("two")},
	)
	if _, err := helper.Run(context.Background(), bytes.NewReader(duplicate), receiver); errorCode(err) != ErrLifecycle {
		t.Fatalf("post-start duplicate frame code=%v", errorCode(err))
	}
	receiver.Close()

	secret, receiver := coverageSessionData(t, manifest, Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")})
	starterErrorHelper, _, _ := coverageHelper(t, newCoverageChild(0, nil, true), errCoverage)
	if _, err := starterErrorHelper.Run(context.Background(), bytes.NewReader(secret), receiver); errorCode(err) != ErrChild {
		t.Fatalf("starter error code=%v", errorCode(err))
	}
	receiver.Close()

	secret, receiver = coverageSessionData(t, manifest, Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")})
	nilChildHelper, _, _ := coverageHelper(t, nil, nil)
	if _, err := nilChildHelper.Run(context.Background(), bytes.NewReader(secret), receiver); errorCode(err) != ErrChild {
		t.Fatalf("nil child code=%v", errorCode(err))
	}
	receiver.Close()
}

func TestCoverageHelperMonitorHeartbeatSignalAndChildErrors(t *testing.T) {
	manifest, _, _, _ := signedFixture(t)
	secretAndHeartbeat, receiver := coverageSessionData(
		t, manifest,
		Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")},
		Frame{Kind: HeartbeatMessage},
	)
	child := newCoverageChild(0, nil, false)
	helper, _, starter := coverageHelper(t, child, nil)
	helper.HeartbeatTimeout = 10 * time.Second
	reader := newCoverageBlockingReader(secretAndHeartbeat)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := helper.Run(ctx, reader, receiver)
		result <- struct {
			code int
			err  error
		}{code: code, err: err}
	}()
	<-reader.blocked
	cancel()
	outcome := <-result
	close(reader.release)
	if errorCode(outcome.err) != ErrLifecycle || !child.killed || starter.values.Len() != 1 {
		t.Fatalf("heartbeat monitor outcome=%+v killed=%v values=%d", outcome, child.killed, starter.values.Len())
	}
	receiver.Close()
	starter.values.Zeroize()

	secret, receiver := coverageSessionData(
		t, manifest,
		Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")},
		Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("unexpected")},
	)
	child = newCoverageChild(0, nil, false)
	helper, _, _ = coverageHelper(t, child, nil)
	if _, err := helper.Run(context.Background(), bytes.NewReader(secret), receiver); errorCode(err) != ErrLifecycle {
		t.Fatalf("unexpected monitor frame code=%v", errorCode(err))
	}
	receiver.Close()

	secret, receiver = coverageSessionData(t, manifest, Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")})
	child = newCoverageChild(-1, errCoverage, true)
	helper, _, _ = coverageHelper(t, child, nil)
	reader = newCoverageBlockingReader(secret)
	if _, err := helper.Run(context.Background(), reader, receiver); errorCode(err) != ErrChild {
		t.Fatalf("child wait error code=%v", errorCode(err))
	}
	close(reader.release)
	receiver.Close()

	secret, receiver = coverageSessionData(t, manifest, Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("one")})
	child = newCoverageChild(0, nil, false)
	child.signalErr = errCoverage
	helper, _, _ = coverageHelper(t, child, nil)
	signals := make(chan os.Signal, 1)
	helper.Signals = signals
	signals <- os.Interrupt
	reader = newCoverageBlockingReader(secret)
	if _, err := helper.Run(context.Background(), reader, receiver); errorCode(err) != ErrLifecycle {
		t.Fatalf("signal error code=%v", errorCode(err))
	}
	close(reader.release)
	receiver.Close()
}

func TestCoverageHelperHandshakeSuccessUsesBoundSession(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	starter := &coverageStarter{child: newCoverageChild(17, nil, true)}
	helper, err := NewHelperAt(signed, policy, starter, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	base, peer := newCoverageEnvelopeStream(t, manifest, manifest.Services[0], SecretSet{items: map[string]SecretBuffer{"APP_TOKEN": {Key: "APP_TOKEN", Version: "1", Env: "APP_TOKEN", Bytes: []byte("coverage-value")}}})
	stream := &coverageHandshakeStream{coverageDuplex: base, blocked: make(chan struct{}), release: make(chan struct{})}
	code, err := helper.RunHandshake(context.Background(), stream)
	close(stream.release)
	peer.Close()
	if err != nil || code != 17 || starter.values.Len() != 1 {
		t.Fatalf("handshake code=%d err=%v values=%d", code, err, starter.values.Len())
	}
	starter.values.Zeroize()
}

// coverageBaseProvider intentionally omits VersionedReader.
type coverageBaseProvider struct{}

func (*coverageBaseProvider) Name() string                          { return "coverage" }
func (*coverageBaseProvider) Capabilities() skprovider.Capabilities { return skprovider.Capabilities{} }

func (*coverageBaseProvider) Get(context.Context, string) (*skprovider.Secret, error) {
	return nil, errCoverage
}

func (*coverageBaseProvider) GetBatch(context.Context, []string) ([]*skprovider.Secret, error) {
	return nil, errCoverage
}

func (*coverageBaseProvider) List(context.Context, string) ([]*skprovider.Secret, error) {
	return nil, errCoverage
}

func (*coverageBaseProvider) ListNames(context.Context, string) ([]string, error) {
	return nil, errCoverage
}

func (*coverageBaseProvider) Fingerprint(context.Context, string) (string, error) {
	return "", errCoverage
}

func (*coverageBaseProvider) Set(context.Context, string, string, skprovider.SecretMeta) error {
	return errCoverage
}
func (*coverageBaseProvider) Delete(context.Context, string) error { return errCoverage }
func (*coverageBaseProvider) GetHistory(context.Context, string) ([]*skprovider.Secret, error) {
	return nil, errCoverage
}
func (*coverageBaseProvider) Rollback(context.Context, string, int64) error { return errCoverage }
func (*coverageBaseProvider) Close() error                                  { return nil }

type coverageVersionedProvider struct {
	coverageBaseProvider
	result      *skprovider.Secret
	err         error
	lastKey     string
	lastVersion int64
}

func (p *coverageVersionedProvider) GetVersion(_ context.Context, key string, version int64) (*skprovider.Secret, error) {
	p.lastKey, p.lastVersion = key, version
	return p.result, p.err
}

func TestCoverageManifestValidationMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
		code   ErrorCode
	}{
		{"version", func(m *Manifest) { m.Version = "wrong" }, ErrInvalidInput},
		{"runtime", func(m *Manifest) { m.RuntimeID = "" }, ErrInvalidInput},
		{"role", func(m *Manifest) { m.Role = "" }, ErrInvalidInput},
		{"generation", func(m *Manifest) { m.Generation = 0 }, ErrInvalidInput},
		{"issued", func(m *Manifest) { m.IssuedAt = 0 }, ErrTTL},
		{"expiry-order", func(m *Manifest) { m.ExpiresAt = m.IssuedAt }, ErrTTL},
		{"expiry-ttl", func(m *Manifest) { m.ExpiresAt = m.IssuedAt + int64(MaxManifestTTL/time.Second) + 1 }, ErrTTL},
		{"nonce", func(m *Manifest) { m.Nonce = "short" }, ErrInvalidInput},
		{"no-services", func(m *Manifest) { m.Services = nil }, ErrInvalidInput},
		{"too-many-services", func(m *Manifest) { m.Services = make([]ServiceAuthority, 257) }, ErrInvalidInput},
		{"duplicate-service", func(m *Manifest) { m.Services = append(m.Services, m.Services[0]) }, ErrInvalidInput},
		{"image", func(m *Manifest) { m.Services[0].Image = "registry.example/api:latest" }, ErrInvalidInput},
		{"user", func(m *Manifest) { m.Services[0].User = "" }, ErrInvalidInput},
		{"user-nul", func(m *Manifest) { m.Services[0].User = "1000\x00" }, ErrInvalidInput},
		{"restart", func(m *Manifest) { m.Services[0].Restart = "always" }, ErrInvalidInput},
		{"stdin", func(m *Manifest) { m.Services[0].OpenStdin = false }, ErrInvalidInput},
		{"wrapper", func(m *Manifest) { m.Services[0].WrapperDigest = "bad" }, ErrInvalidInput},
		{"argv", func(m *Manifest) { m.Services[0].Argv = nil }, ErrInvalidInput},
		{"child-argv", func(m *Manifest) { m.Services[0].Child.Argv = nil }, ErrInvalidInput},
		{"child-user", func(m *Manifest) { m.Services[0].Child.User = "" }, ErrInvalidInput},
		{"child-user-nul", func(m *Manifest) { m.Services[0].Child.User = "current\x00" }, ErrInvalidInput},
		{"child-environment", func(m *Manifest) { m.Services[0].Child.Environment = map[string]string{"LOG_LEVEL": "debug"} }, ErrInvalidInput},
		{"health-interval", func(m *Manifest) { m.Services[0].Health.IntervalMS = 0 }, ErrInvalidInput},
		{"health-command", func(m *Manifest) { m.Services[0].Health.Command = nil }, ErrInvalidInput},
		{"keys", func(m *Manifest) { m.Services[0].Keys = nil }, ErrInvalidInput},
		{"key-name", func(m *Manifest) { m.Services[0].Keys[0].Name = "" }, ErrInvalidInput},
		{"key-version", func(m *Manifest) { m.Services[0].Keys[0].Version = "latest" }, ErrInvalidInput},
		{"key-environment", func(m *Manifest) { m.Services[0].Keys[0].Env = "BAD-NAME" }, ErrInvalidInput},
		{"key-order", func(m *Manifest) { m.Services[0].Keys = append(m.Services[0].Keys, m.Services[0].Keys[0]) }, ErrInvalidInput},
		{"key-environment-collision", func(m *Manifest) {
			m.Services[0].Environment["APP_TOKEN"] = "collision"
			m.Services[0].Child.Environment["APP_TOKEN"] = "collision"
		}, ErrInvalidInput},
		{"key-environment-duplicate", func(m *Manifest) {
			m.Services[0].Keys = append(m.Services[0].Keys, ManifestKey{Name: "SECOND", Version: "2", Env: "APP_TOKEN"})
		}, ErrInvalidInput},
		{"dependency-self", func(m *Manifest) { m.Services[0].Dependencies = []string{"api"} }, ErrInvalidInput},
		{"dependency-order", func(m *Manifest) { m.Services[0].Dependencies = []string{"z", "a"} }, ErrInvalidInput},
		{"network-name", func(m *Manifest) { m.Services[0].Networks = []string{"bad name"} }, ErrInvalidInput},
		{"network-order", func(m *Manifest) { m.Services[0].Networks = []string{"z", "a"} }, ErrInvalidInput},
		{"environment-secret", func(m *Manifest) {
			m.Services[0].Environment["DB_PASSWORD"] = "x"
			m.Services[0].Child.Environment["DB_PASSWORD"] = "x"
		}, ErrInvalidInput},
		{"environment-nul", func(m *Manifest) {
			m.Services[0].Environment["LOG_LEVEL"] = "x\x00"
			m.Services[0].Child.Environment["LOG_LEVEL"] = "x\x00"
		}, ErrInvalidInput},
		{"label-empty", func(m *Manifest) { m.Services[0].Labels[""] = "x" }, ErrInvalidInput},
		{"label-secret-key", func(m *Manifest) { m.Services[0].Labels["API_TOKEN"] = "x" }, ErrInvalidInput},
		{"label-secret-value", func(m *Manifest) { m.Services[0].Labels["component"] = "API_TOKEN" }, ErrInvalidInput},
		{"label-nul", func(m *Manifest) { m.Services[0].Labels["component\x00"] = "x" }, ErrInvalidInput},
	}
	for _, testCase := range cases {
		m := fixtureManifest()
		testCase.mutate(&m)
		if got := errorCode(m.Validate()); got != testCase.code {
			t.Errorf("%s: code=%v want=%v", testCase.name, got, testCase.code)
		}
	}
}

func TestCoverageManifestBindingTrustAndSignedEnvelopeFailures(t *testing.T) {
	manifest, signed, policy, private := signedFixture(t)
	validBinding := LaunchBinding{
		RuntimeID:  manifest.RuntimeID,
		Service:    "api",
		Role:       manifest.Role,
		Generation: manifest.Generation,
		ExpiresAt:  manifest.ExpiresAt,
		Nonce:      manifest.Nonce,
	}
	if err := manifest.MatchBinding(validBinding); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*LaunchBinding){
		func(binding *LaunchBinding) { binding.RuntimeID = "other" },
		func(binding *LaunchBinding) { binding.Service = "missing" },
		func(binding *LaunchBinding) { binding.Role = "other" },
		func(binding *LaunchBinding) { binding.Generation++ },
		func(binding *LaunchBinding) { binding.ExpiresAt++ },
		func(binding *LaunchBinding) { binding.Nonce = "other-nonce-123456" },
	} {
		binding := validBinding
		mutate(&binding)
		if errorCode(manifest.MatchBinding(binding)) != ErrBinding {
			t.Fatalf("binding mutation was accepted: %+v", binding)
		}
	}
	if errorCode(manifest.MatchBinding(LaunchBinding{})) != ErrBinding {
		t.Fatal("empty binding was accepted")
	}
	if err := VerifyManifest(manifest, []byte("bad"), "unknown", policy, time.Now()); errorCode(err) != ErrSignature {
		t.Fatalf("unknown signing key code=%v", errorCode(err))
	}
	signature := mustSignFixture(t, manifest, private)
	noVersions := policy
	noVersions.AllowedVersions = map[string]bool{}
	if errorCode(VerifyManifest(manifest, []byte("bad"), "fixture-key", noVersions, time.Now())) != ErrTrust {
		t.Fatal("empty trust allowlist was accepted")
	}
	deniedRole := policy
	deniedRole.AllowedRoles = map[string]bool{"other": true}
	if errorCode(VerifyManifest(manifest, signature, "fixture-key", deniedRole, time.Now())) != ErrTrust {
		t.Fatal("denied role was accepted")
	}
	deniedKeyVersion := policy
	deniedKeyVersion.KeyVersions = map[string]map[string]bool{"OTHER": {"1": true}}
	if errorCode(VerifyManifest(manifest, signature, "fixture-key", deniedKeyVersion, time.Now())) != ErrKey {
		t.Fatal("denied key version was accepted")
	}
	if _, err := SignManifest(manifest, "", private, time.Now()); errorCode(err) != ErrInvalidInput {
		t.Fatal("empty signing key id was accepted")
	}
	if _, err := SignManifest(manifest, "fixture-key", nil, time.Now()); errorCode(err) != ErrInvalidInput {
		t.Fatal("invalid private key was accepted")
	}
	parsed, err := ParseSignedManifest(signed)
	if err != nil {
		t.Fatal(err)
	}
	parsed.KeyID = ""
	mutated := mustMarshal(parsed)
	if _, err := ParseSignedManifest(mutated); errorCode(err) != ErrSignature {
		t.Fatalf("empty signed key id code=%v", errorCode(err))
	}
	parsed.KeyID = "fixture-key"
	parsed.Signature = "not-base64"
	mutated = mustMarshal(parsed)
	if _, err := VerifySignedManifest(mutated, policy, time.Now()); errorCode(err) != ErrSignature {
		t.Fatalf("bad signed signature code=%v", errorCode(err))
	}
}

func mustSignFixture(t *testing.T, manifest Manifest, private ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.Sign(private, canonical)
}

func TestCoverageTrustDocumentAndJSONObjectParserFailures(t *testing.T) {
	manifest, _, policy, _ := signedFixture(t)
	public := policy.AllowedSigningKeys["fixture-key"]
	document := TrustDocument{
		Keys:        map[string]string{"fixture-key": encodePublicKey(public)},
		Versions:    []string{ManifestVersion},
		RuntimeIDs:  []string{manifest.RuntimeID},
		Roles:       []string{manifest.Role},
		KeyVersions: map[string]map[string]bool{"APP_TOKEN": {"1": true}},
	}
	canonical := mustMarshal(document)
	loaded, err := LoadTrustDocument(canonical)
	if err != nil || len(loaded.AllowedSigningKeys) != 1 {
		t.Fatalf("valid trust document err=%v policy=%+v", err, loaded)
	}
	for _, input := range [][]byte{nil, []byte("[]"), []byte("not-json"), append([]byte(" "), canonical...)} {
		if _, err := LoadTrustDocument(input); err == nil {
			t.Fatalf("invalid trust document was accepted: %q", input)
		}
	}
	unknown := append([]byte(nil), canonical[:len(canonical)-1]...)
	unknown = append(unknown, []byte(`,"unknown":true}`)...)
	if _, err := LoadTrustDocument(unknown); errorCode(err) != ErrTrust {
		t.Fatalf("unknown trust field code=%v", errorCode(err))
	}
	badKey := document
	badKey.Keys = map[string]string{"fixture-key": "bad"}
	if _, err := LoadTrustDocument(mustMarshal(badKey)); errorCode(err) != ErrTrust {
		t.Fatal("bad trust public key was accepted")
	}
	emptyVersions := document
	emptyVersions.Versions = nil
	if _, err := LoadTrustDocument(mustMarshal(emptyVersions)); errorCode(err) != ErrTrust {
		t.Fatal("empty trust versions were accepted")
	}
	if len(boolSet(nil)) != 0 || len(boolSet([]string{"b", "a"})) != 0 || len(boolSet([]string{"a", "a"})) != 0 || len(boolSet([]string{"a"})) != 1 {
		t.Fatal("boolSet ordering contract failed")
	}
	validJSON := []byte(`{"array":[true,false,null,1.5,"text"],"object":{}}`)
	if err := validateJSONObject(validJSON); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		[]byte(`{"a":1,"a":2}`),
		[]byte(`{"a" 1}`),
		[]byte(`{"a":1 "b":2}`),
		[]byte(`{"a":[1,]}`),
		[]byte(`{"a":tru}`),
		[]byte(`{"a":1e}`),
		[]byte(`{"a":"unterminated}`),
		[]byte(`{"a":1} trailing`),
		[]byte(`{"a":`),
	} {
		if err := validateJSONObject(input); err == nil {
			t.Fatalf("malformed JSON object was accepted: %q", input)
		}
	}
}

func TestCoverageCryptoHandshakeSessionAndFrameBoundaries(t *testing.T) {
	if _, err := NewHandshake(bytes.NewReader(nil), bytes.NewReader(nil)); errorCode(err) != ErrCrypto {
		t.Fatal("multiple handshake readers were accepted")
	}
	handshake, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	public := handshake.PublicKey()
	public[0] ^= 1
	if bytes.Equal(public, handshake.PublicKey()) {
		t.Fatal("public key copy was not isolated")
	}
	if _, err := handshake.Derive(nil, nil); errorCode(err) != ErrCrypto {
		t.Fatal("invalid handshake peer was accepted")
	}
	handshake.Close()
	var nilHandshake *Handshake
	if nilHandshake.PublicKey() != nil {
		t.Fatal("nil handshake returned a public key")
	}
	nilHandshake.Close()
	if _, err := EncodeHandshake(nil); errorCode(err) != ErrCrypto {
		t.Fatal("invalid public key was encoded")
	}
	if _, err := ReadHandshake(nil); errorCode(err) != ErrCrypto {
		t.Fatal("nil handshake reader was accepted")
	}
	if _, err := ReadHandshake(bytes.NewReader([]byte("short"))); errorCode(err) != ErrCrypto {
		t.Fatal("truncated handshake was accepted")
	}
	badHandshake := append([]byte("BAD!"), bytes.Repeat([]byte{1}, x25519PublicKeySize)...)
	if _, err := ReadHandshake(bytes.NewReader(badHandshake)); errorCode(err) != ErrCrypto {
		t.Fatal("bad handshake magic was accepted")
	}

	canonical := []byte("coverage-canonical")
	shared := bytes.Repeat([]byte{4}, 32)
	for _, invalid := range []struct {
		shared []byte
		aad    []byte
	}{
		{nil, canonical},
		{shared, nil},
	} {
		if _, err := NewSession(invalid.shared, invalid.aad); errorCode(err) != ErrCrypto {
			t.Fatal("invalid session input was accepted")
		}
	}
	if _, err := NewSession(shared, canonical, bytes.NewReader(nil), bytes.NewReader(nil)); errorCode(err) != ErrCrypto {
		t.Fatal("multiple session readers were accepted")
	}
	randomSession, err := NewSession(shared, canonical, coverageFailReader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := randomSession.SealHeartbeat(); errorCode(err) != ErrCrypto {
		t.Fatal("session random failure was not classified")
	}
	var nilSession *Session
	if _, err := nilSession.Seal(Frame{}); errorCode(err) != ErrFrame {
		t.Fatal("nil session secret seal was accepted")
	}
	if _, err := nilSession.SealHeartbeat(); errorCode(err) != ErrFrame {
		t.Fatal("nil session heartbeat seal was accepted")
	}
	if _, err := nilSession.Open(nil); errorCode(err) != ErrFrame {
		t.Fatal("nil session open was accepted")
	}

	session, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range []Frame{
		{},
		{Kind: HeartbeatMessage, Key: "bad"},
		{Kind: SecretMessage, Key: "", Version: "1"},
		{Kind: SecretMessage, Key: "APP_TOKEN", Version: ""},
		{Kind: SecretMessage, Key: "APP TOKEN", Version: "1"},
		{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: bytes.Repeat([]byte{'x'}, MaxValueLength+1)},
	} {
		if _, err := session.Seal(frame); errorCode(err) != ErrFrame {
			t.Fatalf("invalid seal frame=%+v code=%v", frame, errorCode(err))
		}
	}
	if _, err := session.SealHeartbeat(); err != nil {
		t.Fatal(err)
	}
	plainSession, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := plainSession.Seal(Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("value")})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(value []byte) { value[4] = 99 },
		func(value []byte) { binary.BigEndian.PutUint64(value[5:13], 0) },
		func(value []byte) { binary.BigEndian.PutUint16(value[25:27], MaxKeyLength+1) },
		func(value []byte) { value[frameHeaderSize] = ' ' },
		func(value []byte) { binary.BigEndian.PutUint32(value[29:33], 16) },
	} {
		candidate := append([]byte(nil), wire...)
		mutate(candidate)
		receiver, receiverErr := NewSession(shared, canonical)
		if receiverErr != nil {
			t.Fatal(receiverErr)
		}
		if _, err := receiver.Open(candidate); err == nil {
			t.Fatal("invalid wire was accepted")
		}
		receiver.Close()
	}
	plainSession.Close()
	session.Close()
	randomSession.Close()
}

type coverageFailReader struct{}

func (coverageFailReader) Read([]byte) (int, error) { return 0, errCoverage }
func TestCoverageSupervisorRecoveryAndEnvelopeFailClosedBranches(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()
	runtime := newFakeRuntime()
	runtime.listErr = fail(ErrDaemon)
	supervisor := NewSupervisor(runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("coverage-value"), nil
	}))
	supervisor.Send = func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error {
		return nil
	}
	waited := false
	supervisor.WaitDaemon = func(context.Context) error {
		waited = true
		runtime.listErr = nil
		return nil
	}
	if err := supervisor.reconcileWithRecovery(context.Background(), model, manifest); err != nil || !waited {
		t.Fatalf("successful daemon recovery err=%v waited=%v", err, waited)
	}
	runtime.listErr = fail(ErrDaemon)
	supervisor.WaitDaemon = func(context.Context) error { return errCoverage }
	if errorCode(supervisor.reconcileWithRecovery(context.Background(), model, manifest)) != ErrDaemon {
		t.Fatal("daemon waiter failure was not fail-closed")
	}

	service := manifest.Services[0]
	values := SecretSet{items: map[string]SecretBuffer{service.Keys[0].Name: {
		Key: service.Keys[0].Name, Version: service.Keys[0].Version, Env: service.Keys[0].Env, Bytes: []byte("coverage-value"),
	}}}
	if errorCode(SendEnvelope(context.Background(), newCoverageDuplex([]byte("bad")), manifest, service, values)) != ErrCrypto {
		t.Fatal("invalid peer handshake was accepted")
	}
	mismatch := SecretSet{items: map[string]SecretBuffer{service.Keys[0].Name: {
		Key: service.Keys[0].Name, Version: "2", Env: service.Keys[0].Env, Bytes: []byte("coverage-value"),
	}}}
	stream, peer := newCoverageEnvelopeStream(t, manifest, service, mismatch)
	if errorCode(SendEnvelope(context.Background(), stream, manifest, service, mismatch)) != ErrKey {
		t.Fatal("secret metadata mismatch was accepted")
	}
	peer.Close()
	values.Zeroize()
	mismatch.Zeroize()
}

func TestCoverageManifestResidualCanonicalTrustAndScannerBranches(t *testing.T) {
	manifest := fixtureManifest()
	if _, err := manifest.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	invalid := manifest
	invalid.Digests.Helper = "bad"
	if _, err := invalid.CanonicalBytes(); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid canonical manifest code=%v", errorCode(err))
	}
	if _, err := invalid.Digest(); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid manifest digest code=%v", errorCode(err))
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Digests.Supervisor = "bad" },
		func(m *Manifest) { m.Services[0].Argv = []string{"ok\x00"} },
		func(m *Manifest) { m.Services[0].Child.Argv = []string{"ok\x00"} },
		func(m *Manifest) { m.Services[0].Health.TimeoutMS = 0 },
		func(m *Manifest) { m.Services[0].Health.Retries = 0 },
	} {
		candidate := fixtureManifest()
		mutate(&candidate)
		if errorCode(candidate.Validate()) != ErrInvalidInput {
			t.Fatalf("residual manifest mutation was accepted: %+v", candidate.Services[0])
		}
	}
	if validArguments([]string{"ok\x00"}) == nil || validHealth(HealthSpec{IntervalMS: 1, TimeoutMS: 1, Retries: 1, Command: []string{"ok\x00"}}) == nil {
		t.Fatal("invalid argument or health input was accepted")
	}
	if pinnedImage("registry.example/api@bad") || pinnedImage("registry.example/api") {
		t.Fatal("invalid pinned image was accepted")
	}
	public := policyPublicKeyFixture(t)
	basePolicy := TrustPolicy{
		AllowedSigningKeys: map[string]ed25519.PublicKey{"fixture-key": public},
		AllowedVersions:    map[string]bool{"v2": true},
		AllowedRuntimeIDs:  map[string]bool{"docker-prod": true},
		AllowedRoles:       map[string]bool{"prod-api": true},
		KeyVersions:        map[string]map[string]bool{"APP_TOKEN": {"1": true}},
	}
	if err := ValidateTrustPolicy(basePolicy); err != nil {
		t.Fatalf("valid trust policy rejected: %v", err)
	}
	invalidKeyID := basePolicy
	invalidKeyID.AllowedSigningKeys = map[string]ed25519.PublicKey{"": public}
	if errorCode(ValidateTrustPolicy(invalidKeyID)) != ErrTrust {
		t.Fatal("empty trust key id was accepted")
	}
	invalidKey := basePolicy
	invalidKey.AllowedSigningKeys = map[string]ed25519.PublicKey{"fixture-key": []byte("short")}
	if errorCode(ValidateTrustPolicy(invalidKey)) != ErrTrust {
		t.Fatal("short trust public key was accepted")
	}
	_, signed, policy, _ := signedFixture(t)
	parsed, err := ParseSignedManifest(signed)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Manifest.Version = "wrong"
	if _, err := ParseSignedManifest(mustMarshal(parsed)); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid signed manifest code=%v", errorCode(err))
	}
	parsed, err = ParseSignedManifest(signed)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signature = "eA=="
	if _, err := VerifySignedManifest(mustMarshal(parsed), policy, time.Now()); errorCode(err) != ErrSignature {
		t.Fatalf("short decoded signature code=%v", errorCode(err))
	}
	if err := validateJSONObject([]byte(`{"escaped":"quote\"slash\\unicode\u1234"}`)); err != nil {
		t.Fatalf("escaped JSON rejected: %v", err)
	}
}

func policyPublicKeyFixture(t *testing.T) ed25519.PublicKey {
	t.Helper()
	_, _, policy, _ := signedFixture(t)
	return append(ed25519.PublicKey(nil), policy.AllowedSigningKeys["fixture-key"]...)
}

func TestCoverageCryptoResidualSealAndReplayBranches(t *testing.T) {
	canonical := []byte("coverage-canonical")
	shared := bytes.Repeat([]byte{5}, 32)
	handshake, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake.Derive(bytes.Repeat([]byte{0}, x25519PublicKeySize), canonical); errorCode(err) != ErrCrypto {
		t.Fatal("invalid X25519 public key was accepted")
	}
	handshake.Close()
	session, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.seal(0, "", "", nil); errorCode(err) != ErrFrame {
		t.Fatal("unknown frame kind was accepted")
	}
	if _, err := session.seal(messageSecret, "", "1", nil); errorCode(err) != ErrFrame {
		t.Fatal("empty secret key was accepted")
	}
	if _, err := session.seal(messageHeartbeat, "bad", "", nil); errorCode(err) != ErrFrame {
		t.Fatal("heartbeat metadata was accepted")
	}
	if _, err := session.seal(messageSecret, "APP_TOKEN", "1", bytes.Repeat([]byte{'x'}, MaxValueLength+1)); errorCode(err) != ErrFrame {
		t.Fatal("oversized direct secret was accepted")
	}
	session.send = ^uint64(0)
	if _, err := session.SealHeartbeat(); errorCode(err) != ErrFrame {
		t.Fatal("sequence exhaustion was accepted")
	}
	session.Close()
	sender, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sender.Seal(Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("value")})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	receiver.received = ^uint64(0)
	if _, err := receiver.Open(wire); errorCode(err) != ErrReplay {
		t.Fatalf("received sequence exhaustion code=%v", errorCode(err))
	}
	sender.Close()
	receiver.Close()
}

type coverageRecoveryRuntime struct {
	*fakeRuntime
	failures map[int]error
	lists    int
}

func (r *coverageRecoveryRuntime) List(ctx context.Context, labels map[string]string) ([]Container, error) {
	r.lists++
	if err := r.failures[r.lists]; err != nil {
		return nil, err
	}
	return r.fakeRuntime.List(ctx, labels)
}

func TestCoverageSupervisorReconcileDaemonRetryAndDependencyInspectError(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()
	runtime := &coverageRecoveryRuntime{fakeRuntime: newFakeRuntime(), failures: map[int]error{2: fail(ErrDaemon)}}
	supervisor := NewSupervisor(runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("coverage-value"), nil
	}))
	supervisor.Send = func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error { return nil }
	waited := 0
	supervisor.WaitDaemon = func(context.Context) error {
		waited++
		return nil
	}
	if err := supervisor.reconcileWithRecovery(context.Background(), model, manifest); err != nil || waited != 1 {
		t.Fatalf("reconcile daemon retry err=%v waited=%d lists=%d", err, waited, runtime.lists)
	}
	twoManifest, twoModel := coverageTwoServiceFixture()
	inspectRuntime := &coverageRuntime{fakeRuntime: newFakeRuntime(), inspectErr: errCoverage}
	db := twoModel.Services[1]
	inspectRuntime.containers["db"] = ContainerState{Container: Container{ID: "db", Name: "db", Labels: ServiceLabels(twoManifest, db), Running: true, Healthy: true}}
	api := twoModel.Services[0]
	supervisor = NewSupervisor(inspectRuntime, FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil }))
	if err := supervisor.checkDependencies(context.Background(), api, map[string]ServiceSpec{"db": db}, twoManifest); errorCode(err) != ErrRuntime {
		t.Fatalf("dependency inspect error code=%v", errorCode(err))
	}
	if _, err := OrderServices([]ServiceSpec{{Name: "api"}, {Name: "api"}}); errorCode(err) != ErrRuntime {
		t.Fatal("duplicate service names were accepted")
	}
}

func TestCoverageHelperRejectsAuthenticatedFrameOpenError(t *testing.T) {
	manifest, _, _, _ := signedFixture(t)
	wire, receiver := coverageSessionData(t, manifest, Frame{
		Kind:    SecretMessage,
		Key:     "APP_TOKEN",
		Version: "1",
		Value:   []byte("one"),
	})
	wire[len(wire)-1] ^= 1
	helper, _, _ := coverageHelper(t, newCoverageChild(-1, nil, true), nil)
	if _, err := helper.Run(context.Background(), bytes.NewReader(wire), receiver); errorCode(err) != ErrCrypto {
		t.Fatalf("tampered authenticated frame code=%v", errorCode(err))
	}
	receiver.Close()
}

func TestCoverageHelperHandshakeWriteFailureIsCryptoError(t *testing.T) {
	helper, _, _ := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	stream := newCoverageDuplex(nil)
	stream.failAtWrite = 1
	if _, err := helper.RunHandshake(context.Background(), stream); errorCode(err) != ErrCrypto {
		t.Fatalf("handshake write error code=%v", errorCode(err))
	}
}

func TestCoverageCryptoRejectsHeartbeatMetadataInOpen(t *testing.T) {
	canonical := []byte("coverage-heartbeat")
	shared := bytes.Repeat([]byte{6}, 32)
	sender, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sender.SealHeartbeat()
	if err != nil {
		t.Fatal(err)
	}
	candidate := append([]byte(nil), wire[:frameHeaderSize]...)
	binary.BigEndian.PutUint16(candidate[25:27], 1)
	candidate = append(candidate, 'x')
	candidate = append(candidate, wire[frameHeaderSize:]...)
	receiver, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(candidate); errorCode(err) != ErrFrame {
		t.Fatalf("heartbeat metadata code=%v", errorCode(err))
	}
	sender.Close()
	receiver.Close()
}
