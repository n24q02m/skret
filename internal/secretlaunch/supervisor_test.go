package secretlaunch

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

type fakeRuntime struct {
	mu         sync.Mutex
	containers map[string]ContainerState
	streams    map[string]*fakeStream
	calls      []string
	listErr    error
	attachErr  error
	startErr   error
	removeErr  error
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{containers: make(map[string]ContainerState), streams: make(map[string]*fakeStream)}
}

func (r *fakeRuntime) Render(_ context.Context, model RenderedModel) (RenderedModel, error) {
	return model, nil
}

func (r *fakeRuntime) List(_ context.Context, labels map[string]string) ([]Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "list")
	if r.listErr != nil {
		return nil, r.listErr
	}
	var result []Container
	for _, state := range r.containers {
		if ContainsLabels(state.Labels, labels) {
			result = append(result, state.Container)
		}
	}
	return result, nil
}

func (r *fakeRuntime) Inspect(_ context.Context, id string) (ContainerState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "inspect:"+id)
	state, ok := r.containers[id]
	if !ok {
		return ContainerState{}, fail(ErrRuntime)
	}
	return state, nil
}

func (r *fakeRuntime) Create(_ context.Context, spec ServiceSpec, labels map[string]string) (Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := "cid-" + spec.Name
	r.calls = append(r.calls, "create:"+id)
	merged := cloneLabels(spec.Labels)
	for key, value := range labels {
		merged[key] = value
	}
	container := Container{ID: id, Name: spec.Name, Labels: merged, Running: false, Healthy: false}
	r.containers[id] = ContainerState{Container: container}
	return container, nil
}

type fakeStream struct {
	bytes.Buffer
	closed bool
}

func (s *fakeStream) Close() error {
	s.closed = true
	return nil
}

func (r *fakeRuntime) Attach(_ context.Context, id string) (io.ReadWriteCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "attach:"+id)
	if r.attachErr != nil {
		return nil, r.attachErr
	}
	stream := &fakeStream{}
	r.streams[id] = stream
	return stream, nil
}

func (r *fakeRuntime) Start(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "start:"+id)
	if r.startErr != nil {
		return r.startErr
	}
	state := r.containers[id]
	state.Running = true
	state.Healthy = true
	r.containers[id] = state
	return nil
}

func (r *fakeRuntime) Kill(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "kill:"+id)
	state := r.containers[id]
	state.Running = false
	state.Healthy = false
	r.containers[id] = state
	return nil
}

func (r *fakeRuntime) Remove(_ context.Context, id string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "remove:"+id)
	if r.removeErr != nil {
		return r.removeErr
	}
	delete(r.containers, id)
	return nil
}

func TestSupervisorAttachesBeforeStartAndRefetchesPerRecreation(t *testing.T) {
	runtime := newFakeRuntime()
	fetchCalls := 0
	provider := FetchFunc(func(_ context.Context, key, version string) ([]byte, error) {
		fetchCalls++
		return []byte("synthetic-sentinel"), nil
	})
	manifest := fixtureManifest()
	model := fixtureModel()
	supervisor := NewSupervisor(runtime, provider)
	supervisor.Send = func(_ context.Context, stream io.ReadWriteCloser, _ Manifest, _ ServiceAuthority, values SecretSet) error {
		if stream == nil || values.Len() != 1 {
			t.Fatal("send received invalid stream or values")
		}
		return nil
	}
	result, err := supervisor.Reconcile(context.Background(), model, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Created) != 1 || result.Created[0] != "api" || fetchCalls != 1 {
		t.Fatalf("first reconcile = %+v, fetchCalls = %d", result, fetchCalls)
	}
	attachIndex, startIndex := -1, -1
	for i, call := range runtime.calls {
		if call == "attach:cid-api" {
			attachIndex = i
		}
		if call == "start:cid-api" {
			startIndex = i
		}
	}
	if attachIndex == -1 || startIndex == -1 || attachIndex >= startIndex {
		t.Fatalf("attach must precede start; calls = %v", runtime.calls)
	}

	// Daemon restart recreation: mark dead, reconcile again and assert exact fresh fetch.
	runtime.mu.Lock()
	state := runtime.containers["cid-api"]
	state.Running = false
	state.Healthy = false
	runtime.containers["cid-api"] = state
	runtime.calls = nil
	runtime.mu.Unlock()
	result, err = supervisor.Reconcile(context.Background(), model, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Created) != 1 || fetchCalls != 2 {
		t.Fatalf("recreated result = %+v, fetchCalls = %d", result, fetchCalls)
	}
}

func TestSupervisorScavengesOnlyExactLabelOrphans(t *testing.T) {
	runtime := newFakeRuntime()
	manifest := fixtureManifest()
	exactLabels := OwnershipLabels(manifest)
	foreignLabels := map[string]string{
		"com.skret.secret-launch":            ManifestVersion,
		"com.skret.secret-launch.role":       manifest.Role,
		"com.skret.secret-launch.generation": "8",
		"com.skret.secret-launch.nonce":      manifest.Nonce,
	}
	runtime.containers["exact-orphan"] = ContainerState{Container: Container{ID: "exact-orphan", Name: "orphan-1", Labels: exactLabels}}
	runtime.containers["foreign-orphan"] = ContainerState{Container: Container{ID: "foreign-orphan", Name: "orphan-2", Labels: foreignLabels}}
	supervisor := NewSupervisor(runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil }))
	removed, err := supervisor.ScavengeOrphans(context.Background(), exactLabels)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed count = %d", removed)
	}
	runtime.mu.Lock()
	_, exactExists := runtime.containers["exact-orphan"]
	_, foreignExists := runtime.containers["foreign-orphan"]
	runtime.mu.Unlock()
	if exactExists || !foreignExists {
		t.Fatalf("exactExists = %v, foreignExists = %v", exactExists, foreignExists)
	}
}

func TestSupervisorDaemonRestartWaitRecovery(t *testing.T) {
	runtime := newFakeRuntime()
	manifest := fixtureManifest()
	model := fixtureModel()
	provider := FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil })
	supervisor := NewSupervisor(runtime, provider)
	supervisor.Send = func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error { return nil }
	waited := false
	supervisor.WaitDaemon = func(context.Context) error {
		waited = true
		runtime.mu.Lock()
		runtime.listErr = nil
		runtime.mu.Unlock()
		return nil
	}
	runtime.listErr = fail(ErrDaemon)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = supervisor.Run(ctx, model, manifest)
	if !waited {
		t.Fatal("supervisor did not invoke daemon recovery wait")
	}
}

func TestSupervisorRunRecreatesClosedSession(t *testing.T) {
	runtime := newFakeRuntime()
	manifest := fixtureManifest()
	model := fixtureModel()
	fetchCalls := 0
	sends := 0
	provider := FetchFunc(func(context.Context, string, string) ([]byte, error) {
		fetchCalls++
		return []byte("synthetic-sentinel"), nil
	})
	supervisor := NewSupervisor(runtime, provider)
	supervisor.ReconcileInterval = time.Millisecond
	supervisor.Send = func(_ context.Context, stream io.ReadWriteCloser, _ Manifest, _ ServiceAuthority, values SecretSet) error {
		if values.Len() != 1 {
			t.Fatal("sender received incomplete values")
		}
		sends++
		_ = stream.Close()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := supervisor.Run(ctx, model, manifest); err != nil {
		t.Fatal(err)
	}
	if sends < 2 || fetchCalls < 2 {
		t.Fatalf("closed session was not recreated: sends=%d fetchCalls=%d", sends, fetchCalls)
	}
}

func TestSupervisorRunClosesTrackedSessionsOnCancellation(t *testing.T) {
	runtime := newFakeRuntime()
	manifest := fixtureManifest()
	model := fixtureModel()
	supervisor := NewSupervisor(runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("synthetic-sentinel"), nil
	}))
	supervisor.Send = func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error {
		return nil
	}
	if _, err := supervisor.Reconcile(context.Background(), model, manifest); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	stream := runtime.streams["cid-api"]
	runtime.mu.Unlock()
	if stream == nil {
		t.Fatal("reconcile did not retain attach stream")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := supervisor.Run(ctx, model, manifest); err != nil {
		t.Fatal(err)
	}
	if !stream.closed {
		t.Fatal("Run did not close tracked streams on cancellation")
	}
}

func TestSupervisorScavengeClosesTrackedOrphanStream(t *testing.T) {
	runtime := newFakeRuntime()
	manifest := fixtureManifest()
	labels := OwnershipLabels(manifest)
	stream := &fakeStream{}
	runtime.containers["exact-orphan"] = ContainerState{
		Container: Container{ID: "exact-orphan", Name: "orphan", Labels: cloneLabels(labels)},
	}
	supervisor := NewSupervisor(runtime, FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("x"), nil
	}))
	supervisor.trackSession("exact-orphan", newTrackedStream(stream))
	removed, err := supervisor.ScavengeOrphans(context.Background(), labels)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed count = %d", removed)
	}
	if !stream.closed {
		t.Fatal("scavenge did not close orphan stream")
	}
	if err := supervisor.Close(); err != nil {
		t.Fatal(err)
	}
}
