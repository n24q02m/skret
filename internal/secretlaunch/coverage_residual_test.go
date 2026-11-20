package secretlaunch

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
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
)

// residualSecretFrame is a well-formed secret frame for key at version "1".
// The value is a fixed placeholder, never a real secret.
func residualSecretFrame(key string) Frame {
	return Frame{Kind: SecretMessage, Key: key, Version: "1", Value: []byte("residual-value")}
}

func residualProvider() FetchFunc {
	return FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("residual-value"), nil
	})
}

func residualValues(service ServiceAuthority, value []byte) SecretSet {
	key := service.Keys[0]
	return SecretSet{items: map[string]SecretBuffer{key.Name: {Key: key.Name, Version: key.Version, Env: key.Env, Bytes: value}}}
}

func residualEnvelopeStream(t *testing.T, peerPublic []byte) *coverageDuplex {
	t.Helper()
	message, err := EncodeHandshake(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	return newCoverageDuplex(message)
}

func residualHasCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

// residualClosableReader serves data, then blocks until it is closed. It counts
// Close calls so a test can observe every close path without sleeping.
type residualClosableReader struct {
	mu        sync.Mutex
	data      []byte
	offset    int
	closes    int
	blocked   chan struct{}
	closed    chan struct{}
	twice     chan struct{}
	blockOnce sync.Once
}

func newResidualClosableReader(data []byte) *residualClosableReader {
	return &residualClosableReader{
		data:    append([]byte(nil), data...),
		blocked: make(chan struct{}),
		closed:  make(chan struct{}),
		twice:   make(chan struct{}),
	}
}

func (r *residualClosableReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.offset < len(r.data) {
		n := copy(p, r.data[r.offset:])
		r.offset += n
		r.mu.Unlock()
		return n, nil
	}
	r.mu.Unlock()
	r.blockOnce.Do(func() { close(r.blocked) })
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *residualClosableReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes++
	switch r.closes {
	case 1:
		close(r.closed)
	case 2:
		close(r.twice)
	}
	return nil
}

type residualRenderRuntime struct {
	*fakeRuntime
	rendered RenderedModel
}

func (r *residualRenderRuntime) Render(context.Context, RenderedModel) (RenderedModel, error) {
	return r.rendered, nil
}

// A nil *LaunchError still renders a value-free message instead of panicking.
func TestResidualNilLaunchErrorMessage(t *testing.T) {
	var launchErr *LaunchError
	if got := launchErr.Error(); got != "secret launch: unknown failure" {
		t.Fatalf("nil launch error message = %q", got)
	}
}

// NewHandshake accepts an explicit entropy source and yields an X25519 key.
func TestResidualHandshakeWithExplicitRandom(t *testing.T) {
	handshake, err := NewHandshake(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer handshake.Close()
	if got := len(handshake.PublicKey()); got != x25519PublicKeySize {
		t.Fatalf("public key length = %d", got)
	}
}

// A closed session refuses to seal or open, a frame with a foreign magic is a
// frame error, and a nil session closes without panicking.
func TestResidualSessionClosedAndBadMagic(t *testing.T) {
	var nilSession *Session
	nilSession.Close()

	shared := bytes.Repeat([]byte{3}, 32)
	canonical := []byte("residual-canonical")
	session, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	badMagic := make([]byte, frameHeaderSize+16)
	copy(badMagic, "BAD!")
	if _, err := session.Open(badMagic); errorCode(err) != ErrFrame {
		t.Fatalf("bad magic code = %v", errorCode(err))
	}
	wire, err := session.SealHeartbeat()
	if err != nil {
		t.Fatal(err)
	}
	session.Close()
	if _, err := session.SealHeartbeat(); errorCode(err) != ErrFrame {
		t.Fatalf("seal after close code = %v", errorCode(err))
	}
	if _, err := session.Open(wire); errorCode(err) != ErrFrame {
		t.Fatalf("open after close code = %v", errorCode(err))
	}
}

// An authenticated heartbeat that carries plaintext is rejected and does not
// advance the replay counter, so the genuine first heartbeat still opens.
func TestResidualHeartbeatWithPlaintextIsRejected(t *testing.T) {
	shared := bytes.Repeat([]byte{4}, 32)
	canonical := []byte("residual-heartbeat")
	receiver, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	header := make([]byte, frameHeaderSize)
	copy(header, frameMagic)
	header[4] = messageHeartbeat
	binary.BigEndian.PutUint64(header[5:13], 1)
	binary.BigEndian.PutUint32(header[29:33], uint32(1+16))
	block, err := aes.NewCipher(receiver.key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, header[13:25], []byte{1}, makeAAD(receiver.aad, header, "", ""))
	forged := append(append([]byte(nil), header...), sealed...)
	if _, err := receiver.Open(forged); errorCode(err) != ErrFrame {
		t.Fatalf("heartbeat with plaintext code = %v", errorCode(err))
	}
	sender, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	genuine, err := sender.SealHeartbeat()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := receiver.Open(genuine)
	if err != nil || frame.Kind != HeartbeatMessage || frame.Sequence != 1 {
		t.Fatalf("genuine heartbeat kind=%d seq=%d err=%v", frame.Kind, frame.Sequence, err)
	}
}

// readWireFrame rejects a frame whose ciphertext is shorter than a GCM tag.
func TestResidualReadWireFrameRejectsShortCiphertext(t *testing.T) {
	header := make([]byte, frameHeaderSize)
	copy(header, frameMagic)
	_, err := readWireFrame(bytes.NewReader(header))
	if err == nil || err.Error() != "invalid frame" {
		t.Fatalf("short ciphertext error = %v", err)
	}
}

// A peer that sends the all-zero X25519 point fails key derivation.
func TestResidualHelperHandshakeRejectsLowOrderPeer(t *testing.T) {
	helper, _, starter := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	peer := append([]byte(handshakeMagic), make([]byte, x25519PublicKeySize)...)
	if _, err := helper.RunHandshake(context.Background(), newCoverageDuplex(peer)); errorCode(err) != ErrCrypto {
		t.Fatalf("low-order peer code = %v", errorCode(err))
	}
	if starter.values.items != nil {
		t.Fatal("child started after a failed handshake")
	}
}

// Run falls back to the wall clock when Now is unset and returns the child's
// exit status once all keys have arrived.
func TestResidualHelperRunDefaultsClock(t *testing.T) {
	helper, manifest, _ := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	reader := newCoverageBlockingReader(wire)
	defer close(reader.release)
	helper.Now = nil
	code, err := helper.Run(context.Background(), reader, receiver)
	if err != nil || code != 0 {
		t.Fatalf("run code=%d err=%v", code, err)
	}
	if helper.Now == nil {
		t.Fatal("Run did not install the default clock")
	}
}

// Run refuses an expired manifest and an invalid health contract before it
// reads any frame.
func TestResidualHelperRunRejectsExpiryAndHealth(t *testing.T) {
	helper, manifest, _ := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	_, receiver := coverageSessionData(t, manifest)
	defer receiver.Close()
	helper.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := helper.Run(context.Background(), bytes.NewReader(nil), receiver); errorCode(err) != ErrExpired {
		t.Fatalf("expired manifest code = %v", errorCode(err))
	}
	helper.Now = time.Now
	helper.Service.Health = HealthSpec{}
	if _, err := helper.Run(context.Background(), bytes.NewReader(nil), receiver); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid health code = %v", errorCode(err))
	}
}

// A key delivered twice is a replay, reported with the key name and before
// any child starts.
func TestResidualHelperRunRejectsDuplicateKey(t *testing.T) {
	helper, manifest, starter := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	helper.Service.Keys = append(append([]ManifestKey(nil), helper.Service.Keys...),
		ManifestKey{Name: "OTHER_TOKEN", Version: "1", Env: "OTHER_TOKEN"})
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"), residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	_, err := helper.Run(context.Background(), bytes.NewReader(wire), receiver)
	var launchErr *LaunchError
	if !errors.As(err, &launchErr) || launchErr.Code != ErrReplay || launchErr.Key != "APP_TOKEN" {
		t.Fatalf("duplicate key error = %v", err)
	}
	if starter.values.items != nil {
		t.Fatal("child started after a replayed key")
	}
}

// The manifest window is checked again after the frames arrive; expiry in
// between stops the launch before the child starts.
func TestResidualHelperRunRechecksExpiryBeforeStart(t *testing.T) {
	helper, manifest, starter := coverageHelper(t, newCoverageChild(0, nil, true), nil)
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	calls := 0
	helper.Now = func() time.Time {
		calls++
		if calls >= 3 {
			return time.Now().Add(time.Hour)
		}
		return time.Now()
	}
	if _, err := helper.Run(context.Background(), bytes.NewReader(wire), receiver); errorCode(err) != ErrExpired {
		t.Fatalf("late expiry code = %v", errorCode(err))
	}
	if starter.values.items != nil {
		t.Fatal("child started after the manifest expired")
	}
}

// A child that reports a negative exit code without an error is a child
// failure, not a success.
func TestResidualHelperMonitorNegativeExitCode(t *testing.T) {
	helper, manifest, _ := coverageHelper(t, newCoverageChild(-1, nil, true), nil)
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	reader := newCoverageBlockingReader(wire)
	defer close(reader.release)
	if _, err := helper.Run(context.Background(), reader, receiver); errorCode(err) != ErrChild {
		t.Fatalf("negative exit code = %v", errorCode(err))
	}
}

// After a heartbeat, the monitor keeps reading; a secret frame on the live
// channel kills the child tree and ends the launch as a lifecycle failure.
func TestResidualHelperMonitorSecretAfterHeartbeatKills(t *testing.T) {
	child := newCoverageChild(0, nil, false)
	helper, manifest, _ := coverageHelper(t, child, nil)
	wire, receiver := coverageSessionData(t, manifest,
		residualSecretFrame("APP_TOKEN"), Frame{Kind: HeartbeatMessage}, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	code, err := helper.Run(context.Background(), bytes.NewReader(wire), receiver)
	if code != 0 || errorCode(err) != ErrLifecycle {
		t.Fatalf("secret after heartbeat code=%d err=%v", code, err)
	}
	child.mu.Lock()
	killed := child.killed
	child.mu.Unlock()
	if !killed {
		t.Fatal("child tree was not killed")
	}
}

// When the channel closes and the killed child then reports a wait error, the
// launch is a child failure.
func TestResidualHelperMonitorWaitErrorAfterKill(t *testing.T) {
	child := newCoverageChild(0, errCoverage, false)
	helper, manifest, _ := coverageHelper(t, child, nil)
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	if _, err := helper.Run(context.Background(), bytes.NewReader(wire), receiver); errorCode(err) != ErrChild {
		t.Fatalf("wait error after kill code = %v", errorCode(err))
	}
}

// A sub-millisecond heartbeat timeout still ticks (floored to 1ms) and kills
// the child when no heartbeat arrives.
func TestResidualHelperMonitorTickFloorKillsOnMissedHeartbeat(t *testing.T) {
	child := newCoverageChild(0, nil, false)
	helper, manifest, _ := coverageHelper(t, child, nil)
	helper.HeartbeatTimeout = 2 * time.Microsecond
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	reader := newCoverageBlockingReader(wire)
	defer close(reader.release)
	code, err := helper.Run(context.Background(), reader, receiver)
	if code != 0 || errorCode(err) != ErrLifecycle {
		t.Fatalf("missed heartbeat code=%d err=%v", code, err)
	}
	child.mu.Lock()
	killed := child.killed
	child.mu.Unlock()
	if !killed {
		t.Fatal("child tree was not killed")
	}
}

// residualLateHookContext is a cancellable context whose context.AfterFunc
// callbacks start only after release is closed. Go starts an AfterFunc
// callback in its own goroutine after cancellation, so code that also selects
// on Done can see the cancellation before the callback runs. This context
// pins that order instead of leaving it to the scheduler.
type residualLateHookContext struct {
	done       chan struct{}
	release    chan struct{}
	cancelOnce sync.Once
	releaseOne sync.Once
}

func newResidualLateHookContext() *residualLateHookContext {
	return &residualLateHookContext{done: make(chan struct{}), release: make(chan struct{})}
}

func (c *residualLateHookContext) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *residualLateHookContext) Done() <-chan struct{} { return c.done }

func (c *residualLateHookContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func (c *residualLateHookContext) Value(any) any { return nil }

func (c *residualLateHookContext) cancel() { c.cancelOnce.Do(func() { close(c.done) }) }

func (c *residualLateHookContext) releaseHooks() { c.releaseOne.Do(func() { close(c.release) }) }

// AfterFunc is the method context.AfterFunc uses on a parent that provides
// it: f runs once the context is cancelled and the hooks are released, unless
// the returned stop function runs first.
func (c *residualLateHookContext) AfterFunc(f func()) func() bool {
	var once sync.Once
	go func() {
		<-c.done
		<-c.release
		once.Do(f)
	}()
	return func() bool {
		stopped := false
		once.Do(func() { stopped = true })
		return stopped
	}
}

// residualHookGatedChild releases the late context hooks when it is killed
// and reports its exit only after the stream has been closed. The monitor
// therefore cannot return, and stop the hook, before the hook has run.
type residualHookGatedChild struct {
	*coverageChild
	stream  *residualClosableReader
	release func()
}

func (c *residualHookGatedChild) KillTree() error {
	err := c.coverageChild.KillTree()
	c.release()
	return err
}

func (c *residualHookGatedChild) Wait() error {
	<-c.stream.closed
	return c.coverageChild.Wait()
}

// Cancelling the context while the monitor waits closes the closable channel
// (from the context hook and again on return) and kills the child. The monitor
// sees the cancellation before the hook starts, the order that a busy
// scheduler can produce with a real context.
func TestResidualHelperMonitorCancellationClosesStream(t *testing.T) {
	ctx := newResidualLateHookContext()
	defer ctx.releaseHooks()
	child := &residualHookGatedChild{coverageChild: newCoverageChild(0, nil, false), release: ctx.releaseHooks}
	helper, manifest, _ := coverageHelper(t, child, nil)
	wire, receiver := coverageSessionData(t, manifest, residualSecretFrame("APP_TOKEN"))
	defer receiver.Close()
	stream := newResidualClosableReader(wire)
	child.stream = stream
	type runResult struct {
		code int
		err  error
	}
	done := make(chan runResult, 1)
	go func() {
		code, err := helper.Run(ctx, stream, receiver)
		done <- runResult{code: code, err: err}
	}()
	select {
	case <-stream.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("monitor never waited on the channel")
	}
	ctx.cancel()
	select {
	case result := <-done:
		if result.code != 0 || errorCode(result.err) != ErrLifecycle {
			t.Fatalf("cancelled run code=%d err=%v", result.code, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled run did not return")
	}
	select {
	case <-stream.twice:
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not closed by both the context hook and the monitor")
	}
}

// If the killed child is never reaped, waitAfterKill gives up after its reap
// timeout: a kill error is a child failure, otherwise a lifecycle failure.
func TestResidualHelperWaitAfterKillReapTimeout(t *testing.T) {
	for _, test := range []struct {
		name    string
		killErr error
		want    ErrorCode
	}{
		{name: "kill failed", killErr: errCoverage, want: ErrChild},
		{name: "kill succeeded", killErr: nil, want: ErrLifecycle},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			code, err := (&Helper{}).waitAfterKill(make(chan childResult), test.killErr)
			if code != 1 || errorCode(err) != test.want {
				t.Fatalf("reap timeout code=%d err=%v", code, err)
			}
		})
	}
}

// A tracked stream without an underlying stream reads as closed and closes
// cleanly.
func TestResidualTrackedStreamWithoutStream(t *testing.T) {
	stream := newTrackedStream(nil)
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close error = %v", err)
	}
	if !stream.isClosed() {
		t.Fatal("stream not marked closed")
	}
}

// Reconcile refuses a model whose compose digest does not bind it to the
// manifest, and a runtime render that differs from the signed model, before
// listing any container.
func TestResidualReconcileRejectsUnboundModels(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()
	model.ComposeDigest = digestFixture("e")
	runtime := newFakeRuntime()
	if _, err := NewSupervisor(runtime, residualProvider()).Reconcile(context.Background(), model, manifest); errorCode(err) != ErrBinding {
		t.Fatalf("tampered model code = %v", errorCode(err))
	}
	_, twoModel := coverageTwoServiceFixture()
	rendering := &residualRenderRuntime{fakeRuntime: newFakeRuntime(), rendered: twoModel}
	if _, err := NewSupervisor(rendering, residualProvider()).Reconcile(context.Background(), fixtureModel(), manifest); errorCode(err) != ErrBinding {
		t.Fatalf("drifted render code = %v", errorCode(err))
	}
	if len(runtime.calls) != 0 || len(rendering.calls) != 0 {
		t.Fatalf("runtime touched: %v %v", runtime.calls, rendering.calls)
	}
}

// A dependency cycle that passes manifest validation is rejected by ordering
// before anything is created.
func TestResidualReconcileRejectsDependencyCycle(t *testing.T) {
	manifest, _ := coverageTwoServiceFixture()
	manifest.Services[1].Dependencies = []string{"api"}
	model := RenderedModel{RuntimeID: manifest.RuntimeID, Services: []ServiceSpec{
		serviceSpecFromAuthority(&manifest.Services[0]), serviceSpecFromAuthority(&manifest.Services[1]),
	}}
	digest, err := ModelDigest(model)
	if err != nil {
		t.Fatal(err)
	}
	model.ComposeDigest = digest
	manifest.Digests.Compose = digest
	runtime := newFakeRuntime()
	if _, err := NewSupervisor(runtime, residualProvider()).Reconcile(context.Background(), model, manifest); errorCode(err) != ErrRuntime {
		t.Fatalf("dependency cycle code = %v", errorCode(err))
	}
	for _, call := range runtime.calls {
		if strings.HasPrefix(call, "create:") {
			t.Fatalf("created despite cycle: %v", runtime.calls)
		}
	}
	if _, err := OrderServices([]ServiceSpec{{Name: "api", Dependencies: []string{"missing"}}}); errorCode(err) != ErrRuntime {
		t.Fatalf("missing dependency code = %v", errorCode(err))
	}
}

// Containers of a future generation, or owned containers without a service
// label, are neither reused nor swept.
func TestResidualReconcileKeepsUnsweepableContainers(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()
	future := OwnershipScopeLabels(manifest)
	future["com.skret.secret-launch.service"] = "api"
	future["com.skret.secret-launch.generation"] = "8"
	future["com.skret.secret-launch.nonce"] = "nonce-future-0000001"
	future["com.skret.secret-launch.manifest"] = digestFixture("f")
	runtime := newFakeRuntime()
	runtime.containers["future"] = ContainerState{Container: Container{ID: "future", Name: "future", Labels: future, Running: true}}
	runtime.containers["unlabeled"] = ContainerState{Container: Container{ID: "unlabeled", Name: "unlabeled", Labels: OwnershipLabels(manifest), Running: true}}
	supervisor := NewSupervisor(runtime, residualProvider())
	supervisor.Send = noopSend
	result, err := supervisor.Reconcile(context.Background(), model, manifest)
	if err != nil || result.Removed != 0 || len(result.Created) != 1 || result.Created[0] != "api" {
		t.Fatalf("reconcile result=%+v err=%v", result, err)
	}
	for _, id := range []string{"future", "unlabeled"} {
		if _, ok := runtime.containers[id]; !ok {
			t.Fatalf("container %s was removed", id)
		}
	}
}

// A fetch failure for a later service zeroizes the values already fetched for
// earlier services and reports the failing key.
func TestResidualReconcileFetchFailureZeroizesFetched(t *testing.T) {
	manifest, model := coverageTwoServiceFixture()
	first := []byte("residual-first")
	calls := 0
	provider := FetchFunc(func(context.Context, string, string) ([]byte, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, errCoverage
	})
	runtime := newFakeRuntime()
	_, err := NewSupervisor(runtime, provider).Reconcile(context.Background(), model, manifest)
	var launchErr *LaunchError
	if !errors.As(err, &launchErr) || launchErr.Code != ErrFetch || launchErr.Key != "APP_TOKEN" {
		t.Fatalf("fetch failure error = %v", err)
	}
	if !bytes.Equal(first, make([]byte, len(first))) {
		t.Fatal("fetched value was not zeroized")
	}
	for _, call := range runtime.calls {
		if strings.HasPrefix(call, "create:") {
			t.Fatalf("created after fetch failure: %v", runtime.calls)
		}
	}
}

// Runtime failures while sweeping a stale owned container, checking a
// dependency, or creating a container abort the reconcile with that failure.
func TestResidualReconcileRuntimeFailures(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()

	stale := newFakeRuntime()
	stale.containers["gone"] = ContainerState{Container: Container{ID: "gone", Name: "gone", Labels: LaunchLabels(manifest, ServiceSpec{Name: "gone"})}}
	stale.removeErr = errCoverage
	supervisor := NewSupervisor(stale, residualProvider())
	supervisor.Send = noopSend
	if _, err := supervisor.Reconcile(context.Background(), model, manifest); !errors.Is(err, errCoverage) {
		t.Fatalf("stale remove error = %v", err)
	}
	if !residualHasCall(stale.calls, "remove:gone") || residualHasCall(stale.calls, "create:cid-api") {
		t.Fatalf("stale remove calls = %v", stale.calls)
	}

	twoManifest, twoModel := coverageTwoServiceFixture()
	inspecting := &coverageRuntime{fakeRuntime: newFakeRuntime(), inspectErr: errCoverage}
	supervisor = NewSupervisor(inspecting, residualProvider())
	supervisor.Send = noopSend
	if _, err := supervisor.Reconcile(context.Background(), twoModel, twoManifest); errorCode(err) != ErrRuntime {
		t.Fatalf("dependency inspect code = %v", errorCode(err))
	}
	if !residualHasCall(inspecting.calls, "create:cid-db") || residualHasCall(inspecting.calls, "create:cid-api") {
		t.Fatalf("dependency inspect calls = %v", inspecting.calls)
	}

	creating := &coverageRuntime{fakeRuntime: newFakeRuntime(), createErr: errCoverage}
	supervisor = NewSupervisor(creating, residualProvider())
	supervisor.Send = noopSend
	if _, err := supervisor.Reconcile(context.Background(), model, manifest); !errors.Is(err, errCoverage) {
		t.Fatalf("create error = %v", err)
	}
}

// With Send and Now unset, the supervisor uses SendEnvelope and the wall
// clock; a channel that never answers the handshake gets the container
// killed and removed.
func TestResidualReconcileDefaultSenderAndClock(t *testing.T) {
	runtime := newFakeRuntime()
	supervisor := NewSupervisor(runtime, residualProvider())
	supervisor.Send = nil
	supervisor.Now = nil
	if _, err := supervisor.Reconcile(context.Background(), fixtureModel(), fixtureManifest()); errorCode(err) != ErrCrypto {
		t.Fatalf("default sender code = %v", errorCode(err))
	}
	if !residualHasCall(runtime.calls, "kill:cid-api") || !residualHasCall(runtime.calls, "remove:cid-api") {
		t.Fatalf("failed send cleanup calls = %v", runtime.calls)
	}
}

// Two services start in dependency order; an owned container that matches no
// dependency name is skipped by the dependency check.
func TestResidualReconcileDependencyCheckSkipsOtherContainers(t *testing.T) {
	manifest, model := coverageTwoServiceFixture()
	runtime := newFakeRuntime()
	runtime.containers["extra"] = ContainerState{Container: Container{ID: "extra", Name: "extra", Labels: OwnershipLabels(manifest), Running: true, Healthy: true}}
	supervisor := NewSupervisor(runtime, residualProvider())
	supervisor.Send = noopSend
	result, err := supervisor.Reconcile(context.Background(), model, manifest)
	if err != nil || len(result.Created) != 2 || result.Created[0] != "db" || result.Created[1] != "api" {
		t.Fatalf("two-service result=%+v err=%v", result, err)
	}
	if _, ok := runtime.containers["extra"]; !ok {
		t.Fatal("unrelated owned container was removed")
	}
}

// Run rejects a nil supervisor and a nil context.
func TestResidualSupervisorRunRejectsNilInputs(t *testing.T) {
	var nilContext context.Context
	if err := NewSupervisor(newFakeRuntime(), residualProvider()).Run(nilContext, fixtureModel(), fixtureManifest()); errorCode(err) != ErrRuntime {
		t.Fatalf("nil context code = %v", errorCode(err))
	}
	var nilSupervisor *Supervisor
	if err := nilSupervisor.Run(context.Background(), fixtureModel(), fixtureManifest()); errorCode(err) != ErrRuntime {
		t.Fatalf("nil supervisor code = %v", errorCode(err))
	}
}

// When waiting for the daemon fails, recovery returns the context error if the
// context ended, otherwise a daemon error.
func TestResidualReconcileRecoveryWaitFailures(t *testing.T) {
	manifest := fixtureManifest()
	model := fixtureModel()

	listing := newFakeRuntime()
	listing.listErr = fail(ErrDaemon)
	supervisor := NewSupervisor(listing, residualProvider())
	ctx, cancel := context.WithCancel(context.Background())
	supervisor.WaitDaemon = func(context.Context) error {
		cancel()
		return errCoverage
	}
	if err := supervisor.reconcileWithRecovery(ctx, model, manifest); !errors.Is(err, context.Canceled) {
		t.Fatalf("scavenge wait error = %v", err)
	}

	rendering := &coverageRuntime{fakeRuntime: newFakeRuntime(), renderErr: fail(ErrDaemon)}
	supervisor = NewSupervisor(rendering, residualProvider())
	waits := 0
	supervisor.WaitDaemon = func(context.Context) error {
		waits++
		return errCoverage
	}
	if err := supervisor.reconcileWithRecovery(context.Background(), model, manifest); errorCode(err) != ErrDaemon || waits != 1 {
		t.Fatalf("reconcile wait code=%v waits=%d", errorCode(err), waits)
	}

	ctx, cancel = context.WithCancel(context.Background())
	supervisor.WaitDaemon = func(context.Context) error {
		cancel()
		return errCoverage
	}
	if err := supervisor.reconcileWithRecovery(ctx, model, manifest); !errors.Is(err, context.Canceled) {
		t.Fatalf("reconcile wait cancelled error = %v", err)
	}
}

// ScavengeOrphans stops at the first removal failure and reports it.
func TestResidualScavengeRemoveFailure(t *testing.T) {
	manifest := fixtureManifest()
	runtime := newFakeRuntime()
	runtime.containers["orphan"] = ContainerState{Container: Container{ID: "orphan", Name: "orphan", Labels: OwnershipLabels(manifest)}}
	runtime.removeErr = errCoverage
	removed, err := NewSupervisor(runtime, residualProvider()).ScavengeOrphans(context.Background(), OwnershipLabels(manifest))
	if removed != 0 || !errors.Is(err, errCoverage) {
		t.Fatalf("scavenge removed=%d err=%v", removed, err)
	}
}

// SendEnvelope fails closed on a low-order peer, an oversized value, and an
// invalid health contract.
func TestResidualSendEnvelopeRejectsBadInputs(t *testing.T) {
	manifest := fixtureManifest()
	service := manifest.Services[0]

	lowOrder := residualEnvelopeStream(t, make([]byte, x25519PublicKeySize))
	values := residualValues(service, []byte("residual-value"))
	if err := SendEnvelope(context.Background(), lowOrder, manifest, service, values); errorCode(err) != ErrCrypto {
		t.Fatalf("low-order peer code = %v", errorCode(err))
	}
	values.Zeroize()

	peer, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	oversized := residualValues(service, bytes.Repeat([]byte{'x'}, MaxValueLength+1))
	if err := SendEnvelope(context.Background(), residualEnvelopeStream(t, peer.PublicKey()), manifest, service, oversized); errorCode(err) != ErrFrame {
		t.Fatalf("oversized value code = %v", errorCode(err))
	}
	oversized.Zeroize()

	unhealthy := fixtureManifest()
	unhealthy.Services[0].Health = HealthSpec{}
	unhealthyService := unhealthy.Services[0]
	stream := residualEnvelopeStream(t, peer.PublicKey())
	values = residualValues(unhealthyService, []byte("residual-value"))
	if err := SendEnvelope(context.Background(), stream, unhealthy, unhealthyService, values); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid health code = %v", errorCode(err))
	}
	values.Zeroize()
	if got := len(stream.snapshotWrites()); got != 2 {
		t.Fatalf("writes before health check = %d", got)
	}
}

// A failed first heartbeat closes the channel and fails the envelope; a failed
// later heartbeat closes the channel from the heartbeat loop.
func TestResidualSendEnvelopeHeartbeatWriteFailures(t *testing.T) {
	peer, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	manifest := fixtureManifest()
	service := manifest.Services[0]
	first := residualEnvelopeStream(t, peer.PublicKey())
	first.failAtWrite = 3
	values := residualValues(service, []byte("residual-value"))
	if err := SendEnvelope(context.Background(), first, manifest, service, values); errorCode(err) != ErrCrypto {
		t.Fatalf("first heartbeat code = %v", errorCode(err))
	}
	values.Zeroize()
	select {
	case <-first.closedCh:
	default:
		t.Fatal("channel left open after first heartbeat failure")
	}

	fast := fixtureManifest()
	fast.Services[0].Health.HeartbeatIntervalMS = 1
	fast.Services[0].Health.HeartbeatTimeoutMS = 5
	fastService := fast.Services[0]
	later := residualEnvelopeStream(t, peer.PublicKey())
	later.failAtWrite = 4
	values = residualValues(fastService, []byte("residual-value"))
	if err := SendEnvelope(context.Background(), later, fast, fastService, values); err != nil {
		t.Fatalf("envelope error = %v", err)
	}
	values.Zeroize()
	select {
	case <-later.closedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("channel left open after a later heartbeat failure")
	}
	if got := len(later.snapshotWrites()); got != 3 {
		t.Fatalf("writes before failed heartbeat = %d", got)
	}
}

// Docker runtime: Render returns a valid model unchanged, Inspect maps a
// runner failure to a daemon error, Create rejects an invalid spec.
func TestResidualDockerRuntimeBoundaries(t *testing.T) {
	model := fixtureModel()
	rendered, err := (&DockerRuntime{}).Render(context.Background(), model)
	if err != nil || rendered.ComposeDigest != model.ComposeDigest || !reflectDeepEqualServices(rendered.Services, model.Services) {
		t.Fatalf("render err=%v", err)
	}
	runner := &coverageCommandRunner{handler: func([]string) ([]byte, error) { return nil, errCoverage }}
	docker := &DockerRuntime{Binary: "docker", Runner: runner, ExplicitInvoke: true}
	if _, err := docker.Inspect(context.Background(), "cid"); errorCode(err) != ErrDaemon {
		t.Fatalf("inspect runner failure code = %v", errorCode(err))
	}
	if _, err := docker.Create(context.Background(), ServiceSpec{}, nil); errorCode(err) != ErrRuntime {
		t.Fatalf("invalid create spec code = %v", errorCode(err))
	}
	if got := runner.lastCall(); len(got) == 0 || got[1] != "inspect" {
		t.Fatalf("runner calls ended with %v", got)
	}
}

// Rendered-model validation: digest binding, empty and unsorted models, and
// secret-like environment names are rejected.
func TestResidualRenderedModelValidation(t *testing.T) {
	model := fixtureModel()
	model.ComposeDigest = digestFixture("e")
	data, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderedModel(data); errorCode(err) != ErrBinding {
		t.Fatalf("unbound parsed model code = %v", errorCode(err))
	}
	if _, err := ModelDigest(RenderedModel{}); errorCode(err) != ErrRuntime {
		t.Fatalf("empty model code = %v", errorCode(err))
	}
	_, twoModel := coverageTwoServiceFixture()
	twoModel.Services[0], twoModel.Services[1] = twoModel.Services[1], twoModel.Services[0]
	if _, err := ModelDigest(twoModel); errorCode(err) != ErrRuntime {
		t.Fatalf("unsorted model code = %v", errorCode(err))
	}
	service := fixtureModel().Services[0]
	service.Environment = map[string]string{"DB_PASSWORD": "placeholder"}
	service.Child.Environment = map[string]string{"DB_PASSWORD": "placeholder"}
	var launchErr *LaunchError
	if err := validateServiceSpec(&service); !errors.As(err, &launchErr) || launchErr.Code != ErrRuntime || launchErr.Key != "DB_PASSWORD" {
		t.Fatalf("secret-like environment error = %v", err)
	}
}

// ValidateManifestModel rejects an invalid manifest, an invalid model, and a
// model whose service differs from the signed authority.
func TestResidualValidateManifestModel(t *testing.T) {
	if err := ValidateManifestModel(Manifest{}, fixtureModel()); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid manifest code = %v", errorCode(err))
	}
	if err := ValidateManifestModel(fixtureManifest(), RenderedModel{}); errorCode(err) != ErrRuntime {
		t.Fatalf("invalid model code = %v", errorCode(err))
	}
	drifted := fixtureManifest()
	drifted.Services[0].Labels = map[string]string{"com.example.component": "other"}
	if err := ValidateManifestModel(drifted, fixtureModel()); errorCode(err) != ErrBinding {
		t.Fatalf("drifted service code = %v", errorCode(err))
	}
}

// Label and clone helpers: nil stays nil, an invalid manifest owns nothing,
// and ownership checks reject missing service names and scope.
func TestResidualLabelHelpers(t *testing.T) {
	if cloneStrings(nil) != nil || cloneLabels(nil) != nil {
		t.Fatal("nil clone produced a value")
	}
	if got := OwnershipLabels(Manifest{}); len(got) != 0 {
		t.Fatalf("invalid manifest ownership labels = %v", got)
	}
	manifest := fixtureManifest()
	labels := LaunchLabels(manifest, fixtureModel().Services[0])
	if currentOwnedGeneration(labels, manifest, "") {
		t.Fatal("empty service name was owned")
	}
	if ownedGenerationInScope(map[string]string{}, OwnershipScopeLabels(manifest), manifest.Generation) {
		t.Fatal("container outside scope was owned")
	}
	if olderOwnedGeneration(labels, OwnershipScopeLabels(manifest), ServiceSpec{}, manifest.Generation) {
		t.Fatal("unnamed service matched an older generation")
	}
	if ExactLabels(map[string]string{"a": "1"}, map[string]string{"a": "2"}) {
		t.Fatal("different label values matched exactly")
	}
}

// Field validators reject a nonce with a forbidden rune, empty or overlong
// environment names, maps of different size, and uppercase digests.
func TestResidualFieldValidators(t *testing.T) {
	if validNonce("nonce-1234567890!") {
		t.Fatal("nonce with forbidden rune accepted")
	}
	if validEnvName("") || validEnvName(strings.Repeat("A", MaxKeyLength+1)) {
		t.Fatal("empty or overlong env name accepted")
	}
	if equalStringMap(map[string]string{"a": "1"}, map[string]string{}) {
		t.Fatal("maps of different size compared equal")
	}
	if validDigest("sha256:" + strings.Repeat("A", 64)) {
		t.Fatal("uppercase digest accepted")
	}
}

// ParseSignedManifest maps invalid JSON to a canonical error and unknown
// fields to an unknown-field error.
func TestResidualParseSignedManifestErrors(t *testing.T) {
	if _, err := ParseSignedManifest([]byte("{")); errorCode(err) != ErrCanonical {
		t.Fatalf("invalid json code = %v", errorCode(err))
	}
	if _, err := ParseSignedManifest([]byte(`{"unknown":1}`)); errorCode(err) != ErrUnknownField {
		t.Fatalf("unknown field code = %v", errorCode(err))
	}
}

// The strict JSON scanner rejects every malformed shape with a canonical
// error, and reports the end of an all-space document.
func TestResidualJSONScannerRejectsMalformedInput(t *testing.T) {
	if got := (&jsonScanner{data: []byte("   ")}).firstNonSpace(); got != 3 {
		t.Fatalf("first non-space of spaces = %d", got)
	}
	for _, input := range []string{
		"",
		`{1:2}`,
		`{"\x":1}`,
		`{"a" 1}`,
		`{"a":}`,
		`{"a":1`,
		`{"a":"b";}`,
		`[}`,
		`[1`,
		`["a";]`,
		`"abc`,
		`nul`,
		`1e`,
	} {
		scanner := jsonScanner{data: []byte(input)}
		if err := scanner.value(); errorCode(err) != ErrCanonical {
			t.Fatalf("input %q code = %v", input, errorCode(err))
		}
	}
}

// The skret adapter refuses a provider without exact-version reads instead of
// falling back to the latest value.
func TestResidualSkretProviderRequiresVersionedReader(t *testing.T) {
	provider := &SkretProvider{Provider: &coverageBaseProvider{}}
	if _, err := provider.Fetch(context.Background(), "APP_TOKEN", "1"); errorCode(err) != ErrNoProvider {
		t.Fatalf("unversioned provider code = %v", errorCode(err))
	}
}

// ExecStarter refuses an unknown child user, and a reaped child can no longer
// be signalled or killed.
func TestResidualExecStarterUserAndReapedChild(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	spec := ChildSpec{Argv: []string{goBinary, "version"}, User: "definitely-no-such-user-residual"}
	if _, err := (ExecStarter{}).Start(context.Background(), spec, SecretSet{}); errorCode(err) != ErrChild {
		t.Fatalf("unknown user code = %v", errorCode(err))
	}
	spec.User = "current"
	child, err := (ExecStarter{}).Start(context.Background(), spec, SecretSet{})
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := child.Signal(os.Interrupt); errorCode(err) != ErrChild {
		t.Fatalf("signal reaped child code = %v", errorCode(err))
	}
	if err := child.KillTree(); errorCode(err) != ErrChild {
		t.Fatalf("kill reaped child code = %v", errorCode(err))
	}
}
