package secretlaunch

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeChild struct {
	mu      sync.Mutex
	done    chan struct{}
	closed  bool
	code    int
	killed  bool
	signals []os.Signal
}

func newFakeChild(code int, finished bool) *fakeChild {
	child := &fakeChild{done: make(chan struct{}), code: code}
	if finished {
		close(child.done)
		child.closed = true
	}
	return child
}

func (c *fakeChild) Wait() error {
	<-c.done
	return nil
}

func (c *fakeChild) Signal(signal os.Signal) error {
	c.mu.Lock()
	c.signals = append(c.signals, signal)
	c.mu.Unlock()
	return nil
}

func (c *fakeChild) KillTree() error {
	c.mu.Lock()
	c.killed = true
	if !c.closed {
		close(c.done)
		c.closed = true
	}
	c.code = 137
	c.mu.Unlock()
	return nil
}

func (c *fakeChild) ExitCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

type fakeStarter struct {
	mu      sync.Mutex
	started int
	values  SecretSet
	child   *fakeChild
}

func (s *fakeStarter) Start(_ context.Context, _ ChildSpec, values SecretSet) (ChildProcess, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started++
	s.values = SecretSet{items: make(map[string]SecretBuffer, len(values.items))}
	for key, item := range values.items {
		s.values.items[key] = SecretBuffer{Key: item.Key, Version: item.Version, Env: item.Env, Bytes: append([]byte(nil), item.Bytes...)}
	}
	if s.child == nil {
		s.child = newFakeChild(0, true)
	}
	return s.child, nil
}

type blockingReadWriter struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingReadWriter() *blockingReadWriter {
	return &blockingReadWriter{started: make(chan struct{}), closed: make(chan struct{})}
}

func (s *blockingReadWriter) Read([]byte) (int, error) {
	s.once.Do(func() { close(s.started) })
	<-s.closed
	return 0, io.ErrClosedPipe
}

func (s *blockingReadWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *blockingReadWriter) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func (s *blockingReadWriter) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func secretWire(t *testing.T, manifest Manifest) ([]byte, *Session, *Session) {
	t.Helper()
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	shared := bytes.Repeat([]byte{3}, 32)
	sender, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSession(shared, canonical)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sender.Seal(Frame{Kind: SecretMessage, Key: manifest.Services[0].Keys[0].Name, Version: manifest.Services[0].Keys[0].Version, Value: []byte("synthetic-sentinel")})
	if err != nil {
		t.Fatal(err)
	}
	return wire, sender, receiver
}

func TestHelperDoesNotStartChildBeforeSignedVerification(t *testing.T) {
	_, signed, policy, _ := signedFixture(t)
	signed[len(signed)-3] ^= 1
	starter := &fakeStarter{}
	if _, err := NewHelper(signed, policy, starter); err == nil {
		t.Fatal("tampered manifest unexpectedly accepted")
	}
	if starter.started != 0 {
		t.Fatal("child started before manifest verification")
	}
}

func TestHelperRejectsDecryptFailureBeforeChildStart(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	starter := &fakeStarter{}
	helper, err := NewHelper(signed, policy, starter)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	wire, sender, receiver := secretWire(t, manifest)
	defer sender.Close()
	defer receiver.Close()
	wire[len(wire)-1] ^= 1
	if _, err := helper.Run(context.Background(), bytes.NewReader(wire), receiver); errorCode(err) != ErrCrypto {
		t.Fatalf("decrypt error code = %v", errorCode(err))
	}
	if starter.started != 0 {
		t.Fatal("child started after decrypt failure")
	}
	Zeroize(wire)
}

func TestHelperPreservesChildExitStatus(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	child := newFakeChild(23, true)
	starter := &fakeStarter{child: child}
	helper, err := NewHelper(signed, policy, starter)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	wire, sender, receiver := secretWire(t, manifest)
	defer sender.Close()
	defer receiver.Close()
	stream, writer := io.Pipe()
	defer stream.Close()
	defer writer.Close()
	go func() {
		_, _ = writer.Write(wire)
	}()
	code, err := helper.Run(context.Background(), stream, receiver)
	if err != nil || code != 23 {
		t.Fatalf("child status = %d, err %v", code, err)
	}
	if starter.started != 1 || !bytes.Equal(starter.values.items[manifest.Services[0].Keys[0].Name].Bytes, []byte("synthetic-sentinel")) {
		t.Fatal("child did not receive intended in-memory value")
	}
	Zeroize(wire)
	starter.values.Zeroize()
}

func TestHelperEOFKillsCompleteChildTree(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	child := newFakeChild(0, false)
	starter := &fakeStarter{child: child}
	helper, err := NewHelper(signed, policy, starter)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	helper.HeartbeatTimeout = 100 * time.Millisecond
	wire, sender, receiver := secretWire(t, manifest)
	defer sender.Close()
	defer receiver.Close()
	_, err = helper.Run(context.Background(), bytes.NewReader(wire), receiver)
	if errorCode(err) != ErrLifecycle {
		t.Fatalf("EOF error code = %v", errorCode(err))
	}
	child.mu.Lock()
	killed := child.killed
	child.mu.Unlock()
	if !killed {
		t.Fatal("EOF did not kill child tree")
	}
	Zeroize(wire)
}

type blockingReader struct {
	first  []byte
	offset int
	block  chan struct{}
}

func (r *blockingReader) Read(buffer []byte) (int, error) {
	if r.offset < len(r.first) {
		n := copy(buffer, r.first[r.offset:])
		r.offset += n
		return n, nil
	}
	<-r.block
	return 0, context.Canceled
}

func TestHelperHeartbeatLossKillsChildTree(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	child := newFakeChild(0, false)
	starter := &fakeStarter{child: child}
	helper, err := NewHelper(signed, policy, starter)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	helper.HeartbeatTimeout = 20 * time.Millisecond
	wire, sender, receiver := secretWire(t, manifest)
	defer sender.Close()
	defer receiver.Close()
	reader := &blockingReader{first: wire, block: make(chan struct{})}
	_, err = helper.Run(context.Background(), reader, receiver)
	if errorCode(err) != ErrLifecycle {
		t.Fatalf("heartbeat error code = %v", errorCode(err))
	}
	child.mu.Lock()
	killed := child.killed
	child.mu.Unlock()
	if !killed {
		t.Fatal("heartbeat loss did not kill child tree")
	}
}

func TestHelperHandshakeCancellationClosesClosableStream(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	helper, err := NewHelper(signed, policy, &fakeStarter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	stream := newBlockingReadWriter()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, runErr := helper.RunHandshake(ctx, stream)
		result <- runErr
	}()
	<-stream.started
	cancel()
	select {
	case runErr := <-result:
		if runErr == nil {
			t.Fatal("canceled handshake unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		_ = stream.Close()
		t.Fatal("canceled handshake remained blocked")
	}
	if !stream.IsClosed() {
		t.Fatal("canceled handshake did not close stream")
	}
}

func TestHelperInitialSecretCancellationClosesClosableStream(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	starter := &fakeStarter{}
	helper, err := NewHelper(signed, policy, starter)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	_, sender, receiver := secretWire(t, manifest)
	defer sender.Close()
	defer receiver.Close()
	stream := newBlockingReadWriter()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, runErr := helper.Run(ctx, stream, receiver)
		result <- runErr
	}()
	<-stream.started
	cancel()
	select {
	case runErr := <-result:
		if runErr == nil {
			t.Fatal("canceled secret intake unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		_ = stream.Close()
		t.Fatal("canceled secret intake remained blocked")
	}
	if !stream.IsClosed() {
		t.Fatal("canceled secret intake did not close stream")
	}
}

func TestHelperForwardsSignals(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	child := newFakeChild(0, false)
	starter := &fakeStarter{child: child}
	helper, err := NewHelper(signed, policy, starter)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	helper.HeartbeatTimeout = time.Second
	signals := make(chan os.Signal, 1)
	helper.Signals = signals
	wire, sender, receiver := secretWire(t, manifest)
	defer sender.Close()
	defer receiver.Close()
	result := make(chan error, 1)
	go func() {
		_, runErr := helper.Run(context.Background(), &blockingReader{first: wire, block: make(chan struct{})}, receiver)
		result <- runErr
	}()
	time.Sleep(5 * time.Millisecond)
	signals <- os.Interrupt
	time.Sleep(5 * time.Millisecond)
	_ = child.KillTree()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("helper did not stop after signal test cleanup")
	}
	child.mu.Lock()
	forwarded := len(child.signals) > 0
	child.mu.Unlock()
	if !forwarded {
		t.Fatal("signal was not forwarded")
	}
}
