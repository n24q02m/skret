package secretlaunch

import (
	"bytes"
	"sync"
	"testing"
)

func TestX25519HKDFAESGCMRoundTripAndReplayRejection(t *testing.T) {
	manifest := fixtureManifest()
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	left, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewHandshake()
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	leftKey, err := left.Derive(right.PublicKey(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	rightKey, err := right.Derive(left.PublicKey(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftKey, rightKey) {
		t.Fatal("X25519 peers derived different keys")
	}
	leftSession, err := NewSession(leftKey, canonical)
	if err != nil {
		t.Fatal(err)
	}
	rightSession, err := NewSession(rightKey, canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer leftSession.Close()
	defer rightSession.Close()
	wire, err := leftSession.Seal(Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "v1", Value: []byte("synthetic-sentinel")})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := rightSession.Open(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame.Value) != "synthetic-sentinel" || frame.Key != "APP_TOKEN" || frame.Version != "v1" {
		t.Fatalf("unexpected frame metadata: %+v", frame)
	}
	Zeroize(frame.Value)
	if _, err := rightSession.Open(wire); errorCode(err) != ErrReplay {
		t.Fatalf("replay code = %v", errorCode(err))
	}
	heartbeat, err := leftSession.SealHeartbeat()
	if err != nil {
		t.Fatal(err)
	}
	openedHeartbeat, err := rightSession.Open(heartbeat)
	if err != nil || openedHeartbeat.Kind != HeartbeatMessage {
		t.Fatalf("heartbeat open = %v", err)
	}
	Zeroize(wire)
	Zeroize(heartbeat)
}

func TestEnvelopeRejectsManifestAADTamperCiphertextTamperAndBounds(t *testing.T) {
	manifest := fixtureManifest()
	canonical, _ := manifest.canonicalBytesUnchecked()
	other := fixtureManifest()
	other.Role = "candidate-api"
	otherCanonical, _ := other.canonicalBytesUnchecked()
	shared := bytes.Repeat([]byte{9}, 32)
	seal, err := NewSession(shared, canonical, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	openWithOtherAAD, err := NewSession(shared, otherCanonical)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := seal.Seal(Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "v1", Value: []byte("synthetic-sentinel")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWithOtherAAD.Open(wire); errorCode(err) != ErrCrypto {
		t.Fatalf("AAD tamper code = %v", errorCode(err))
	}
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 1
	openWithOriginalAAD, _ := NewSession(shared, canonical)
	if _, err := openWithOriginalAAD.Open(tampered); errorCode(err) != ErrCrypto {
		t.Fatalf("ciphertext tamper code = %v", errorCode(err))
	}
	if _, err := seal.Seal(Frame{Kind: SecretMessage, Key: string(bytes.Repeat([]byte{'k'}, MaxKeyLength+1)), Version: "v1", Value: []byte("x")}); errorCode(err) != ErrFrame {
		t.Fatalf("key bound code = %v", errorCode(err))
	}
	if _, err := seal.Seal(Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "v1", Value: bytes.Repeat([]byte{'x'}, MaxValueLength+1)}); errorCode(err) != ErrFrame {
		t.Fatalf("value bound code = %v", errorCode(err))
	}
	seal.Close()
	openWithOtherAAD.Close()
	openWithOriginalAAD.Close()
	Zeroize(shared)
	Zeroize(wire)
	Zeroize(tampered)
}

func TestZeroizeErasesEnvelopeBuffer(t *testing.T) {
	buffer := []byte("synthetic-sentinel")
	Zeroize(buffer)
	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatal("buffer still contains plaintext after zeroization")
	}
}

type gatedRandomReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gatedRandomReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	for i := range p {
		p[i] = 1
	}
	return len(p), nil
}

func TestSessionCloseSynchronizesWithSeal(t *testing.T) {
	reader := &gatedRandomReader{started: make(chan struct{}), release: make(chan struct{})}
	session, err := NewSession(bytes.Repeat([]byte{7}, 32), []byte("canonical"), reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed := make(chan struct{})
	go func() {
		_, _ = session.Seal(Frame{Kind: SecretMessage, Key: "APP_TOKEN", Version: "1", Value: []byte("value")})
		close(sealed)
	}()
	<-reader.started
	closed := make(chan struct{})
	go func() {
		session.Close()
		close(closed)
	}()
	close(reader.release)
	<-sealed
	<-closed
}
