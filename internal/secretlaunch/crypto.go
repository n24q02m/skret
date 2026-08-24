package secretlaunch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"runtime"
	"sync"
)

const (
	messageSecret       byte = 1
	messageHeartbeat    byte = 2
	handshakeMagic           = "SLH1"
	frameMagic               = "SLP1"
	handshakeSize            = 4 + 32
	frameHeaderSize          = 4 + 1 + 8 + 12 + 2 + 2 + 4
	x25519PublicKeySize      = 32
)

type Handshake struct {
	private *ecdh.PrivateKey
	public  []byte
}

func NewHandshake(random ...io.Reader) (*Handshake, error) {
	r := cryptorand.Reader
	if len(random) > 1 {
		return nil, fail(ErrCrypto)
	}
	if len(random) == 1 && random[0] != nil {
		r = random[0]
	}
	private, err := ecdh.X25519().GenerateKey(r)
	if err != nil {
		return nil, fail(ErrCrypto)
	}
	return &Handshake{private: private, public: append([]byte(nil), private.PublicKey().Bytes()...)}, nil
}

func (h *Handshake) PublicKey() []byte {
	if h == nil {
		return nil
	}
	return append([]byte(nil), h.public...)
}

func (h *Handshake) Derive(peer []byte, manifestCanonical []byte) ([]byte, error) {
	if h == nil || h.private == nil || len(peer) != x25519PublicKeySize || len(manifestCanonical) == 0 {
		return nil, fail(ErrCrypto)
	}
	public, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fail(ErrCrypto)
	}
	shared, err := h.private.ECDH(public)
	if err != nil {
		return nil, fail(ErrCrypto)
	}
	aad := sha256.Sum256(manifestCanonical)
	key := hkdfSHA256(shared, aad[:], []byte("skret secret-launch v2"), 32)
	Zeroize(shared)
	return key, nil
}

func (h *Handshake) Close() {
	if h == nil {
		return
	}
	Zeroize(h.public)
	if h.private != nil {
		private := h.private.Bytes()
		Zeroize(private)
	}
	h.private = nil
	h.public = nil
}

func EncodeHandshake(public []byte) ([]byte, error) {
	if len(public) != x25519PublicKeySize {
		return nil, fail(ErrCrypto)
	}
	result := make([]byte, handshakeSize)
	copy(result, handshakeMagic)
	copy(result[4:], public)
	return result, nil
}

func ReadHandshake(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, fail(ErrCrypto)
	}
	buffer := make([]byte, handshakeSize)
	if _, err := io.ReadFull(r, buffer); err != nil {
		Zeroize(buffer)
		return nil, fail(ErrCrypto)
	}
	if !bytes.Equal(buffer[:4], []byte(handshakeMagic)) {
		Zeroize(buffer)
		return nil, fail(ErrCrypto)
	}
	public := append([]byte(nil), buffer[4:]...)
	Zeroize(buffer)
	return public, nil
}

type MessageKind byte

const (
	SecretMessage    MessageKind = MessageKind(messageSecret)
	HeartbeatMessage MessageKind = MessageKind(messageHeartbeat)
)

type Frame struct {
	Kind     MessageKind
	Sequence uint64
	Key      string
	Version  string
	Value    []byte
}

type Session struct {
	mu       sync.Mutex
	key      []byte
	aad      []byte
	random   io.Reader
	send     uint64
	received uint64
}

func NewSession(shared, manifestCanonical []byte, random ...io.Reader) (*Session, error) {
	if len(shared) != 32 || len(manifestCanonical) == 0 || len(random) > 1 {
		return nil, fail(ErrCrypto)
	}
	r := cryptorand.Reader
	if len(random) == 1 && random[0] != nil {
		r = random[0]
	}
	digest := sha256.Sum256(manifestCanonical)
	key := hkdfSHA256(shared, digest[:], []byte("skret secret-launch v2"), 32)
	return &Session{key: key, aad: append([]byte(nil), digest[:]...), random: r}, nil
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	Zeroize(s.key)
	Zeroize(s.aad)
	s.key = nil
	s.aad = nil
	s.received = 0
}

func (s *Session) Seal(frame Frame) ([]byte, error) {
	if s == nil || frame.Kind != SecretMessage || frame.Key == "" {
		return nil, fail(ErrFrame)
	}
	if err := validateFrameFields(frame.Key, frame.Version, frame.Value); err != nil {
		return nil, err
	}
	return s.seal(messageSecret, frame.Key, frame.Version, frame.Value)
}

func (s *Session) SealHeartbeat() ([]byte, error) {
	if s == nil {
		return nil, fail(ErrFrame)
	}
	return s.seal(messageHeartbeat, "", "", nil)
}

func (s *Session) seal(kind byte, key, version string, value []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 32 || s.random == nil {
		return nil, fail(ErrFrame)
	}
	if kind != messageSecret && kind != messageHeartbeat {
		return nil, fail(ErrFrame)
	}
	if kind == messageSecret && (key == "" || validateFrameFields(key, version, value) != nil) {
		return nil, fail(ErrFrame)
	}
	if kind == messageHeartbeat && (key != "" || version != "" || len(value) != 0) {
		return nil, fail(ErrFrame)
	}
	if s.send == ^uint64(0) {
		return nil, fail(ErrFrame)
	}
	sequence := s.send + 1
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		Zeroize(nonce)
		return nil, fail(ErrCrypto)
	}
	ciphertextLength := len(value) + 16
	if ciphertextLength > MaxValueLength+16 {
		Zeroize(nonce)
		return nil, fail(ErrFrame)
	}
	if len(key) > MaxKeyLength || len(version) > MaxKeyLength {
		Zeroize(nonce)
		return nil, fail(ErrFrame)
	}
	header := make([]byte, frameHeaderSize)
	copy(header, frameMagic)
	header[4] = kind
	binary.BigEndian.PutUint64(header[5:13], sequence)
	copy(header[13:25], nonce)
	binary.BigEndian.PutUint16(header[25:27], uint16(len(key)))
	binary.BigEndian.PutUint16(header[27:29], uint16(len(version)))
	binary.BigEndian.PutUint32(header[29:33], uint32(ciphertextLength))
	aad := makeAAD(s.aad, header, key, version)
	block, err := aes.NewCipher(s.key)
	if err != nil {
		Zeroize(nonce)
		Zeroize(header)
		Zeroize(aad)
		return nil, fail(ErrCrypto)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		Zeroize(nonce)
		Zeroize(header)
		Zeroize(aad)
		return nil, fail(ErrCrypto)
	}
	sealed := gcm.Seal(nil, nonce, value, aad)
	result := make([]byte, 0, frameHeaderSize+len(key)+len(version)+len(sealed))
	result = append(result, header...)
	result = append(result, key...)
	result = append(result, version...)
	result = append(result, sealed...)
	s.send = sequence
	Zeroize(nonce)
	Zeroize(header)
	Zeroize(aad)
	Zeroize(sealed)
	return result, nil
}

func (s *Session) Open(wire []byte) (Frame, error) {
	if s == nil || len(wire) < frameHeaderSize || len(wire) > MaxFrameLength {
		return Frame{}, fail(ErrFrame)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 32 {
		return Frame{}, fail(ErrFrame)
	}
	header := wire[:frameHeaderSize]
	if !bytes.Equal(header[:4], []byte(frameMagic)) {
		return Frame{}, fail(ErrFrame)
	}
	kind := header[4]
	if kind != messageSecret && kind != messageHeartbeat {
		return Frame{}, fail(ErrFrame)
	}
	sequence := binary.BigEndian.Uint64(header[5:13])
	if sequence == 0 || s.received == ^uint64(0) || sequence != s.received+1 {
		return Frame{}, fail(ErrReplay)
	}
	keyLength := int(binary.BigEndian.Uint16(header[25:27]))
	versionLength := int(binary.BigEndian.Uint16(header[27:29]))
	ciphertextLength := int(binary.BigEndian.Uint32(header[29:33]))
	if keyLength > MaxKeyLength || versionLength > MaxKeyLength || ciphertextLength < 16 || ciphertextLength > MaxValueLength+16 {
		return Frame{}, fail(ErrFrame)
	}
	payloadLength := frameHeaderSize + keyLength + versionLength + ciphertextLength
	if payloadLength != len(wire) {
		return Frame{}, fail(ErrFrame)
	}
	key := string(wire[frameHeaderSize : frameHeaderSize+keyLength])
	versionStart := frameHeaderSize + keyLength
	version := string(wire[versionStart : versionStart+versionLength])
	if kind == messageHeartbeat && (keyLength != 0 || versionLength != 0) {
		return Frame{}, fail(ErrFrame)
	}
	if kind == messageSecret {
		if err := validateFrameFields(key, version, nil); err != nil {
			return Frame{}, err
		}
	}
	nonce := header[13:25]
	aad := makeAAD(s.aad, header, key, version)
	block, err := aes.NewCipher(s.key)
	if err != nil {
		Zeroize(aad)
		return Frame{}, fail(ErrCrypto)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		Zeroize(aad)
		return Frame{}, fail(ErrCrypto)
	}
	ciphertext := wire[versionStart+versionLength:]
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	Zeroize(aad)
	if err != nil {
		Zeroize(plain)
		return Frame{}, fail(ErrCrypto)
	}
	if kind == messageHeartbeat && len(plain) != 0 {
		Zeroize(plain)
		return Frame{}, fail(ErrFrame)
	}
	s.received = sequence
	return Frame{Kind: MessageKind(kind), Sequence: sequence, Key: key, Version: version, Value: plain}, nil
}

func validateFrameFields(key, version string, value []byte) error {
	if key == "" || len(key) > MaxKeyLength || version == "" || len(version) > MaxKeyLength {
		return fail(ErrFrame)
	}
	if len(value) > MaxValueLength {
		return fail(ErrFrame)
	}
	for _, value := range []string{key, version} {
		for _, r := range value {
			if r == 0 || r == '\r' || r == '\n' || r == '\t' || r == ' ' {
				return fail(ErrFrame)
			}
		}
	}
	return nil
}

func makeAAD(manifestAAD, header []byte, key, version string) []byte {
	aad := make([]byte, 0, len(manifestAAD)+len(header)+len(key)+len(version))
	aad = append(aad, manifestAAD...)
	aad = append(aad, header...)
	aad = append(aad, key...)
	aad = append(aad, version...)
	return aad
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer Zeroize(prk)
	result := make([]byte, 0, length)
	previous := []byte(nil)
	for counter := byte(1); len(result) < length; counter++ {
		h := hmac.New(sha256.New, prk)
		_, _ = h.Write(previous)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{counter})
		block := h.Sum(nil)
		result = append(result, block...)
		Zeroize(previous)
		previous = block
	}
	Zeroize(previous)
	return result[:length]
}

func Zeroize(buffer []byte) {
	for i := range buffer {
		buffer[i] = 0
	}
	runtime.KeepAlive(buffer)
}
