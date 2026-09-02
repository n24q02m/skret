package secretlaunch

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"
)

type Helper struct {
	Manifest          Manifest
	Service           ServiceAuthority
	CanonicalManifest []byte
	Starter           ChildStarter
	Signals           <-chan os.Signal
	HeartbeatTimeout  time.Duration
	Now               func() time.Time
	binding           LaunchBinding
}

func NewHelper(signed []byte, policy TrustPolicy, starter ChildStarter) (*Helper, error) {
	return NewHelperAt(signed, policy, starter, time.Now())
}

func NewHelperAt(signed []byte, policy TrustPolicy, starter ChildStarter, now time.Time) (*Helper, error) {
	if len(signed) == 0 || starter == nil {
		return nil, fail(ErrInvalidInput)
	}
	manifest, err := VerifySignedManifest(signed, policy, now)
	if err != nil {
		return nil, err
	}
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		return nil, err
	}
	return &Helper{
		Manifest:          manifest,
		CanonicalManifest: canonical,
		Starter:           starter,
		Now:               time.Now,
	}, nil
}

func resolveHeartbeatTimeout(health HealthSpec, configured time.Duration) (time.Duration, error) {
	if err := validHealth(health); err != nil {
		return 0, err
	}
	if configured > 0 {
		return configured, nil
	}
	return time.Duration(health.HeartbeatTimeoutMS) * time.Millisecond, nil
}

func (h *Helper) Bind(binding LaunchBinding) error {
	if h == nil {
		return fail(ErrBinding)
	}
	if err := h.Manifest.MatchBinding(binding); err != nil {
		return err
	}
	service, ok := h.Manifest.Service(binding.Service)
	if !ok {
		return fail(ErrBinding)
	}
	h.Service = service
	h.binding = binding
	return nil
}

func (h *Helper) RunHandshake(ctx context.Context, stream io.ReadWriter) (int, error) {
	if h == nil || ctx == nil || stream == nil || h.Starter == nil || h.binding.RuntimeID == "" || h.binding.Service == "" {
		return 1, fail(ErrLifecycle)
	}
	handshake, err := NewHandshake()
	if err != nil {
		return 1, err
	}
	defer handshake.Close()
	message, err := EncodeHandshake(handshake.PublicKey())
	if err != nil {
		return 1, err
	}
	if _, err := stream.Write(message); err != nil {
		Zeroize(message)
		return 1, fail(ErrCrypto)
	}
	Zeroize(message)
	peer, err := readHandshakeContext(ctx, stream)
	if err != nil {
		return 1, err
	}
	key, err := handshake.Derive(peer, h.CanonicalManifest)
	Zeroize(peer)
	if err != nil {
		return 1, err
	}
	session, err := NewSession(key, h.CanonicalManifest)
	Zeroize(key)
	if err != nil {
		return 1, err
	}
	defer session.Close()
	return h.Run(ctx, stream, session)
}

func readHandshakeContext(ctx context.Context, stream io.Reader) ([]byte, error) {
	if ctx == nil || stream == nil {
		return nil, fail(ErrLifecycle)
	}
	closer, closable := stream.(io.Closer)
	if !closable {
		return ReadHandshake(stream)
	}
	stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
	peer, err := ReadHandshake(stream)
	stop()
	if ctx.Err() != nil {
		Zeroize(peer)
		return nil, fail(ErrLifecycle)
	}
	return peer, err
}

func readWireFrameContext(ctx context.Context, stream io.Reader) ([]byte, error) {
	if ctx == nil || stream == nil {
		return nil, fail(ErrLifecycle)
	}
	closer, closable := stream.(io.Closer)
	if !closable {
		return readWireFrame(stream)
	}
	stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
	wire, err := readWireFrame(stream)
	stop()
	if ctx.Err() != nil {
		Zeroize(wire)
		return nil, fail(ErrLifecycle)
	}
	return wire, err
}
func (h *Helper) Run(ctx context.Context, stream io.Reader, session *Session) (int, error) {
	if h == nil || ctx == nil || h.Starter == nil || stream == nil || session == nil ||
		h.binding.RuntimeID == "" || h.binding.Service == "" {
		return 1, fail(ErrLifecycle)
	}
	if h.Now == nil {
		h.Now = time.Now
	}
	if err := h.Manifest.ValidateAt(h.Now()); err != nil {
		return 1, err
	}
	heartbeatTimeout, err := resolveHeartbeatTimeout(h.Service.Health, h.HeartbeatTimeout)
	if err != nil {
		return 1, err
	}
	h.HeartbeatTimeout = heartbeatTimeout
	values := SecretSet{items: make(map[string]SecretBuffer, len(h.Service.Keys))}
	defer values.Zeroize()
	byKey := make(map[string]ManifestKey, len(h.Service.Keys))
	required := make(map[string]struct{}, len(h.Service.Keys))
	for _, key := range h.Service.Keys {
		byKey[key.Name] = key
		required[key.Name] = struct{}{}
	}
	lastHeartbeat := h.Now()
	for len(required) > 0 {
		wire, err := readWireFrameContext(ctx, stream)
		if err != nil {
			return 1, fail(ErrLifecycle)
		}
		frame, err := session.Open(wire)
		Zeroize(wire)
		if err != nil {
			return 1, err
		}
		if frame.Kind == HeartbeatMessage {
			lastHeartbeat = h.Now()
			Zeroize(frame.Value)
			continue
		}
		definition, ok := byKey[frame.Key]
		if !ok || definition.Version != frame.Version {
			Zeroize(frame.Value)
			return 1, failKey(ErrKey, frame.Key)
		}
		if _, duplicate := values.items[frame.Key]; duplicate {
			Zeroize(frame.Value)
			return 1, failKey(ErrReplay, frame.Key)
		}
		values.items[frame.Key] = SecretBuffer{
			Key: definition.Name, Version: definition.Version, Env: definition.Env, Bytes: frame.Value,
		}
		delete(required, frame.Key)
	}
	if err := h.Manifest.ValidateAt(h.Now()); err != nil {
		return 1, err
	}
	child, err := h.Starter.Start(ctx, h.Service.Child, values)
	if err != nil {
		return 1, fail(ErrChild)
	}
	if child == nil {
		return 1, fail(ErrChild)
	}
	for key, item := range values.items {
		Zeroize(item.Bytes)
		item.Bytes = nil
		values.items[key] = item
	}
	return h.monitor(ctx, stream, session, child, lastHeartbeat)
}

type childResult struct {
	err  error
	code int
}

type frameResult struct {
	frame Frame
	err   error
}

func (h *Helper) monitor(ctx context.Context, stream io.Reader, session *Session, child ChildProcess, lastHeartbeat time.Time) (int, error) {
	if closer, ok := stream.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer func() {
			stop()
			_ = closer.Close()
		}()
	}
	frames := make(chan frameResult, 1)
	go func() {
		wire, err := readWireFrame(stream)
		if err != nil {
			frames <- frameResult{err: err}
			return
		}
		frame, err := session.Open(wire)
		Zeroize(wire)
		frames <- frameResult{frame: frame, err: err}
	}()
	wait := make(chan childResult, 1)
	go func() {
		err := child.Wait()
		wait <- childResult{err: err, code: child.ExitCode()}
	}()
	tick := h.HeartbeatTimeout / 4
	if tick < time.Millisecond {
		tick = time.Millisecond
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case result := <-wait:
			if result.code >= 0 {
				return result.code, nil
			}
			if result.err != nil {
				return 1, fail(ErrChild)
			}
			return 1, fail(ErrChild)
		case result := <-frames:
			if result.err != nil {
				killErr := child.KillTree()
				return h.waitAfterKill(wait, killErr)
			}
			if result.frame.Kind == HeartbeatMessage {
				lastHeartbeat = h.Now()
				Zeroize(result.frame.Value)
			} else {
				Zeroize(result.frame.Value)
				killErr := child.KillTree()
				return h.waitAfterKill(wait, killErr)
			}
			go func() {
				wire, err := readWireFrame(stream)
				if err != nil {
					frames <- frameResult{err: err}
					return
				}
				frame, err := session.Open(wire)
				Zeroize(wire)
				frames <- frameResult{frame: frame, err: err}
			}()
		case signal := <-h.Signals:
			if signal != nil {
				if err := child.Signal(signal); err != nil {
					killErr := child.KillTree()
					return h.waitAfterKill(wait, killErr)
				}
			}
		case <-ticker.C:
			if h.Now().Sub(lastHeartbeat) > h.HeartbeatTimeout {
				killErr := child.KillTree()
				return h.waitAfterKill(wait, killErr)
			}
		case <-ctx.Done():
			killErr := child.KillTree()
			return h.waitAfterKill(wait, killErr)
		}
	}
}

func (h *Helper) waitAfterKill(wait <-chan childResult, killErr error) (int, error) {
	const reapTimeout = 2 * time.Second
	timer := time.NewTimer(reapTimeout)
	defer timer.Stop()
	select {
	case waited := <-wait:
		if killErr != nil {
			return 1, fail(ErrChild)
		}
		if waited.err != nil || waited.code < 0 {
			return 1, fail(ErrChild)
		}
		return waited.code, fail(ErrLifecycle)
	case <-timer.C:
		if killErr != nil {
			return 1, fail(ErrChild)
		}
		return 1, fail(ErrLifecycle)
	}
}

func readWireFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fail(ErrFrame)
	}
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		Zeroize(header)
		return nil, err
	}
	if string(header[:4]) != frameMagic {
		Zeroize(header)
		return nil, errors.New("invalid frame")
	}
	keyLength := int(binary.BigEndian.Uint16(header[25:27]))
	versionLength := int(binary.BigEndian.Uint16(header[27:29]))
	ciphertextLength := int(binary.BigEndian.Uint32(header[29:33]))
	total := frameHeaderSize + keyLength + versionLength + ciphertextLength
	if keyLength > MaxKeyLength || versionLength > MaxKeyLength || ciphertextLength < 16 || total > MaxFrameLength {
		Zeroize(header)
		return nil, errors.New("invalid frame")
	}
	result := make([]byte, total)
	copy(result, header)
	Zeroize(header)
	if _, err := io.ReadFull(reader, result[frameHeaderSize:]); err != nil {
		Zeroize(result)
		return nil, err
	}
	return result, nil
}
