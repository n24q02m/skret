package secretlaunch

import (
	"context"
	"io"
	"reflect"
	"sort"
	"sync"
	"time"
)

type EnvelopeSender func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error

type Supervisor struct {
	Runtime           Runtime
	Provider          SecretProvider
	Send              EnvelopeSender
	Now               func() time.Time
	WaitDaemon        func(context.Context) error
	ReconcileInterval time.Duration

	mu       sync.Mutex
	sessions map[string]*trackedStream
}

type trackedStream struct {
	mu     sync.Mutex
	stream io.ReadWriteCloser
	closed bool
}

func newTrackedStream(stream io.ReadWriteCloser) *trackedStream {
	return &trackedStream{stream: stream}
}

func (s *trackedStream) Read(p []byte) (int, error) {
	if s == nil {
		return 0, io.ErrClosedPipe
	}
	s.mu.Lock()
	stream := s.stream
	closed := s.closed
	s.mu.Unlock()
	if closed || stream == nil {
		return 0, io.ErrClosedPipe
	}
	return stream.Read(p)
}

func (s *trackedStream) Write(p []byte) (int, error) {
	if s == nil {
		return 0, io.ErrClosedPipe
	}
	s.mu.Lock()
	stream := s.stream
	closed := s.closed
	s.mu.Unlock()
	if closed || stream == nil {
		return 0, io.ErrClosedPipe
	}
	return stream.Write(p)
}

func (s *trackedStream) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	stream := s.stream
	s.mu.Unlock()
	if stream == nil {
		return nil
	}
	return stream.Close()
}

func (s *trackedStream) isClosed() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type ReconcileResult struct {
	Created     []string
	Removed     int
	Reused      []string
	FetchedKeys []string
}

func NewSupervisor(runtime Runtime, provider SecretProvider) *Supervisor {
	return &Supervisor{
		Runtime: runtime, Provider: provider, Now: time.Now, Send: SendEnvelope,
		sessions: make(map[string]*trackedStream),
	}
}

func (s *Supervisor) Reconcile(ctx context.Context, model RenderedModel, manifest Manifest) (ReconcileResult, error) {
	var result ReconcileResult
	if s == nil || s.Runtime == nil || s.Provider == nil {
		return result, fail(ErrNoProvider)
	}
	if err := manifest.ValidateAt(s.now()); err != nil {
		return result, err
	}
	if err := ValidateManifestModel(manifest, model); err != nil {
		return result, err
	}
	rendered, err := s.Runtime.Render(ctx, model)
	if err != nil {
		return result, err
	}
	if err := ValidateManifestModel(manifest, rendered); err != nil {
		return result, err
	}
	commonLabels := OwnershipLabels(manifest)
	if len(commonLabels) == 0 {
		return result, fail(ErrBinding)
	}
	containers, err := s.Runtime.List(ctx, commonLabels)
	if err != nil {
		return result, err
	}
	ordered, err := OrderServices(rendered.Services)
	if err != nil {
		return result, err
	}
	serviceByName := make(map[string]ServiceSpec, len(rendered.Services))
	authorityByName := make(map[string]ServiceAuthority, len(manifest.Services))
	for _, service := range rendered.Services {
		serviceByName[service.Name] = service
	}
	for _, authority := range manifest.Services {
		authorityByName[authority.Name] = authority
	}
	if err := validateDependencies(ordered, serviceByName); err != nil {
		return result, err
	}

	matches := make(map[string][]Container, len(containers))
	for _, container := range containers {
		service, desired := serviceByName[container.Name]
		if !desired || !ExactLabels(container.Labels, ServiceLabels(manifest, service)) {
			continue
		}
		matches[container.Name] = append(matches[container.Name], container)
	}

	type pending struct {
		service   ServiceSpec
		authority ServiceAuthority
		old       []Container
		values    SecretSet
	}
	pendingServices := make([]pending, 0, len(ordered))
	for _, service := range ordered {
		existing := matches[service.Name]
		if len(existing) == 1 && existing[0].Running && s.hasSession(existing[0].ID) {
			state, inspectErr := s.Runtime.Inspect(ctx, existing[0].ID)
			if inspectErr == nil && state.Running && state.Healthy &&
				ExactLabels(state.Labels, ServiceLabels(manifest, service)) {
				result.Reused = append(result.Reused, service.Name)
				continue
			}
		}
		authority, ok := authorityByName[service.Name]
		if !ok {
			return ReconcileResult{}, fail(ErrBinding)
		}
		pendingServices = append(pendingServices, pending{
			service: service, authority: authority, old: append([]Container(nil), existing...),
		})
	}

	for i := range pendingServices {
		values, fetchErr := FetchSecrets(ctx, s.Provider, pendingServices[i].authority.Keys)
		if fetchErr != nil {
			for j := range pendingServices {
				pendingServices[j].values.Zeroize()
			}
			return ReconcileResult{}, fetchErr
		}
		pendingServices[i].values = values
		for _, key := range pendingServices[i].authority.Keys {
			result.FetchedKeys = append(result.FetchedKeys, key.Name)
		}
	}
	defer func() {
		for i := range pendingServices {
			pendingServices[i].values.Zeroize()
		}
	}()
	sort.Strings(result.FetchedKeys)
	result.FetchedKeys = uniqueStrings(result.FetchedKeys)

	for i := range pendingServices {
		pending := &pendingServices[i]
		for _, old := range pending.old {
			s.closeSession(old.ID)
			if err := s.Runtime.Remove(ctx, old.ID, true); err != nil {
				return ReconcileResult{}, err
			}
			result.Removed++
		}
		if err := s.checkDependencies(ctx, pending.service, serviceByName, manifest); err != nil {
			return ReconcileResult{}, err
		}
		labels := LaunchLabels(manifest, pending.service)
		container, createErr := s.Runtime.Create(ctx, pending.service, labels)
		if createErr != nil {
			return ReconcileResult{}, createErr
		}
		stream, attachErr := s.Runtime.Attach(ctx, container.ID)
		if attachErr != nil {
			_ = s.Runtime.Remove(ctx, container.ID, true)
			return ReconcileResult{}, attachErr
		}
		tracked := newTrackedStream(stream)
		if startErr := s.Runtime.Start(ctx, container.ID); startErr != nil {
			_ = tracked.Close()
			_ = s.Runtime.Remove(ctx, container.ID, true)
			return ReconcileResult{}, startErr
		}
		sender := s.Send
		if sender == nil {
			sender = SendEnvelope
		}
		if sendErr := sender(ctx, tracked, manifest, pending.authority, pending.values); sendErr != nil {
			_ = s.Runtime.Kill(ctx, container.ID)
			_ = tracked.Close()
			_ = s.Runtime.Remove(ctx, container.ID, true)
			return ReconcileResult{}, sendErr
		}
		s.trackSession(container.ID, tracked)
		result.Created = append(result.Created, pending.service.Name)
	}
	return result, nil
}

func (s *Supervisor) Run(ctx context.Context, model RenderedModel, manifest Manifest) error {
	if s == nil || ctx == nil {
		return fail(ErrRuntime)
	}
	defer func() { _ = s.Close() }()
	interval := s.ReconcileInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		if err := s.reconcileWithRecovery(ctx, model, manifest); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return nil
			case <-ticker.C:
				if err := s.reconcileWithRecovery(ctx, model, manifest); err != nil {
					ticker.Stop()
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
			}
		}
	}
}

func (s *Supervisor) reconcileWithRecovery(
	ctx context.Context,
	model RenderedModel,
	manifest Manifest,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := s.ScavengeOrphans(ctx, OwnershipLabels(manifest)); err != nil {
			if errorCode(err) != ErrDaemon || s.WaitDaemon == nil {
				return err
			}
			if waitErr := s.WaitDaemon(ctx); waitErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fail(ErrDaemon)
			}
			continue
		}
		if _, err := s.Reconcile(ctx, model, manifest); err == nil {
			return nil
		} else if errorCode(err) != ErrDaemon || s.WaitDaemon == nil {
			return err
		}
		if waitErr := s.WaitDaemon(ctx); waitErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fail(ErrDaemon)
		}
	}
}

func (s *Supervisor) Close() error {
	s.mu.Lock()
	sessions := s.sessions
	s.sessions = make(map[string]*trackedStream)
	s.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	return nil
}

func (s *Supervisor) ScavengeOrphans(ctx context.Context, labels map[string]string) (int, error) {
	if s == nil || s.Runtime == nil || len(labels) == 0 {
		return 0, fail(ErrRuntime)
	}
	containers, err := s.Runtime.List(ctx, labels)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, container := range containers {
		if !ExactLabels(container.Labels, labels) {
			continue
		}
		s.closeSession(container.ID)
		if err := s.Runtime.Remove(ctx, container.ID, true); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (s *Supervisor) checkDependencies(
	ctx context.Context,
	service ServiceSpec,
	all map[string]ServiceSpec,
	manifest Manifest,
) error {
	for _, dependency := range service.Dependencies {
		expected, ok := all[dependency]
		if !ok {
			return fail(ErrRuntime)
		}
		containers, err := s.Runtime.List(ctx, OwnershipLabels(manifest))
		if err != nil {
			return err
		}
		found := false
		for _, container := range containers {
			if container.Name != dependency || !ExactLabels(container.Labels, ServiceLabels(manifest, expected)) {
				continue
			}
			found = true
			state, inspectErr := s.Runtime.Inspect(ctx, container.ID)
			if inspectErr != nil || !state.Running || !state.Healthy ||
				!ExactLabels(state.Labels, ServiceLabels(manifest, expected)) {
				return fail(ErrRuntime)
			}
		}
		if !found {
			return fail(ErrRuntime)
		}
	}
	return nil
}

func (s *Supervisor) trackSession(containerID string, stream *trackedStream) {
	s.mu.Lock()
	previous := s.sessions[containerID]
	s.sessions[containerID] = stream
	s.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
}

func (s *Supervisor) hasSession(containerID string) bool {
	s.mu.Lock()
	session := s.sessions[containerID]
	s.mu.Unlock()
	return session != nil && !session.isClosed()
}

func (s *Supervisor) closeSession(containerID string) {
	s.mu.Lock()
	stream := s.sessions[containerID]
	delete(s.sessions, containerID)
	s.mu.Unlock()
	if stream != nil {
		_ = stream.Close()
	}
}

func (s *Supervisor) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func OrderServices(services []ServiceSpec) ([]ServiceSpec, error) {
	byName := make(map[string]ServiceSpec, len(services))
	for _, service := range services {
		if _, exists := byName[service.Name]; exists {
			return nil, fail(ErrRuntime)
		}
		byName[service.Name] = service
	}
	state := make(map[string]uint8, len(services))
	ordered := make([]ServiceSpec, 0, len(services))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fail(ErrRuntime)
		case 2:
			return nil
		}
		service, ok := byName[name]
		if !ok {
			return fail(ErrRuntime)
		}
		state[name] = 1
		deps := append([]string(nil), service.Dependencies...)
		sort.Strings(deps)
		for _, dependency := range deps {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[name] = 2
		ordered = append(ordered, service)
		return nil
	}
	names := make([]string, 0, len(services))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func validateDependencies(ordered []ServiceSpec, all map[string]ServiceSpec) error {
	for _, service := range ordered {
		for _, dependency := range service.Dependencies {
			if _, ok := all[dependency]; !ok {
				return fail(ErrRuntime)
			}
		}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	result := values[:0]
	last := ""
	for _, value := range values {
		if value != last {
			result = append(result, value)
			last = value
		}
	}
	return result
}

func SendEnvelope(
	ctx context.Context,
	stream io.ReadWriteCloser,
	manifest Manifest,
	service ServiceAuthority,
	values SecretSet,
) error {
	if stream == nil || values.Len() != len(service.Keys) {
		return fail(ErrCrypto)
	}
	expected, ok := manifest.Service(service.Name)
	if !ok || !serviceAuthoritiesEqual(expected, service) {
		return fail(ErrBinding)
	}
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		return err
	}
	peer, err := ReadHandshake(stream)
	if err != nil {
		return fail(ErrCrypto)
	}
	defer Zeroize(peer)
	handshake, err := NewHandshake()
	if err != nil {
		return err
	}
	defer handshake.Close()
	message, err := EncodeHandshake(handshake.PublicKey())
	if err != nil {
		return err
	}
	if _, err := stream.Write(message); err != nil {
		Zeroize(message)
		return fail(ErrCrypto)
	}
	Zeroize(message)
	key, err := handshake.Derive(peer, canonical)
	if err != nil {
		return err
	}
	defer Zeroize(key)
	session, err := NewSession(key, canonical)
	if err != nil {
		return err
	}
	for _, definition := range service.Keys {
		item, present := values.items[definition.Name]
		if !present || item.Version != definition.Version || item.Env != definition.Env {
			session.Close()
			return failKey(ErrKey, definition.Name)
		}
		wire, sealErr := session.Seal(Frame{
			Kind: SecretMessage, Key: item.Key, Version: item.Version, Value: item.Bytes,
		})
		if sealErr != nil {
			session.Close()
			return sealErr
		}
		if _, writeErr := stream.Write(wire); writeErr != nil {
			Zeroize(wire)
			session.Close()
			return fail(ErrCrypto)
		}
		Zeroize(wire)
	}
	interval := time.Duration(service.Health.IntervalMS) * time.Millisecond
	go func() {
		defer session.Close()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				wire, heartbeatErr := session.SealHeartbeat()
				if heartbeatErr != nil {
					_ = stream.Close()
					return
				}
				if _, writeErr := stream.Write(wire); writeErr != nil {
					Zeroize(wire)
					_ = stream.Close()
					return
				}
				Zeroize(wire)
			case <-ctx.Done():
				_ = stream.Close()
				return
			}
		}
	}()
	return nil
}

func serviceAuthoritiesEqual(first, second ServiceAuthority) bool {
	return reflect.DeepEqual(first, second)
}
