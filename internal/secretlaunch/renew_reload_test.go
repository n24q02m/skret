package secretlaunch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"testing"
	"time"
)

func TestHelperHandshakeAcceptsPeerHoldingRenewedWindow(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	starter := &coverageStarter{child: newCoverageChild(17, nil, true)}
	helper, err := NewHelperAt(signed, policy, starter, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
		t.Fatal(err)
	}
	values := SecretSet{items: map[string]SecretBuffer{
		"APP_TOKEN": {Key: "APP_TOKEN", Version: "1", Env: "APP_TOKEN", Bytes: []byte("coverage-value")},
	}}
	base, peer := newCoverageEnvelopeStream(t, renewedWindow(manifest), manifest.Services[0], values)
	stream := &coverageHandshakeStream{coverageDuplex: base, blocked: make(chan struct{}), release: make(chan struct{})}
	code, err := helper.RunHandshake(context.Background(), stream)
	close(stream.release)
	peer.Close()
	if err != nil || code != 17 || starter.values.Len() != 1 {
		t.Fatalf("handshake across windows code=%d err=%v values=%d", code, err, starter.values.Len())
	}
	starter.values.Zeroize()
}

type reloadHarness struct {
	supervisor *Supervisor
	clock      time.Time
	sends      int
	errs       []error
}

func newReloadHarness(manifest Manifest) *reloadHarness {
	h := &reloadHarness{clock: time.Unix(manifest.IssuedAt+60, 0)}
	h.supervisor = NewSupervisor(newFakeRuntime(), FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("synthetic-sentinel"), nil
	}))
	h.supervisor.ReconcileInterval = time.Millisecond
	h.supervisor.Now = func() time.Time { return h.clock }
	h.supervisor.Send = func(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error {
		h.sends++
		return nil
	}
	h.supervisor.OnReloadError = func(err error) { h.errs = append(h.errs, err) }
	return h
}

func TestSupervisorRunSurvivesExpiryThroughReload(t *testing.T) {
	manifest := fixtureManifest()
	h := newReloadHarness(manifest)
	reloads := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.supervisor.Reload = func(context.Context) (Manifest, error) {
		reloads++
		if reloads == 1 {
			h.clock = time.Unix(manifest.ExpiresAt+5, 0) // the original window is over
		}
		if reloads == 5 {
			cancel()
		}
		renewed := manifest
		renewed.IssuedAt = manifest.ExpiresAt
		renewed.ExpiresAt = manifest.ExpiresAt + 600
		return renewed, nil
	}
	if err := h.supervisor.Run(ctx, fixtureModel(), manifest); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if h.sends != 1 || len(h.errs) != 0 {
		t.Fatalf("containers must survive renewal: sends=%d errs=%v", h.sends, h.errs)
	}
}

func TestSupervisorRunRejectsUnacceptableReloadsAndFailsClosedAtExpiry(t *testing.T) {
	manifest := fixtureManifest()
	cases := map[string]struct {
		candidate func(Manifest) Manifest
		code      ErrorCode
	}{
		"other generation": {func(m Manifest) Manifest { m.Generation++; m.IssuedAt = m.ExpiresAt; m.ExpiresAt += 600; return m }, ErrBinding},
		"earlier expiry":   {func(m Manifest) Manifest { m.ExpiresAt--; m.IssuedAt--; return m }, ErrExpired},
		"unchanged":        {func(m Manifest) Manifest { return m }, ErrExpired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newReloadHarness(manifest)
			h.supervisor.Reload = func(context.Context) (Manifest, error) {
				h.clock = time.Unix(manifest.ExpiresAt+5, 0)
				return tc.candidate(manifest), nil
			}
			err := h.supervisor.Run(context.Background(), fixtureModel(), manifest)
			if errorCode(err) != ErrExpired {
				t.Fatalf("Run must fail closed at expiry, got %v", err)
			}
			if len(h.errs) == 0 || errorCode(h.errs[0]) != tc.code {
				t.Fatalf("reload errors = %v, want first code %s", h.errs, tc.code)
			}
		})
	}
}

func TestSupervisorRunRollbackReloadIsReportedAndIgnored(t *testing.T) {
	manifest := fixtureManifest()
	h := newReloadHarness(manifest)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	h.supervisor.Reload = func(context.Context) (Manifest, error) {
		calls++
		if calls == 3 {
			cancel()
		}
		older := manifest
		older.ExpiresAt--
		return older, nil
	}
	if err := h.supervisor.Run(ctx, fixtureModel(), manifest); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if len(h.errs) == 0 || errorCode(h.errs[0]) != ErrReplay {
		t.Fatalf("reload errors = %v", h.errs)
	}
}

func TestSupervisorRunReportsReloadFailureAndKeepsRunning(t *testing.T) {
	manifest := fixtureManifest()
	h := newReloadHarness(manifest)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failure := errors.New("manifest unavailable")
	calls := 0
	h.supervisor.Reload = func(context.Context) (Manifest, error) {
		calls++
		if calls == 3 {
			cancel()
		}
		return Manifest{}, failure
	}
	if err := h.supervisor.Run(ctx, fixtureModel(), manifest); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if len(h.errs) == 0 || !errors.Is(h.errs[0], failure) {
		t.Fatalf("reload errors = %v", h.errs)
	}
}

func TestSupervisorRunToleratesMissingReloadAndMissingReporter(t *testing.T) {
	manifest := fixtureManifest()
	silent := newReloadHarness(manifest)
	silent.supervisor.OnReloadError = nil
	silent.supervisor.Reload = func(context.Context) (Manifest, error) { return Manifest{}, errors.New("x") }
	silent.clock = time.Unix(manifest.ExpiresAt+5, 0)
	if err := silent.supervisor.Run(context.Background(), fixtureModel(), manifest); errorCode(err) != ErrExpired {
		t.Fatalf("Run with silent reporter = %v", err)
	}
	bare := newReloadHarness(manifest)
	bare.clock = time.Unix(manifest.ExpiresAt+5, 0)
	if err := bare.supervisor.Run(context.Background(), fixtureModel(), manifest); errorCode(err) != ErrExpired {
		t.Fatalf("Run without reload = %v", err)
	}
}

func TestRenewSignedManifest(t *testing.T) {
	manifest, template, policy, private := signedFixture(t)
	now := time.Unix(manifest.IssuedAt+120, 0)

	out, err := RenewSignedManifest(template, policy, private, now, 10*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := VerifySignedManifest(out, policy, now)
	if err != nil {
		t.Fatalf("renewed manifest does not verify: %v", err)
	}
	if renewed.IssuedAt != now.Unix() || renewed.ExpiresAt != now.Add(10*time.Minute).Unix() {
		t.Fatalf("window = [%d,%d]", renewed.IssuedAt, renewed.ExpiresAt)
	}
	if err := AcceptRenewal(manifest, renewed, now); err != nil {
		t.Fatalf("renewal not accepted: %v", err)
	}
	if bytes.Contains(out, private) {
		t.Fatal("output leaks key material")
	}

	// A template whose own window is long over is still a valid template.
	later := now.Add(30 * time.Minute)
	if _, err := RenewSignedManifest(template, policy, private, later, 10*time.Minute, time.Hour); err != nil {
		t.Fatalf("expired template within max age: %v", err)
	}
	// A renewed manifest is itself a valid template for the next renewal.
	if _, err := RenewSignedManifest(out, policy, private, later, 10*time.Minute, time.Hour); err != nil {
		t.Fatalf("renewal of renewal: %v", err)
	}

	_, stranger, _ := ed25519.GenerateKey(cryptorand.Reader)
	narrow := policy
	narrow.AllowedRuntimeIDs = map[string]bool{"other": true}
	badSignature := mustMarshal(func() SignedManifest {
		signed, _ := ParseSignedManifest(template)
		signed.Signature = "!!"
		return signed
	}())
	failures := map[string]struct {
		run  func() error
		code ErrorCode
	}{
		"max age exceeded": {func() error {
			_, e := RenewSignedManifest(template, policy, private, now.Add(2*time.Hour), time.Minute, time.Hour)
			return e
		}, ErrExpired},
		"zero max age": {func() error {
			_, e := RenewSignedManifest(template, policy, private, now, time.Minute, 0)
			return e
		}, ErrInvalidInput},
		"template from the future": {func() error {
			_, e := RenewSignedManifest(template, policy, private, time.Unix(manifest.IssuedAt-10, 0), time.Minute, time.Hour)
			return e
		}, ErrNotYetValid},
		"ttl over cap": {func() error {
			_, e := RenewSignedManifest(template, policy, private, now, MaxManifestTTL+time.Second, time.Hour)
			return e
		}, ErrTTL},
		"short key": {func() error {
			_, e := RenewSignedManifest(template, policy, private[:10], now, time.Minute, time.Hour)
			return e
		}, ErrInvalidInput},
		"garbage template": {func() error {
			_, e := RenewSignedManifest([]byte("{}"), policy, private, now, time.Minute, time.Hour)
			return e
		}, ErrCanonical},
		"key not trusted for template": {func() error {
			_, e := RenewSignedManifest(template, policy, stranger, now, time.Minute, time.Hour)
			return e
		}, ErrSignature},
		"tampered template": {func() error {
			tampered := bytes.Replace(template, []byte(`"generation":7`), []byte(`"generation":8`), 1)
			_, e := RenewSignedManifest(tampered, policy, private, now, time.Minute, time.Hour)
			return e
		}, ErrSignature},
		"bad signature encoding": {func() error {
			_, e := RenewSignedManifest(badSignature, policy, private, now, time.Minute, time.Hour)
			return e
		}, ErrSignature},
		"untrusted runtime": {func() error {
			_, e := RenewSignedManifest(template, narrow, private, now, time.Minute, time.Hour)
			return e
		}, ErrTrust},
	}
	for name, tc := range failures {
		if err := tc.run(); errorCode(err) != tc.code {
			t.Errorf("%s: err = %v, want code %s", name, err, tc.code)
		}
	}
}
