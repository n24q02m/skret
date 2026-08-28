package secretlaunch

import (
	"bytes"
	"context"
	"testing"
)

func TestValidHealthRequiresSafeSignedHeartbeatProtocol(t *testing.T) {
	base := HealthSpec{
		Command:             []string{"/bin/true"},
		IntervalMS:          30_000,
		TimeoutMS:           5_000,
		Retries:             1,
		HeartbeatIntervalMS: 1_000,
		HeartbeatTimeoutMS:  5_000,
	}
	if err := validHealth(base); err != nil {
		t.Fatalf("safe heartbeat protocol rejected: %v", err)
	}
	for name, candidate := range map[string]HealthSpec{
		"missing cadence":      {Command: base.Command, IntervalMS: base.IntervalMS, TimeoutMS: base.TimeoutMS, Retries: base.Retries, HeartbeatTimeoutMS: base.HeartbeatTimeoutMS},
		"missing deadline":     {Command: base.Command, IntervalMS: base.IntervalMS, TimeoutMS: base.TimeoutMS, Retries: base.Retries, HeartbeatIntervalMS: base.HeartbeatIntervalMS},
		"deadline too short":   {Command: base.Command, IntervalMS: base.IntervalMS, TimeoutMS: base.TimeoutMS, Retries: base.Retries, HeartbeatIntervalMS: 2_000, HeartbeatTimeoutMS: 5_999},
		"zero health interval": {Command: base.Command, IntervalMS: 0, TimeoutMS: base.TimeoutMS, Retries: base.Retries, HeartbeatIntervalMS: base.HeartbeatIntervalMS, HeartbeatTimeoutMS: base.HeartbeatTimeoutMS},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validHealth(candidate); err == nil {
				t.Fatal("unsafe heartbeat protocol accepted")
			}
		})
	}
}

func TestSendEnvelopeSendsImmediateHeartbeatWithLongHealthInterval(t *testing.T) {
	manifest := fixtureManifest()
	service := manifest.Services[0]
	service.Health.IntervalMS = 30_000
	service.Health.HeartbeatIntervalMS = 30_000
	service.Health.HeartbeatTimeoutMS = 90_000
	manifest.Services[0] = service
	values := SecretSet{items: map[string]SecretBuffer{
		service.Keys[0].Name: {Key: service.Keys[0].Name, Version: service.Keys[0].Version, Env: service.Keys[0].Env, Bytes: []byte("heartbeat-sentinel")},
	}}
	stream, peer := newCoverageEnvelopeStream(t, manifest, service, values)
	defer stream.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := SendEnvelope(ctx, stream, manifest, service, values); err != nil {
		t.Fatalf("SendEnvelope error=%v", err)
	}
	writes := stream.snapshotWrites()
	if len(writes) != 3 {
		t.Fatalf("writes=%d, want handshake, secret, immediate heartbeat", len(writes))
	}
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	key, err := peer.Derive(writes[0][4:], canonical)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSession(key, canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	secret, err := receiver.Open(writes[1])
	if err != nil || secret.Kind != SecretMessage || !bytes.Equal(secret.Value, []byte("heartbeat-sentinel")) {
		t.Fatalf("secret frame=%+v err=%v", secret, err)
	}
	Zeroize(secret.Value)
	heartbeat, err := receiver.Open(writes[2])
	if err != nil || heartbeat.Kind != HeartbeatMessage {
		t.Fatalf("heartbeat frame=%+v err=%v", heartbeat, err)
	}
	Zeroize(heartbeat.Value)
	if service.Health.IntervalMS <= 5_000 {
		t.Fatal("test no longer exercises a health interval longer than the old watchdog")
	}
	values.Zeroize()
}
