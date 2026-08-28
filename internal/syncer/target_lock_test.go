package syncer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireTargetLockSerializesSameTarget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	releaseFirst, err := AcquireTargetLock("cloudflare", "account/worker")
	require.NoError(t, err)
	defer releaseFirst()

	acquired := make(chan struct{})
	releaseSecond := make(chan func() error, 1)
	go func() {
		release, lockErr := AcquireTargetLock("cloudflare", "account/worker")
		if lockErr == nil {
			releaseSecond <- release
			close(acquired)
		}
	}()
	select {
	case <-acquired:
		t.Fatal("second process acquired target lock before first release")
	case <-time.After(50 * time.Millisecond):
	}

	require.NoError(t, releaseFirst())
	select {
	case <-acquired:
		release := <-releaseSecond
		require.NoError(t, release())
	case <-time.After(time.Second):
		t.Fatal("second process did not acquire target lock after first release")
	}
}
