package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeChild implements supervisor for driving watchLoop without real processes.
type fakeChild struct {
	done       chan error
	terminated int
}

func (f *fakeChild) Done() <-chan error      { return f.done }
func (f *fakeChild) Terminate(time.Duration) { f.terminated++ }

// watchResult bundles the loop's return values for delivery over a channel.
type watchResult struct {
	code int
	err  error
}

// runLoop runs watchLoop in a goroutine and returns a channel that yields its
// result, so a test can drive stimuli on dep channels and assert afterwards.
func runLoop(ctx context.Context, d watchDeps, child supervisor, fp string) <-chan watchResult {
	res := make(chan watchResult, 1)
	go func() {
		code, err := watchLoop(ctx, d, child, fp)
		res <- watchResult{code, err}
	}()
	return res
}

// awaitResult fails the test if the loop does not return within a short window.
func awaitResult(t *testing.T, res <-chan watchResult) watchResult {
	t.Helper()
	select {
	case r := <-res:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return in time")
		return watchResult{}
	}
}

func TestWatchLoop_ChildExits(t *testing.T) {
	child := &fakeChild{done: make(chan error, 1)}
	deps := watchDeps{out: &bytes.Buffer{}}

	res := runLoop(context.Background(), deps, child, "A")
	child.done <- nil

	got := awaitResult(t, res)
	assert.Equal(t, 0, got.code)
	assert.NoError(t, got.err)
	assert.Equal(t, 0, child.terminated)
}

func TestWatchLoop_RestartsOnChange(t *testing.T) {
	tick := make(chan time.Time, 1)
	var out bytes.Buffer

	fps := []string{"B"} // first poll returns "B" (initial fingerprint is "A")
	fpIdx := 0
	fingerprint := func(context.Context) (string, error) {
		fp := fps[fpIdx]
		fpIdx++
		return fp, nil
	}

	const secretValue = "super-secret-value"
	list := func(context.Context) ([]*provider.Secret, error) {
		return []*provider.Secret{{Key: "API_KEY", Value: secretValue}}, nil
	}

	var capturedEnv []string
	buildEnv := func(s []*provider.Secret) []string {
		// Simulate rebuilding env from the freshly fetched secrets.
		return []string{"API_KEY=" + s[0].Value}
	}

	newChild := &fakeChild{done: make(chan error, 1)}
	spawnCount := 0
	spawn := func(env []string) (supervisor, error) {
		spawnCount++
		capturedEnv = env
		return newChild, nil
	}

	deps := watchDeps{
		fingerprint: fingerprint,
		list:        list,
		buildEnv:    buildEnv,
		spawn:       spawn,
		tick:        tick,
		grace:       time.Millisecond,
		out:         &out,
	}

	first := &fakeChild{done: make(chan error, 1)}
	res := runLoop(context.Background(), deps, first, "A")

	tick <- time.Now()   // trigger a fingerprint check -> change -> restart
	newChild.done <- nil // end the loop via the restarted child exiting

	got := awaitResult(t, res)
	assert.Equal(t, 0, got.code)
	assert.NoError(t, got.err)
	assert.Equal(t, 1, first.terminated, "original child terminated once")
	assert.Equal(t, 1, spawnCount, "spawn invoked once for restart")
	assert.Equal(t, []string{"API_KEY=" + secretValue}, capturedEnv)
	assert.Contains(t, out.String(), "secrets changed")
}

func TestWatchLoop_NoChangeNoRestart(t *testing.T) {
	tick := make(chan time.Time, 1)
	var out bytes.Buffer

	fingerprint := func(context.Context) (string, error) { return "A", nil } // same as initial

	spawnCount := 0
	deps := watchDeps{
		fingerprint: fingerprint,
		list:        func(context.Context) ([]*provider.Secret, error) { return nil, nil },
		buildEnv:    func([]*provider.Secret) []string { return nil },
		spawn: func([]string) (supervisor, error) {
			spawnCount++
			return nil, nil
		},
		tick: tick,
		out:  &out,
	}

	child := &fakeChild{done: make(chan error, 1)}
	res := runLoop(context.Background(), deps, child, "A")

	tick <- time.Now() // fingerprint unchanged -> no restart
	child.done <- nil  // end loop

	got := awaitResult(t, res)
	assert.Equal(t, 0, got.code)
	assert.NoError(t, got.err)
	assert.Equal(t, 0, child.terminated)
	assert.Equal(t, 0, spawnCount)
	assert.NotContains(t, out.String(), "secrets changed")
}

func TestWatchLoop_Signal(t *testing.T) {
	signals := make(chan os.Signal, 1)
	child := &fakeChild{done: make(chan error, 1)}
	deps := watchDeps{
		signals: signals,
		grace:   time.Millisecond,
		out:     &bytes.Buffer{},
	}

	res := runLoop(context.Background(), deps, child, "A")
	signals <- os.Interrupt

	got := awaitResult(t, res)
	assert.Equal(t, 0, got.code)
	assert.NoError(t, got.err)
	assert.Equal(t, 1, child.terminated)
}

func TestWatchLoop_FingerprintErrorContinues(t *testing.T) {
	tick := make(chan time.Time, 1)
	spawnCount := 0
	deps := watchDeps{
		fingerprint: func(context.Context) (string, error) {
			return "", errors.New("transient backend error")
		},
		spawn: func([]string) (supervisor, error) {
			spawnCount++
			return nil, nil
		},
		tick: tick,
		out:  &bytes.Buffer{},
	}

	child := &fakeChild{done: make(chan error, 1)}
	res := runLoop(context.Background(), deps, child, "A")

	tick <- time.Now() // fingerprint errors -> keep child, no restart
	child.done <- nil  // end loop

	got := awaitResult(t, res)
	assert.Equal(t, 0, got.code)
	assert.NoError(t, got.err)
	assert.Equal(t, 0, child.terminated)
	assert.Equal(t, 0, spawnCount)
}

func TestWatchLoop_NoValueLeak(t *testing.T) {
	tick := make(chan time.Time, 1)
	var out bytes.Buffer

	const secretValue = "leaky-secret-do-not-print"
	fpIdx := 0
	deps := watchDeps{
		fingerprint: func(context.Context) (string, error) {
			fpIdx++
			return "changed", nil // differs from initial "A"
		},
		list: func(context.Context) ([]*provider.Secret, error) {
			return []*provider.Secret{{Key: "TOKEN", Value: secretValue}}, nil
		},
		buildEnv: func(s []*provider.Secret) []string {
			return []string{"TOKEN=" + s[0].Value}
		},
		tick:  tick,
		grace: time.Millisecond,
		out:   &out,
	}

	newChild := &fakeChild{done: make(chan error, 1)}
	deps.spawn = func([]string) (supervisor, error) { return newChild, nil }

	first := &fakeChild{done: make(chan error, 1)}
	res := runLoop(context.Background(), deps, first, "A")

	tick <- time.Now()
	newChild.done <- nil

	awaitResult(t, res)
	assert.NotContains(t, out.String(), secretValue, "secret value must never be printed")
}

func TestWatchLoop_ListErrorReturns(t *testing.T) {
	tick := make(chan time.Time, 1)
	deps := watchDeps{
		fingerprint: func(context.Context) (string, error) { return "changed", nil },
		list: func(context.Context) ([]*provider.Secret, error) {
			return nil, errors.New("list failed")
		},
		buildEnv: func([]*provider.Secret) []string { return nil },
		spawn:    func([]string) (supervisor, error) { return nil, nil },
		tick:     tick,
		grace:    time.Millisecond,
		out:      &bytes.Buffer{},
	}

	child := &fakeChild{done: make(chan error, 1)}
	res := runLoop(context.Background(), deps, child, "A")
	tick <- time.Now()

	got := awaitResult(t, res)
	assert.Equal(t, 1, got.code)
	require.Error(t, got.err)
	assert.Equal(t, 1, child.terminated, "child terminated before the failed re-fetch")
}

func TestWatchLoop_SpawnErrorReturns(t *testing.T) {
	tick := make(chan time.Time, 1)
	deps := watchDeps{
		fingerprint: func(context.Context) (string, error) { return "changed", nil },
		list:        func(context.Context) ([]*provider.Secret, error) { return nil, nil },
		buildEnv:    func([]*provider.Secret) []string { return nil },
		spawn: func([]string) (supervisor, error) {
			return nil, errors.New("spawn failed")
		},
		tick:  tick,
		grace: time.Millisecond,
		out:   &bytes.Buffer{},
	}

	child := &fakeChild{done: make(chan error, 1)}
	res := runLoop(context.Background(), deps, child, "A")
	tick <- time.Now()

	got := awaitResult(t, res)
	assert.Equal(t, 1, got.code)
	require.Error(t, got.err)
}

// TestRunCmd_WatchFlagsRegistered asserts the --watch and --watch-interval
// flags are wired onto the run command, leaving the non-watch path untouched.
func TestRunCmd_WatchFlagsRegistered(t *testing.T) {
	cmd := newRunCmd(&GlobalOpts{})

	watchFlag := cmd.Flags().Lookup("watch")
	require.NotNil(t, watchFlag, "--watch flag must be registered")
	assert.Equal(t, "false", watchFlag.DefValue)

	intervalFlag := cmd.Flags().Lookup("watch-interval")
	require.NotNil(t, intervalFlag, "--watch-interval flag must be registered")
	assert.Equal(t, "15s", intervalFlag.DefValue)
}

// TestRunWatch_Integration_ChildExits exercises the real runWatch wiring
// (LookPath -> Fingerprint -> Supervise -> watchLoop -> exit mapping) against a
// local provider, using the test binary itself as a fast-exiting child (see the
// SKRET_RUN_CHILD branch in TestMain). It restarts nothing because the child
// exits before the watch interval elapses.
func TestRunWatch_Integration_ChildExits(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	t.Setenv("SKRET_RUN_CHILD", "0") // the spawned test binary exits 0 immediately

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"run", "--watch", "--watch-interval", "10s", "--", os.Args[0]})
	require.NoError(t, cmd.Execute())
}

// TestRunWatch_Integration_NonZeroExit asserts the child's non-zero exit code
// surfaces as a run error (the `code != 0` branch in runWatch).
func TestRunWatch_Integration_NonZeroExit(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	t.Setenv("SKRET_RUN_CHILD", "7") // the spawned test binary exits 7

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"run", "--watch", "--watch-interval", "10s", "--", os.Args[0]})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "7")
}
