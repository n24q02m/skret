package syncer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

// coverageSetHome points os.UserHomeDir at dir for the current platform.
func coverageSetHome(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
}

// coverageCancelTransport cancels the request context from inside the round
// trip and then reports a transport failure, modelling a connection that is
// torn down because the caller gave up.
type coverageCancelTransport struct {
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (c *coverageCancelTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	c.cancel()
	return nil, errors.New("synthetic connection reset")
}

func coverageRequestFactory(ctx context.Context, method string, calls *atomic.Int32) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		calls.Add(1)
		return http.NewRequestWithContext(ctx, method, "http://provider.invalid/resource", http.NoBody)
	}
}

func TestMutationNeedsReconciliationError_NilReceiverUsesSentinel(t *testing.T) {
	var nilErr *MutationNeedsReconciliationError
	assert.Equal(t, ErrMutationNeedsReconciliation.Error(), nilErr.Error())
	assert.Equal(t, ErrMutationNeedsReconciliation, nilErr.Unwrap())
}

func TestDoWithRetry_ReportsFactoryAndCancellationFailures(t *testing.T) {
	t.Run("request factory error is returned without a round trip", func(t *testing.T) {
		factoryErr := errors.New("synthetic factory failure")
		transport := &coverageCancelTransport{cancel: func() {}}
		resp, err := doWithRetry(context.Background(), &http.Client{Transport: transport}, func() (*http.Request, error) {
			return nil, factoryErr
		}, http.StatusOK)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, factoryErr)
		assert.Zero(t, transport.calls.Load())
	})

	t.Run("transport failure after cancellation reports the context error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		transport := &coverageCancelTransport{cancel: cancel}
		var built atomic.Int32
		resp, err := doWithRetry(ctx, &http.Client{Transport: transport}, coverageRequestFactory(ctx, http.MethodGet, &built), http.StatusOK)
		assert.Nil(t, resp)
		assert.Equal(t, context.Canceled, err)
		assert.Equal(t, int32(1), transport.calls.Load())
		assert.Equal(t, int32(1), built.Load())
	})
}

func TestDoMutation_ReportsFactoryAndCancellationFailures(t *testing.T) {
	t.Run("already cancelled context never builds a request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var built atomic.Int32
		resp, err := doMutation(ctx, http.DefaultClient, coverageRequestFactory(ctx, http.MethodPut, &built), http.StatusOK)
		assert.Nil(t, resp)
		assert.Equal(t, context.Canceled, err)
		assert.Zero(t, built.Load())
	})

	t.Run("request factory error is returned unwrapped", func(t *testing.T) {
		factoryErr := errors.New("synthetic factory failure")
		transport := &coverageCancelTransport{cancel: func() {}}
		resp, err := doMutation(context.Background(), &http.Client{Transport: transport}, func() (*http.Request, error) {
			return nil, factoryErr
		}, http.StatusOK)
		assert.Nil(t, resp)
		assert.Equal(t, factoryErr, err)
		assert.Zero(t, transport.calls.Load())
	})

	t.Run("cancelled transport failure needs reconciliation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		transport := &coverageCancelTransport{cancel: cancel}
		var built atomic.Int32
		resp, err := doMutation(ctx, &http.Client{Transport: transport}, coverageRequestFactory(ctx, http.MethodPut, &built), http.StatusOK)
		assert.Nil(t, resp)
		var mutation *MutationNeedsReconciliationError
		require.ErrorAs(t, err, &mutation)
		assert.Equal(t, http.MethodPut, mutation.Method)
		assert.Zero(t, mutation.StatusCode)
		assert.Equal(t, context.Canceled, mutation.Cause)
		assert.ErrorIs(t, err, ErrMutationNeedsReconciliation)
		assert.Equal(t, "PUT mutation needs reconciliation after transport failure", err.Error())
		assert.Equal(t, int32(1), transport.calls.Load())
	})
}

func TestGitLabSyncer_ReportsRequestAndResponseFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid key stops sync before any request", func(t *testing.T) {
		transport := &coverageCancelTransport{cancel: func() {}}
		gl := &GitLabSyncer{projectID: "1", token: "t", baseURL: "http://gitlab.invalid", httpClient: &http.Client{Transport: transport}}
		err := gl.Sync(ctx, []*provider.Secret{{Key: "/a/bad-key", Value: "v"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a valid GitLab CI/CD variable name")
		assert.Zero(t, transport.calls.Load())
	})

	t.Run("unparseable base url", func(t *testing.T) {
		transport := &coverageCancelTransport{cancel: func() {}}
		gl := &GitLabSyncer{projectID: "1", token: "t", baseURL: "://bad", httpClient: &http.Client{Transport: transport}}

		err := gl.SyncKey(ctx, &provider.Secret{Key: "K", Value: "v"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gitlab: parse base url")

		err = gl.createVariable(ctx, "K", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gitlab: parse base url")

		names, err := gl.ExistingKeys(ctx)
		require.Error(t, err)
		assert.Nil(t, names)
		assert.Contains(t, err.Error(), "gitlab: parse base url")
		assert.Zero(t, transport.calls.Load())
	})

	t.Run("create failing with a server error is returned for reconciliation", func(t *testing.T) {
		var methods []string
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			methods = append(methods, r.Method)
			mu.Unlock()
			if r.Method == http.MethodPut {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		gl := &GitLabSyncer{projectID: "1", token: "t", baseURL: server.URL, httpClient: server.Client()}

		err := gl.SyncKey(ctx, &provider.Secret{Key: "/a/K", Value: "value-123"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMutationNeedsReconciliation)
		var status *HTTPStatusError
		require.ErrorAs(t, err, &status)
		assert.Equal(t, http.StatusInternalServerError, status.StatusCode)
		assert.Contains(t, err.Error(), `gitlab: create "K"`)
		assert.NotContains(t, err.Error(), "masking requirements")
		assert.NotContains(t, err.Error(), "value-123")
		assert.Equal(t, []string{http.MethodPut, http.MethodPost}, methods)
	})

	t.Run("listing is forbidden", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()
		gl := &GitLabSyncer{projectID: "1", token: "t", baseURL: server.URL, httpClient: server.Client()}

		names, err := gl.ExistingKeys(ctx)
		require.Error(t, err)
		assert.Nil(t, names)
		assert.Contains(t, err.Error(), "gitlab: list variables: status 403")
	})

	t.Run("listing returns malformed json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"not":"a list"`)
		}))
		defer server.Close()
		gl := &GitLabSyncer{projectID: "1", token: "t", baseURL: server.URL, httpClient: server.Client()}

		names, err := gl.ExistingKeys(ctx)
		require.Error(t, err)
		assert.Nil(t, names)
		assert.Contains(t, err.Error(), "gitlab: decode variables")
	})
}

func TestCloudflareSyncer_SyncPagesRejectsDestinationCollision(t *testing.T) {
	transport := &coverageCancelTransport{cancel: func() {}}
	c := &CloudflareSyncer{accountID: "acc", pages: "site", token: "t", baseURL: "http://cloudflare.invalid", httpClient: &http.Client{Transport: transport}}
	err := c.syncPages(context.Background(), []*provider.Secret{{Key: "/a/K", Value: "1"}, {Key: "/b/K", Value: "2"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is produced by distinct source keys")
	assert.Zero(t, transport.calls.Load())
}

// coverageGateTransport holds every mutation inside RoundTrip until release is
// closed, so a test can fill a syncer's bounded worker pool deterministically.
type coverageGateTransport struct {
	entered   chan struct{}
	release   chan struct{}
	mutations atomic.Int32
	publicKey string
}

func newCoverageGateTransport(capacity int) *coverageGateTransport {
	return &coverageGateTransport{entered: make(chan struct{}, capacity), release: make(chan struct{})}
}

func (g *coverageGateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		body := fmt.Sprintf(`{"key_id":"key-1","key":%q}`, g.publicKey)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	}
	g.mutations.Add(1)
	g.entered <- struct{}{}
	<-g.release
	status := http.StatusOK
	if req.Method == http.MethodPut && strings.Contains(req.URL.Path, "/actions/secrets/") {
		status = http.StatusNoContent
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
}

// coverageGoroutines counts goroutines whose stack contains every fragment.
func coverageGoroutines(fragments ...string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, stack := range strings.Split(string(buf), "\n\n") {
		matched := true
		for _, fragment := range fragments {
			if !strings.Contains(stack, fragment) {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}
	return count
}

func coverageEventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// coverageRunSaturatedSync starts sync with twelve secrets against a pool of
// ten, waits until ten mutations are in flight and the dispatcher is parked in
// WaitGroup.Wait, cancels, and waits for the two queued workers to observe the
// cancellation (the pool is full, so ctx.Done is their only ready case).
func coverageRunSaturatedSync(t *testing.T, gate *coverageGateTransport, workerFrame, dispatcherFrame string, run func(context.Context, []*provider.Secret) error) error {
	t.Helper()
	const poolSize, total = 10, 12
	secrets := make([]*provider.Secret, 0, total)
	for i := range total {
		secrets = append(secrets, &provider.Secret{Key: fmt.Sprintf("/app/K%02d", i), Value: "v"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, secrets) }()

	for range poolSize {
		select {
		case <-gate.entered:
		case <-time.After(20 * time.Second):
			close(gate.release)
			t.Fatal("timed out waiting for in-flight mutations")
		}
	}
	coverageEventually(t, "dispatcher to wait for workers", func() bool {
		return coverageGoroutines(dispatcherFrame, "(*WaitGroup).Wait") == 1
	})
	cancel()
	coverageEventually(t, "queued workers to observe cancellation", func() bool {
		return coverageGoroutines(workerFrame) == poolSize
	})
	close(gate.release)
	err := <-done
	assert.Equal(t, int32(poolSize), gate.mutations.Load())
	return err
}

func TestCloudflareSyncer_SyncWorkerQueuedSecretsObserveCancellation(t *testing.T) {
	gate := newCoverageGateTransport(12)
	c := &CloudflareSyncer{accountID: "acc", worker: "w", token: "t", baseURL: "http://cloudflare.invalid", httpClient: &http.Client{Transport: gate}}
	err := coverageRunSaturatedSync(t, gate, "(*CloudflareSyncer).syncWorker.func1(", "(*CloudflareSyncer).syncWorker(", c.Sync)
	assert.Equal(t, context.Canceled, err)
}

func TestGitHubSyncer_SyncQueuedSecretsObserveCancellation(t *testing.T) {
	publicKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	gate := newCoverageGateTransport(12)
	gate.publicKey = base64.StdEncoding.EncodeToString(publicKey[:])
	g := &GitHubSyncer{owner: "o", repo: "r", token: "t", baseURL: "http://github.invalid", httpClient: &http.Client{Transport: gate}}
	err = coverageRunSaturatedSync(t, gate, "(*GitHubSyncer).Sync.func1(", "(*GitHubSyncer).Sync(", g.Sync)
	assert.Equal(t, context.Canceled, err)
}

func TestEnvelope_RemainingValidationBranches(t *testing.T) {
	now := replayTestTime()
	_, privateKey := replayTestKeys(t)
	validManifestDigest := "sha256:" + strings.Repeat("a", 64)

	t.Run("canonical bytes reject unsupported version", func(t *testing.T) {
		envelope, err := BuildSignedEnvelope(validManifestDigest, "operator", "hub", "nonce-version", now.Add(time.Minute), []byte("payload"), privateKey, now)
		require.NoError(t, err)
		envelope.Version = 99
		canonical, err := envelope.CanonicalSigningBytes()
		require.Error(t, err)
		assert.Nil(t, canonical)
	})

	client := &EnvelopeClient{
		BaseURL:               "http://hub.invalid",
		Signer:                privateKey,
		OperatorSessionCookie: "session=synthetic",
		Clock:                 func() time.Time { return now },
	}

	t.Run("submit rejects an invalid manifest digest", func(t *testing.T) {
		response, err := client.Submit(t.Context(), "bad", "operator", "hub", "nonce-digest", now.Add(time.Minute), []byte("payload"))
		require.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "manifest digest")
	})

	t.Run("submit reports request creation failure without values", func(t *testing.T) {
		var missingCtx context.Context
		response, err := client.Submit(missingCtx, validManifestDigest, "operator", "hub", "nonce-request", now.Add(time.Minute), []byte("payload"))
		require.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, "envelope: request creation failed", err.Error())
	})

	t.Run("expiry that cannot be encoded", func(t *testing.T) {
		err := validateExpiry(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), now)
		require.Error(t, err)
		assert.Equal(t, "envelope: invalid expiry", err.Error())
	})

	t.Run("digest with a short hex body", func(t *testing.T) {
		assert.False(t, validDigest("sha256:abcd"))
		assert.True(t, validDigest(validManifestDigest))
	})
}

func TestStateManifest_RemainingVerificationBranches(t *testing.T) {
	root, publicKey, privateKey, now := coverageManifestFixture(t)
	manifest, err := BuildStateManifest(root, "operator", "hub", "nonce-remaining", now.Add(time.Minute), privateKey, now)
	require.NoError(t, err)

	err = VerifyStateManifest(manifest, root, "", "hub", publicKey, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role")

	err = VerifyStateManifest(manifest, root, "operator", "", publicKey, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")

	err = VerifyStateManifest(manifest, filepath.Join(root, "missing"), "operator", "hub", publicKey, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source root")

	truncated := *manifest
	truncated.Signature = append([]byte(nil), manifest.Signature[:10]...)
	err = VerifyStateManifest(&truncated, root, "operator", "hub", publicKey, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")

	require.NoError(t, VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now))
}

func TestStateManifest_FieldValidatorsRejectBoundaryValues(t *testing.T) {
	err := validateStateManifestRootField("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source root")

	err = validateStateManifestTimestamp(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	require.Error(t, err)
	assert.Equal(t, "state manifest: invalid expiry", err.Error())
}

func TestStateManifest_UnsafeAncestorsRejectMissingAndLinkedRoots(t *testing.T) {
	// The temp dir itself may sit under a symlinked ancestor (darwin's /var
	// -> /private/var), which the check rightly rejects; start from its real
	// path so only the link created below is unsafe.
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	err = rejectStateManifestUnsafeAncestors(filepath.Join(base, "missing"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source root")

	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(base, "link")
	faultDirLink(t, link, target)
	err = rejectStateManifestUnsafeAncestors(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe source roots are not allowed")

	require.NoError(t, rejectStateManifestUnsafeAncestors(target))
}

func TestStateManifest_PortableScanHelpersAcceptStableEntries(t *testing.T) {
	dir := t.TempDir()
	dirInfo, err := os.Lstat(dir)
	require.NoError(t, err)
	require.NoError(t, revalidateStateManifestDirectories(map[string]os.FileInfo{dir: dirInfo}))

	other := t.TempDir()
	otherInfo, err := os.Lstat(other)
	require.NoError(t, err)
	err = revalidateStateManifestDirectories(map[string]os.FileInfo{dir: otherInfo})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source directories changed during scan")

	content := []byte("portable manifest content")
	path := filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	fileInfo, err := os.Lstat(path)
	require.NoError(t, err)
	size, digest, err := hashStateManifestFile(path, fileInfo)
	require.NoError(t, err)
	sum := sha256.Sum256(content)
	assert.Equal(t, int64(len(content)), size)
	assert.Equal(t, hex.EncodeToString(sum[:]), digest)
}

func TestAtomicWrite_ReportsChmodAndReplaceFailures(t *testing.T) {
	t.Run("closed temporary file cannot be secured", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "out.env")
		err := atomicWrite(target, dir, ".tmp-*", func(f *os.File) error { return f.Close() })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chmod")
		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		assert.Empty(t, entries)
	})

	t.Run("target that is a non-empty directory cannot be replaced", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "out.env")
		require.NoError(t, os.Mkdir(target, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(target, "keep"), []byte("keep"), 0o600))
		err := atomicWrite(target, dir, ".tmp-*", func(f *os.File) error {
			_, writeErr := f.WriteString("K=v\n")
			return writeErr
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rename")
		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		require.Len(t, entries, 1)
		assert.Equal(t, "out.env", entries[0].Name())
		assert.Equal(t, []byte("keep"), mustReadFile(t, filepath.Join(target, "keep")))
	})
}

func TestLoadDeploySalt_ReportsFilesystemFailures(t *testing.T) {
	t.Run("no home directory", func(t *testing.T) {
		coverageWithoutHome(t)
		salt, err := LoadDeploySalt()
		require.Error(t, err)
		assert.Nil(t, salt)
		assert.Contains(t, err.Error(), "user home dir")
	})

	t.Run("salt path is a directory", func(t *testing.T) {
		home := withFakeHome(t)
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".skret", "hub-salt"), 0o700))
		salt, err := LoadDeploySalt()
		require.Error(t, err)
		assert.Nil(t, salt)
		assert.Contains(t, err.Error(), "read hub salt")
	})

	t.Run("skret directory cannot be created", func(t *testing.T) {
		blocked := t.TempDir()
		coverageSetHome(t, filepath.Join(blocked, "home"))
		faultBlockCreate(t, blocked)
		salt, err := LoadDeploySalt()
		require.Error(t, err)
		assert.Nil(t, salt)
		assert.Contains(t, err.Error(), "create skret dir")
		assert.NoDirExists(t, filepath.Join(blocked, "home"))
	})

	t.Run("temporary salt path is a directory", func(t *testing.T) {
		home := withFakeHome(t)
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".skret", "hub-salt.tmp"), 0o700))
		salt, err := LoadDeploySalt()
		require.Error(t, err)
		assert.Nil(t, salt)
		assert.Contains(t, err.Error(), "write hub salt")
		assert.NoFileExists(t, filepath.Join(home, ".skret", "hub-salt"))
	})

	t.Run("short salt cannot be replaced", func(t *testing.T) {
		home := withFakeHome(t)
		skretDir := filepath.Join(home, ".skret")
		require.NoError(t, os.MkdirAll(skretDir, 0o700))
		saltPath := filepath.Join(skretDir, "hub-salt")
		require.NoError(t, os.WriteFile(saltPath, []byte("short"), 0o600))
		require.NoError(t, os.WriteFile(saltPath+".tmp", nil, 0o600))
		faultBlockRemoval(t, saltPath)

		salt, err := LoadDeploySalt()
		require.Error(t, err)
		assert.Nil(t, salt)
		assert.Contains(t, err.Error(), "rename hub salt")
		assert.Equal(t, []byte("short"), mustReadFile(t, saltPath))
		assert.Len(t, mustReadFile(t, saltPath+".tmp"), 16)
	})
}

func TestAcquireTargetLock_ReportsFilesystemFailures(t *testing.T) {
	t.Run("no home directory", func(t *testing.T) {
		coverageWithoutHome(t)
		release, err := AcquireTargetLock("github", "owner/repo")
		require.Error(t, err)
		assert.Nil(t, release)
		assert.Contains(t, err.Error(), "user home dir")
	})

	t.Run("skret path is a file", func(t *testing.T) {
		home := withFakeHome(t)
		require.NoError(t, os.WriteFile(filepath.Join(home, ".skret"), []byte("not a directory"), 0o600))
		release, err := AcquireTargetLock("github", "owner/repo")
		require.Error(t, err)
		assert.Nil(t, release)
		assert.Contains(t, err.Error(), "create sync lock dir")
	})

	t.Run("lock path is a directory", func(t *testing.T) {
		withFakeHome(t)
		statePath, err := StatePathFor("github", "owner/repo")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(statePath+".lock", 0o700))
		release, err := AcquireTargetLock("github", "owner/repo")
		require.Error(t, err)
		assert.Nil(t, release)
		assert.Contains(t, err.Error(), "open sync target lock")
		assert.DirExists(t, statePath+".lock")
	})
}

func TestValidateDestinationMapping_OnlyAppliesToNameKeyedTargets(t *testing.T) {
	duplicates := []*provider.Secret{{Key: "/a/K", Value: "1"}, {Key: "/b/K", Value: "2"}}
	assert.NoError(t, ValidateDestinationMapping("dotenv", duplicates))

	err := ValidateDestinationMapping("github", []*provider.Secret{nil})
	require.Error(t, err)
	assert.Equal(t, "github: secret is nil", err.Error())
}

func TestCanonicalTargetIdentity_DefaultsAndInvalidEndpoints(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)

	identity, err := CanonicalTargetIdentity(TargetConfig{Type: "dotenv", Fields: map[string]string{}})
	require.NoError(t, err)
	assert.Equal(t, "dotenv|"+canonicalTargetPart(filepath.Join(wd, ".env")), identity)

	identity, err = CanonicalTargetIdentity(TargetConfig{Type: "terraform", Fields: map[string]string{}})
	require.NoError(t, err)
	assert.Equal(t, "terraform|"+canonicalTargetPart(filepath.Join(wd, "terraform.tfvars")), identity)

	_, err = CanonicalTargetIdentity(TargetConfig{Type: "gitlab", Fields: map[string]string{"project": "group/app", "base_url": "://bad"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gitlab target base_url")

	assert.NoError(t, ValidateTargetIdentities([]TargetConfig{
		{Type: "github", Fields: map[string]string{"repo": "owner/one"}},
		{Type: "github", Fields: map[string]string{"repo": "owner/two"}},
	}))
}

func TestValidHCLIdentifier_RejectsEmptyName(t *testing.T) {
	assert.False(t, validHCLIdentifier(""))
	assert.True(t, validHCLIdentifier("_name-1"))
}

func TestK8sSyncer_StdoutWriteFailure(t *testing.T) {
	readOnly, err := os.CreateTemp(t.TempDir(), "stdout-*")
	require.NoError(t, err)
	name := readOnly.Name()
	require.NoError(t, readOnly.Close())
	readOnly, err = os.Open(name)
	require.NoError(t, err)
	defer readOnly.Close()

	orig := os.Stdout
	os.Stdout = readOnly
	defer func() { os.Stdout = orig }()

	err = NewK8s("-", "app-secrets", "").Sync(context.Background(), []*provider.Secret{{Key: "API_KEY", Value: "sk-123"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "k8s: write stdout")
	assert.NotContains(t, err.Error(), "sk-123")
	assert.Empty(t, mustReadFile(t, name))
}
