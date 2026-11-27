package exec_test

import (
	"bytes"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a bytes.Buffer safe to read while RunFiltered writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunFiltered_RoutesOutputAndPreservesExitCode(t *testing.T) {
	for _, code := range []int{0, 3, 77} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			env := append(childEnv("print"),
				"SKRET_TEST_STDOUT=to stdout",
				"SKRET_TEST_STDERR=to stderr",
				"SKRET_TEST_EXIT="+strconv.Itoa(code))

			err := skexec.RunFiltered(os.Args[0], []string{os.Args[0]}, env, &stdout, &stderr)

			assert.Equal(t, "to stdout", stdout.String())
			assert.Equal(t, "to stderr", stderr.String())
			assert.Equal(t, code, skexec.ExitCode(err))
			if code == 0 {
				require.NoError(t, err)
			}
		})
	}
}

func TestRunFiltered_StartFailureIsNotAnExitError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-binary")
	err := skexec.RunFiltered(missing, []string{missing}, os.Environ(), &bytes.Buffer{}, &bytes.Buffer{})
	require.Error(t, err)
	var exitErr *osexec.ExitError
	assert.False(t, errors.As(err, &exitErr))
}

// A child killed by a signal reports the shell convention 128+signal on Unix;
// on Windows a killed process simply exits with code 1.
func TestRunFiltered_KilledChildExitCode(t *testing.T) {
	err := skexec.RunFiltered(os.Args[0], []string{os.Args[0]}, childEnv("selfkill"), &bytes.Buffer{}, &bytes.Buffer{})
	require.Error(t, err)
	var coder interface{ ExitCode() int }
	require.True(t, errors.As(err, &coder))
	want := 1
	if runtime.GOOS != "windows" {
		want = 128 + 9 // SIGKILL
		assert.Contains(t, err.Error(), "killed")
	}
	assert.Equal(t, want, coder.ExitCode())
}

// A grandchild that keeps the output pipe open must not hang RunFiltered
// after the child itself has exited successfully.
func TestRunFiltered_DoesNotWaitForPipeHolders(t *testing.T) {
	defer skexec.SetFilteredWaitDelay(200 * time.Millisecond)()
	ready := filepath.Join(t.TempDir(), "pid")
	env := append(childEnv("orphan"), "SKRET_TEST_READY="+ready)

	start := time.Now()
	err := skexec.RunFiltered(os.Args[0], []string{os.Args[0]}, env, &syncBuffer{}, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 20*time.Second)

	raw, readErr := os.ReadFile(ready)
	require.NoError(t, readErr)
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, convErr)
	if p, findErr := os.FindProcess(pid); findErr == nil {
		_ = p.Kill()
	}
}

func TestInjectedValue(t *testing.T) {
	assert.Equal(t, "plain", skexec.InjectedValue("plain"))
	assert.Equal(t, "a b c", skexec.InjectedValue("a\nb\r\nc\x00"))
}
