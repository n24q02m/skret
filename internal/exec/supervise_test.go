package exec_test

import (
	"context"
	"errors"
	"os"
	osexec "os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain lets the test binary act as a controllable child when SKRET_TEST_CHILD
// is set, so supervise tests can spawn a real, portable subprocess by
// re-invoking os.Args[0] instead of relying on sleep/go run.
func TestMain(m *testing.M) {
	switch os.Getenv("SKRET_TEST_CHILD") {
	case "sleep":
		time.Sleep(30 * time.Second) // killed by the test
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	case "print":
		// Write fixed text to stdout and stderr, then exit with a chosen code.
		_, _ = os.Stdout.WriteString(os.Getenv("SKRET_TEST_STDOUT"))
		_, _ = os.Stderr.WriteString(os.Getenv("SKRET_TEST_STDERR"))
		code, _ := strconv.Atoi(os.Getenv("SKRET_TEST_EXIT"))
		os.Exit(code)
	case "waitterm":
		// Report readiness, then exit 42 once SIGTERM arrives.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM)
		_, _ = os.Stdout.WriteString("ready\n")
		select {
		case <-sigCh:
			_, _ = os.Stdout.WriteString("terminated\n")
			os.Exit(42)
		case <-time.After(30 * time.Second):
			os.Exit(3)
		}
	case "selfkill":
		self, _ := os.FindProcess(os.Getpid())
		_ = self.Kill()
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "orphan":
		// Leave a grandchild holding the inherited stdout open, record its
		// pid for cleanup, and exit successfully.
		gc := osexec.CommandContext(context.Background(), os.Args[0])
		gc.Env = append(os.Environ(), "SKRET_TEST_CHILD=sleep")
		gc.Stdout = os.Stdout
		if err := gc.Start(); err != nil {
			os.Exit(4)
		}
		_ = os.WriteFile(os.Getenv("SKRET_TEST_READY"), []byte(strconv.Itoa(gc.Process.Pid)), 0o600)
		os.Exit(0)
	case "ignoreterm":
		// Ignore SIGTERM, then tell the test it is safe to send it.
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(os.Getenv("SKRET_TEST_READY"), nil, 0o600); err != nil {
			os.Exit(3)
		}
		time.Sleep(30 * time.Second) // killed by the test
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func childEnv(mode string) []string {
	return append(os.Environ(), "SKRET_TEST_CHILD="+mode)
}

func TestSupervise_NaturalExit(t *testing.T) {
	child, err := skexec.Supervise(os.Args[0], []string{os.Args[0]}, childEnv("exit7"))
	require.NoError(t, err)

	waitErr := <-child.Done()
	assert.Equal(t, 7, skexec.ExitCode(waitErr))
}

func TestSupervise_Terminate(t *testing.T) {
	child, err := skexec.Supervise(os.Args[0], []string{os.Args[0]}, childEnv("sleep"))
	require.NoError(t, err)

	start := time.Now()
	child.Terminate(2 * time.Second)

	select {
	case <-child.Done():
		assert.Less(t, time.Since(start), 25*time.Second, "child should stop well before the 30s sleep")
	case <-time.After(25 * time.Second):
		t.Fatal("child did not exit after Terminate")
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"non-exit-error", errors.New("boom"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, skexec.ExitCode(tt.err))
		})
	}
}

func TestSupervise_BadBinary(t *testing.T) {
	_, err := skexec.Supervise("this-binary-does-not-exist-xyz", []string{"x"}, nil)
	assert.Error(t, err)
}
