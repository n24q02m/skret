package exec_test

import (
	"errors"
	"os"
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
