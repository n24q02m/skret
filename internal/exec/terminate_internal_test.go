package exec

import (
	osexec "os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Terminating a command that never started is a no-op: there is no process
// to signal and nothing will ever arrive on done.
func TestTerminate_NotStartedIsNoOp(t *testing.T) {
	done := make(chan error, 1)
	start := time.Now()
	terminate(&osexec.Cmd{}, done, time.Minute)
	assert.Less(t, time.Since(start), 30*time.Second, "must not wait for the grace period")
	assert.Empty(t, done)
}
