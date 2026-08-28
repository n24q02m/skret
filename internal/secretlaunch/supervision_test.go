package secretlaunch

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
)

type oneShotWaitChild struct {
	mu         sync.Mutex
	done       chan struct{}
	waitCalls  int
	terminated bool
	waited     bool
	killErr    error
	code       int
}

func newOneShotWaitChild(killErr error) *oneShotWaitChild {
	return &oneShotWaitChild{done: make(chan struct{}), killErr: killErr}
}

func (c *oneShotWaitChild) Wait() error {
	c.mu.Lock()
	c.waitCalls++
	if c.waitCalls > 1 {
		c.mu.Unlock()
		return errors.New("wait called twice")
	}
	done := c.done
	c.mu.Unlock()
	<-done
	c.mu.Lock()
	c.waited = true
	c.mu.Unlock()
	return nil
}

func (c *oneShotWaitChild) Signal(os.Signal) error { return nil }

func (c *oneShotWaitChild) KillTree() error {
	c.mu.Lock()
	if !c.terminated {
		c.terminated = true
		c.code = 137
		close(c.done)
	}
	err := c.killErr
	c.mu.Unlock()
	return err
}

func (c *oneShotWaitChild) ExitCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

type oneShotStarter struct {
	child ChildProcess
}

func (s *oneShotStarter) Start(_ context.Context, _ ChildSpec, _ SecretSet) (ChildProcess, error) {
	return s.child, nil
}

func (c *oneShotWaitChild) snapshot() (waitCalls int, terminated bool, waited bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waitCalls, c.terminated, c.waited
}

func TestHelperReapsAbortedChildThroughExactlyOneWaitOwner(t *testing.T) {
	for name, killErr := range map[string]error{
		"kill succeeds":      nil,
		"kill reports error": errors.New("synthetic kill failure"),
	} {
		t.Run(name, func(t *testing.T) {
			manifest, signed, policy, _ := signedFixture(t)
			child := newOneShotWaitChild(killErr)
			starter := &oneShotStarter{child: child}
			helper, err := NewHelper(signed, policy, starter)
			if err != nil {
				t.Fatal(err)
			}
			if err := helper.Bind(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api"}); err != nil {
				t.Fatal(err)
			}
			wire, sender, receiver := secretWire(t, manifest)
			defer sender.Close()
			defer receiver.Close()
			_, runErr := helper.Run(context.Background(), bytes.NewReader(wire), receiver)
			calls, terminated, waited := child.snapshot()
			if calls != 1 {
				t.Fatalf("Wait calls=%d, want exactly one owner", calls)
			}
			if !terminated || !waited {
				t.Fatalf("child teardown terminated=%v waited=%v", terminated, waited)
			}
			if killErr == nil {
				if errorCode(runErr) != ErrLifecycle {
					t.Fatalf("abort error code=%v, want lifecycle", errorCode(runErr))
				}
			} else if errorCode(runErr) != ErrChild {
				t.Fatalf("kill failure code=%v, want child", errorCode(runErr))
			}
			Zeroize(wire)
		})
	}
}
