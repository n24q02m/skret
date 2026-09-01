//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package secretlaunch

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unsupportedUnixSignal string

func (unsupportedUnixSignal) Signal()               {}
func (signal unsupportedUnixSignal) String() string { return string(signal) }

func TestResolveUnixChildUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantUID int
		wantGID int
		wantErr bool
	}{
		{name: "numeric uid defaults gid", value: "123", wantUID: 123, wantGID: 123},
		{name: "numeric uid and gid", value: "123:456", wantUID: 123, wantGID: 456},
		{name: "negative uid", value: "-1", wantErr: true},
		{name: "negative gid", value: "123:-1", wantErr: true},
		{name: "invalid numeric gid", value: "123:not-a-gid", wantErr: true},
		{name: "too many components", value: "1:2:3", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uid, gid, err := resolveUser(test.value)
			if test.wantErr {
				assert.Equal(t, ErrChild, errorCode(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantUID, uid)
			assert.Equal(t, test.wantGID, gid)
		})
	}
}

func TestResolveUnixChildUserByAccountName(t *testing.T) {
	t.Parallel()

	account, err := user.Current()
	require.NoError(t, err)
	wantUID, err := strconv.Atoi(account.Uid)
	require.NoError(t, err)
	wantGID, err := strconv.Atoi(account.Gid)
	require.NoError(t, err)

	uid, gid, err := resolveUser(account.Username)
	require.NoError(t, err)
	assert.Equal(t, wantUID, uid)
	assert.Equal(t, wantGID, gid)

	uid, gid, err = resolveUser(account.Username + ":321")
	require.NoError(t, err)
	assert.Equal(t, wantUID, uid)
	assert.Equal(t, 321, gid)
}

func TestApplyUnixChildUserSetsExactCredential(t *testing.T) {
	t.Parallel()

	command := &exec.Cmd{}
	require.NoError(t, applyChildUser(command, "123:456"))
	require.NotNil(t, command.SysProcAttr)
	require.NotNil(t, command.SysProcAttr.Credential)
	assert.True(t, command.SysProcAttr.Setpgid)
	assert.Equal(t, uint32(123), command.SysProcAttr.Credential.Uid)
	assert.Equal(t, uint32(456), command.SysProcAttr.Credential.Gid)
}

func TestUnixProcessTreeSignalFallbacksFailClosed(t *testing.T) {
	t.Parallel()

	current, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	assert.Error(t, signalProcessTree(current, unsupportedUnixSignal("unsupported")))

	missing, err := os.FindProcess(1 << 30)
	require.NoError(t, err)
	assert.Error(t, signalProcessTree(missing, syscall.SIGTERM))
	assert.Error(t, killProcessTree(missing))
}

func TestUnixProcessTreeSignalsOwnedGroup(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		stop func(*execChild) error
	}{
		{name: "signal", stop: func(child *execChild) error {
			return child.Signal(syscall.SIGTERM)
		}},
		{name: "kill", stop: (*execChild).KillTree},
	} {
		t.Run(test.name, func(t *testing.T) {
			binary, err := exec.LookPath("sleep")
			require.NoError(t, err)
			command := exec.CommandContext(t.Context(), binary, "30")
			require.NoError(t, configureProcessGroup(command))
			require.NoError(t, command.Start())
			t.Cleanup(func() { _ = command.Process.Kill() })

			require.NoError(t, test.stop(&execChild{command: command}))
			assert.Error(t, command.Wait())
		})
	}
}
