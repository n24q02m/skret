package secretlaunch

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type ChildProcess interface {
	Wait() error
	Signal(os.Signal) error
	KillTree() error
	ExitCode() int
}

type ChildStarter interface {
	Start(ctx context.Context, spec ChildSpec, values SecretSet) (ChildProcess, error)
}

type StartFunc func(context.Context, ChildSpec, SecretSet) (ChildProcess, error)

func (f StartFunc) Start(ctx context.Context, spec ChildSpec, values SecretSet) (ChildProcess, error) {
	if f == nil {
		return nil, fail(ErrChild)
	}
	return f(ctx, spec, values)
}

type ExecStarter struct{}

func (ExecStarter) Start(ctx context.Context, spec ChildSpec, values SecretSet) (ChildProcess, error) {
	if len(spec.Argv) == 0 {
		return nil, fail(ErrChild)
	}
	if err := disableDumps(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	if err := validateSecretEnvironment(values); err != nil {
		return nil, err
	}
	// The helper's stdin/stdout carry the encrypted control channel. The child
	// must not inherit that channel or it could consume protocol frames or
	// corrupt heartbeats with application output. Nil stdio maps to the
	// platform null device in os/exec.
	command.Env = filteredEnvironment(os.Environ(), spec.Environment, values)
	if err := configureProcessGroup(command); err != nil {
		return nil, err
	}
	if err := applyChildUser(command, spec.User); err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, fail(ErrChild)
	}
	return &execChild{command: command}, nil
}

type execChild struct {
	command *exec.Cmd
}

func (c *execChild) Wait() error {
	if c == nil || c.command == nil {
		return fail(ErrChild)
	}
	return c.command.Wait()
}

func (c *execChild) Signal(signal os.Signal) error {
	if c == nil || c.command == nil || c.command.Process == nil {
		return fail(ErrChild)
	}
	if err := signalProcessTree(c.command.Process, signal); err != nil {
		return fail(ErrChild)
	}
	return nil
}

func (c *execChild) KillTree() error {
	if c == nil || c.command == nil || c.command.Process == nil {
		return fail(ErrChild)
	}
	if err := killProcessTree(c.command.Process); err != nil {
		return fail(ErrChild)
	}
	return nil
}

func (c *execChild) ExitCode() int {
	if c == nil || c.command == nil || c.command.ProcessState == nil {
		return -1
	}
	return c.command.ProcessState.ExitCode()
}

func validateSecretEnvironment(values SecretSet) error {
	for _, item := range values.items {
		name := item.Env
		if name == "" {
			name = item.Key
		}
		if !validEnvName(name) {
			return failKey(ErrKey, item.Key)
		}
	}
	return nil
}

func filteredEnvironment(parent []string, declared map[string]string, values SecretSet) []string {
	environment := make(map[string]string, len(declared)+values.Len()+8)
	allowedParent := map[string]bool{
		"HOME": true, "HOSTNAME": true, "LANG": true, "LC_ALL": true,
		"LC_CTYPE": true, "PATH": true, "SSL_CERT_DIR": true,
		"SSL_CERT_FILE": true, "TZ": true,
	}
	for _, entry := range parent {
		name, value, ok := strings.Cut(entry, "=")
		if ok && allowedParent[name] {
			environment[name] = value
		}
	}
	for name, value := range declared {
		environment[name] = value
	}
	for _, item := range values.items {
		envName := item.Env
		if envName == "" {
			envName = item.Key
		}
		environment[envName] = string(item.Bytes)
	}
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+environment[name])
	}
	return result
}
