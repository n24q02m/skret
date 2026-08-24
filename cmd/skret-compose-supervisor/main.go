package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/n24q02m/skret/internal/config"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/secretlaunch"
)

const maxCommandOutputBytes = 8 << 20

var errCommandOutputLimit = errors.New("command output limit exceeded")

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if b.exceeded {
		return 0, errCommandOutputLimit
	}
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return 0, errCommandOutputLimit
	}
	if len(value) > remaining {
		_, _ = b.Buffer.Write(value[:remaining])
		b.exceeded = true
		return remaining, errCommandOutputLimit
	}
	return b.Buffer.Write(value)
}

func (b *boundedBuffer) overflowed() bool { return b.exceeded }

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr boundedBuffer
	stdout.limit = maxCommandOutputBytes
	stderr.limit = maxCommandOutputBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.overflowed() || stderr.overflowed() {
		return stdout.Bytes(), stderr.Bytes(), errCommandOutputLimit
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

type attachRunner struct{}

func (attachRunner) Attach(ctx context.Context, name string, args ...string) (io.ReadWriteCloser, error) {
	command := exec.CommandContext(ctx, name, args...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	return &attachedStream{Reader: stdout, WriteCloser: stdin, command: command}, nil
}

type attachedStream struct {
	io.Reader
	io.WriteCloser
	command *exec.Cmd
}

func (s *attachedStream) Close() error {
	if s == nil {
		return nil
	}
	_ = s.WriteCloser.Close()
	if s.command != nil && s.command.Process != nil {
		_ = s.command.Process.Kill()
	}
	if s.command != nil {
		return s.command.Wait()
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, nil, nil))
}

func run(args []string, diagnostics io.Writer, runtime secretlaunch.Runtime, injected secretlaunch.SecretProvider) int {
	ctx, stop := signal.NotifyContext(context.Background())
	defer stop()
	return runContext(ctx, args, diagnostics, runtime, injected)
}

func runContext(
	ctx context.Context,
	args []string,
	diagnostics io.Writer,
	runtime secretlaunch.Runtime,
	injected secretlaunch.SecretProvider,
) int {
	flags := flag.NewFlagSet("skret-compose-supervisor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "signed launch manifest path")
	trustPath := flags.String("trust", "", "trust allowlist path")
	runtimeID := flags.String("runtime", "", "explicit runtime binding")
	composePath := flags.String("compose", "", "metadata-only rendered model path")
	invokeDocker := flags.Bool("invoke-docker", false, "explicitly allow Docker CLI calls")
	dockerBinary := flags.String("docker-binary", "", "absolute Docker CLI path")
	dockerDigest := flags.String("docker-sha256", "", "signed Docker CLI digest")
	providerName := flags.String("provider", "aws", "exact-version provider")
	providerPath := flags.String("provider-path", "", "provider namespace path")
	region := flags.String("region", "", "provider region")
	profile := flags.String("profile", "", "provider profile")
	kmsKeyID := flags.String("kms-key-id", "", "provider KMS key identifier")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(diagnostics, "compose supervisor: invalid arguments")
		return 2
	}
	if *manifestPath == "" || *trustPath == "" || *runtimeID == "" || *composePath == "" || flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "compose supervisor: manifest, trust, runtime, and compose are required")
		return 2
	}
	if !*invokeDocker && runtime == nil {
		fmt.Fprintln(diagnostics, secretlaunchError(secretlaunch.ErrNotInvoked))
		return 2
	}
	signed, err := secretlaunch.ReadRegularFile(*manifestPath, secretlaunch.MaxSignedManifestBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, "compose supervisor: manifest unavailable")
		return 1
	}
	defer secretlaunch.Zeroize(signed)
	trustBytes, err := secretlaunch.ReadRegularFile(*trustPath, secretlaunch.MaxTrustDocumentBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, "compose supervisor: trust unavailable")
		return 1
	}
	policy, err := secretlaunch.LoadTrustDocument(trustBytes)
	secretlaunch.Zeroize(trustBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	manifest, err := secretlaunch.VerifySignedManifest(signed, policy, timeNow())
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	if manifest.RuntimeID != *runtimeID {
		fmt.Fprintln(diagnostics, secretlaunchError(secretlaunch.ErrBinding))
		return 1
	}
	executable, err := os.Executable()
	if err != nil || secretlaunch.VerifyRegularFileDigest(executable, manifest.Digests.Supervisor, 256<<20) != nil {
		fmt.Fprintln(diagnostics, "compose supervisor: executable binding rejected")
		return 1
	}
	modelBytes, err := secretlaunch.ReadRegularFile(*composePath, secretlaunch.MaxRenderedModelBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, "compose supervisor: model unavailable")
		return 1
	}
	model, err := secretlaunch.ParseRenderedModel(modelBytes)
	secretlaunch.Zeroize(modelBytes)
	if err != nil || secretlaunch.ValidateManifestModel(manifest, model) != nil {
		fmt.Fprintln(diagnostics, secretlaunchError(secretlaunch.ErrBinding))
		return 1
	}

	provider := injected
	var closeProvider func() error
	if provider == nil {
		if *providerName != "aws" || *providerPath == "" {
			fmt.Fprintln(diagnostics, secretlaunchError(secretlaunch.ErrNoProvider))
			return 1
		}
		base, providerErr := skaws.New(&config.ResolvedConfig{
			Provider: "aws", Path: *providerPath, Region: *region, Profile: *profile, KMSKeyID: *kmsKeyID,
		})
		if providerErr != nil {
			fmt.Fprintln(diagnostics, secretlaunchError(secretlaunch.ErrNoProvider))
			return 1
		}
		closeProvider = base.Close
		adapted, adapterErr := secretlaunch.NewSkretProvider(base)
		if adapterErr != nil {
			_ = base.Close()
			fmt.Fprintln(diagnostics, adapterErr)
			return 1
		}
		provider = adapted
	}
	if closeProvider != nil {
		defer closeProvider()
	}
	if runtime == nil {
		if !filepath.IsAbs(*dockerBinary) || *dockerDigest == "" ||
			secretlaunch.VerifyRegularFileDigest(*dockerBinary, *dockerDigest, 256<<20) != nil {
			fmt.Fprintln(diagnostics, secretlaunchError(secretlaunch.ErrRuntime))
			return 1
		}
		runtime = secretlaunch.NewDockerRuntime(*dockerBinary, commandRunner{}, attachRunner{}, *invokeDocker)
	}
	supervisor := secretlaunch.NewSupervisor(runtime, provider)
	defer supervisor.Close()
	if err := supervisor.Run(ctx, model, manifest); err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	return 0
}

func secretlaunchError(code secretlaunch.ErrorCode) error {
	return &secretlaunch.LaunchError{Code: code}
}

func timeNow() time.Time { return time.Now() }
