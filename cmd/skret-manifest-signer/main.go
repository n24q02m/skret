// Command skret-manifest-signer re-signs a previously signed launch manifest
// with a fresh validity window. It never changes launch authority: the
// template is verified against the trust document, may not be older than
// --max-age, and the result is verified and bound to the rendered model before
// it atomically replaces the output file. Intended to run as a short-lived
// oneshot (for example a systemd timer) beside the compose supervisor.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/n24q02m/skret/internal/secretlaunch"
)

const defaultTTL = 10 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, time.Now))
}

func run(args []string, diagnostics io.Writer, now func() time.Time) int {
	flags := flag.NewFlagSet("skret-manifest-signer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	templatePath := flags.String("template", "", "previously signed manifest used as the authority template")
	trustPath := flags.String("trust", "", "trust allowlist path")
	keyPath := flags.String("key", "", "Ed25519 signing key file (mode 0600 or stricter)")
	modelPath := flags.String("model", "", "metadata-only rendered model path")
	outPath := flags.String("out", "", "output manifest path (atomically replaced)")
	ttl := flags.Duration("ttl", defaultTTL, "validity window of the renewed manifest")
	maxAge := flags.Duration("max-age", 0, "refuse to renew a template signed longer ago than this")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(diagnostics, "manifest signer: invalid arguments")
		return 2
	}
	if *templatePath == "" || *trustPath == "" || *keyPath == "" || *modelPath == "" || *outPath == "" ||
		*maxAge <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "manifest signer: template, trust, key, model, out, and max-age are required")
		return 2
	}
	if err := renew(*templatePath, *trustPath, *keyPath, *modelPath, *outPath, *ttl, *maxAge, now(), diagnostics); err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	return 0
}

func renew(
	templatePath, trustPath, keyPath, modelPath, outPath string,
	ttl, maxAge time.Duration,
	now time.Time,
	diagnostics io.Writer,
) error {
	private, err := secretlaunch.ReadSigningKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("manifest signer: signing key %q: %w", keyPath, err)
	}
	defer secretlaunch.Zeroize(private)
	template, err := secretlaunch.ReadRegularFile(templatePath, secretlaunch.MaxSignedManifestBytes)
	if err != nil {
		return fmt.Errorf("manifest signer: template %q: %w", templatePath, err)
	}
	defer secretlaunch.Zeroize(template)
	trustBytes, err := secretlaunch.ReadRegularFile(trustPath, secretlaunch.MaxTrustDocumentBytes)
	if err != nil {
		return fmt.Errorf("manifest signer: trust %q: %w", trustPath, err)
	}
	policy, err := secretlaunch.LoadTrustDocument(trustBytes)
	secretlaunch.Zeroize(trustBytes)
	if err != nil {
		return fmt.Errorf("manifest signer: trust %q: %w", trustPath, err)
	}
	modelBytes, err := secretlaunch.ReadRegularFile(modelPath, secretlaunch.MaxRenderedModelBytes)
	if err != nil {
		return fmt.Errorf("manifest signer: model %q: %w", modelPath, err)
	}
	model, err := secretlaunch.ParseRenderedModel(modelBytes)
	secretlaunch.Zeroize(modelBytes)
	if err != nil {
		return fmt.Errorf("manifest signer: model %q: %w", modelPath, err)
	}

	signed, err := secretlaunch.RenewSignedManifest(template, policy, private, now, ttl, maxAge)
	if err != nil {
		return fmt.Errorf("manifest signer: renew %q: %w", templatePath, err)
	}
	// Verify what is about to be published exactly as the supervisor will.
	manifest, err := secretlaunch.VerifySignedManifest(signed, policy, now)
	if err != nil {
		return fmt.Errorf("manifest signer: verify renewed manifest: %w", err)
	}
	if err := secretlaunch.ValidateManifestModel(manifest, model); err != nil {
		return fmt.Errorf("manifest signer: bind renewed manifest to model %q: %w", modelPath, err)
	}
	// The manifest holds identities and digests only, never secret values.
	if err := secretlaunch.WriteFileAtomic(outPath, signed, 0o644); err != nil {
		return fmt.Errorf("manifest signer: write %q: %w", outPath, err)
	}
	parsed, err := secretlaunch.ParseSignedManifest(signed)
	if err != nil {
		return fmt.Errorf("manifest signer: parse renewed manifest: %w", err)
	}
	fmt.Fprintf(diagnostics, "manifest signer: renewed runtime=%s generation=%d key=%s expires=%s\n",
		manifest.RuntimeID, manifest.Generation, parsed.KeyID, time.Unix(manifest.ExpiresAt, 0).UTC().Format(time.RFC3339))
	return nil
}
