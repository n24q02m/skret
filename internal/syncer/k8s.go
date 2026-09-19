package syncer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
	"gopkg.in/yaml.v3"
)

// K8sSyncer renders secrets as a Kubernetes Secret manifest (stringData, so
// values are written as plaintext for the cluster to base64-encode on
// apply). It generates YAML only -- it never talks to a cluster; applying
// the file stays the operator's job (kubectl/flux/argo).
type K8sSyncer struct {
	// filePath is the output path; "" or "-" streams the manifest to stdout.
	filePath string
	// secretName is metadata.name of the generated Secret.
	secretName string
	// namespace, when set, is emitted as metadata.namespace.
	namespace string
}

// K8sManifestAlias is accepted as a synonym for the k8s target type so both
// spellings resolve to the same syncer and canonical identity.
const K8sManifestAlias = "k8s-manifest"

// NewK8s creates a Secret-manifest syncer. An empty secretName defaults to
// skret-secrets; an empty filePath (or "-") targets stdout.
func NewK8s(filePath, secretName, namespace string) Syncer {
	if filePath == "" {
		filePath = "-"
	}
	if secretName == "" {
		secretName = "skret-secrets"
	}
	return &K8sSyncer{filePath: filePath, secretName: secretName, namespace: namespace}
}

func (k *K8sSyncer) Name() string { return "k8s" }

// validK8sSecretKey enforces the Kubernetes Secret data key charset
// (alphanumerics, dashes, underscores, dots).
func validK8sSecretKey(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// validDNSSubdomain checks RFC 1123 subdomain syntax (metadata.name and
// metadata.namespace shape).
func validDNSSubdomain(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

type k8sObjectMeta struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace,omitempty"`
}

type k8sSecretManifest struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   k8sObjectMeta     `yaml:"metadata"`
	Type       string            `yaml:"type"`
	StringData map[string]string `yaml:"stringData"`
}

func (k *K8sSyncer) render(secrets []*provider.Secret) ([]byte, error) {
	stringData := make(map[string]string, len(secrets))
	nameToKey := make(map[string]string, len(secrets))
	for _, s := range secrets {
		name := SecretName(s.Key)
		if !validK8sSecretKey(name) {
			return nil, fmt.Errorf("k8s: key %q is not a valid Secret data key (only alphanumerics, '-', '_' and '.' are allowed); rename the provider key so its last segment is valid", name)
		}
		if prev, ok := nameToKey[name]; ok && prev != s.Key {
			return nil, fmt.Errorf("k8s: Secret data key %q is produced by two distinct keys %q and %q; rename one so secrets are not silently lost", name, prev, s.Key)
		}
		nameToKey[name] = s.Key
		stringData[name] = s.Value
	}
	manifest := k8sSecretManifest{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata:   k8sObjectMeta{Name: k.secretName, Namespace: k.namespace},
		Type:       "Opaque",
		StringData: stringData,
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) // conventional k8s manifest indentation
	if err := enc.Encode(&manifest); err != nil {
		return nil, fmt.Errorf("k8s: marshal manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("k8s: marshal manifest: %w", err)
	}
	return buf.Bytes(), nil
}

func (k *K8sSyncer) Sync(_ context.Context, secrets []*provider.Secret) error {
	out, err := k.render(secrets)
	if err != nil {
		return err
	}
	if k.filePath == "-" {
		_, err := fmt.Fprint(os.Stdout, string(out))
		if err != nil {
			return fmt.Errorf("k8s: write stdout: %w", err)
		}
		return nil
	}
	dir := filepath.Dir(k.filePath)
	return atomicWrite(k.filePath, dir, ".skret-sync-*.yaml", func(f *os.File) error {
		_, err := f.Write(out)
		return err
	})
}

func init() {
	Register("k8s", newK8sFromConfig)
	Register(K8sManifestAlias, newK8sFromConfig)
}

func newK8sFromConfig(tc TargetConfig) (Syncer, error) {
	name := field(tc, "name")
	if name == "" {
		name = "skret-secrets"
	}
	if !validDNSSubdomain(name) {
		return nil, fmt.Errorf("k8s: name %q is not a valid DNS subdomain (metadata.name)", name)
	}
	ns := field(tc, "namespace")
	if ns != "" && !validDNSSubdomain(ns) {
		return nil, fmt.Errorf("k8s: namespace %q is not a valid DNS subdomain (metadata.namespace)", ns)
	}
	return NewK8s(field(tc, "file"), name, ns), nil
}
