package syncer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
)

// TerraformSyncer writes secrets to a terraform.tfvars / *.auto.tfvars file
// (HCL). The file is managed wholesale -- like dotenv, every sync rewrites
// it atomically with exactly the synced keys, sorted by name.
type TerraformSyncer struct {
	filePath string
}

// NewTerraform creates a tfvars file syncer. An empty path defaults to
// terraform.tfvars.
func NewTerraform(filePath string) Syncer {
	if filePath == "" {
		filePath = "terraform.tfvars"
	}
	return &TerraformSyncer{filePath: filePath}
}

func (t *TerraformSyncer) Name() string { return "terraform" }

// validHCLIdentifier matches HCL2 identifier rules for the subset terraform
// accepts as a variable name: start with a letter or underscore, then
// letters, digits, underscores or dashes.
func validHCLIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			// always allowed
		case r >= '0' && r <= '9', r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// hclQuote renders s as a quoted HCL string literal. Only the escapes HCL
// defines are emitted (\", \\, \n, \r, \t and \uNNNN for control
// characters); everything else passes through byte-for-byte.
func hclQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (t *TerraformSyncer) Sync(_ context.Context, secrets []*provider.Secret) error {
	// The written variable name is the target-side SecretName (last path
	// segment), the same name `sync --dry-run`, dotenv, github and gitlab
	// use. Collisions are checked before opening the file so a detected
	// clash leaves no partial output.
	type assignment struct {
		name, value string
	}
	assignments := make([]assignment, 0, len(secrets))
	nameToKey := make(map[string]string, len(secrets))
	for _, s := range secrets {
		name := SecretName(s.Key)
		if !validHCLIdentifier(name) {
			return fmt.Errorf("terraform: %q is not a valid terraform variable name (HCL identifiers start with a letter or underscore, then letters, digits, underscores or dashes); rename the provider key so its last segment is valid", name)
		}
		if prev, ok := nameToKey[name]; ok && prev != s.Key {
			return fmt.Errorf("terraform: variable %q is produced by two distinct keys %q and %q; rename one so secrets are not silently lost", name, prev, s.Key)
		}
		nameToKey[name] = s.Key
		assignments = append(assignments, assignment{name: name, value: s.Value})
	}
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].name < assignments[j].name })

	dir := filepath.Dir(t.filePath)
	return atomicWrite(t.filePath, dir, ".skret-sync-*.tfvars", func(f *os.File) error {
		for _, a := range assignments {
			if _, err := fmt.Fprintf(f, "%s = %s\n", a.name, hclQuote(a.value)); err != nil {
				return err
			}
		}
		return nil
	})
}

func init() { Register("terraform", newTerraformFromConfig) }

func newTerraformFromConfig(tc TargetConfig) (Syncer, error) {
	return NewTerraform(field(tc, "file")), nil
}
