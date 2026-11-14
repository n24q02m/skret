// Package syncsource resolves the secret set a sync target receives.
//
// A target without declared sources receives the environment path, exactly
// as `skret sync` always did. A target with sources receives the union of
// every source: each source is one provider path, filtered by an allow list
// (keys) or a deny list (exclude), plus the top-level exclude list. The same
// union is what `--prune` compares the target against, so a name kept on
// purpose has to be declared, not merely present somewhere.
package syncsource

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
)

// ErrInvalidSources marks a declaration that cannot produce a well-defined
// set: two sources on one path, two sources yielding one destination name,
// or a declared key the provider does not have.
var ErrInvalidSources = errors.New("syncsource: invalid sources")

// ErrList marks a provider listing failure for one source path.
var ErrList = errors.New("syncsource: list failed")

// Lister is the provider capability a collector needs.
type Lister interface {
	List(ctx context.Context, path string) ([]*provider.Secret, error)
}

// Set is the resolved source set of one target.
type Set struct {
	// Secrets is the union, source by source in declaration order, each
	// source in provider listing order.
	Secrets []*provider.Secret
	// Paths are the resolved source paths in declaration order.
	Paths []string
	// Empty lists the paths that produced no secret after filtering.
	Empty []string
}

// Identity names the source set for state journals and reports. For a
// target without declared sources it is the environment path.
func (s *Set) Identity() string { return strings.Join(s.Paths, ",") }

// Collector resolves source sets, listing each provider path at most once
// per run so targets sharing a path see the same snapshot.
type Collector struct {
	lister  Lister
	envPath string
	exclude []string
	listed  map[string][]*provider.Secret
}

// NewCollector returns a collector over lister. envPath is the environment
// path (the default source); exclude is the top-level exclude list, applied
// to every source.
func NewCollector(lister Lister, envPath string, exclude []string) *Collector {
	return &Collector{lister: lister, envPath: envPath, exclude: exclude, listed: map[string][]*provider.Secret{}}
}

// Collect resolves the set for one target. nil sources means the
// environment path alone.
func (c *Collector) Collect(ctx context.Context, sources []syncer.SourceSpec) (*Set, error) {
	if sources == nil {
		sources = []syncer.SourceSpec{{}}
	}
	paths := make([]string, len(sources))
	seen := make(map[string]bool, len(sources))
	for i := range sources {
		path := cleanPath(sources[i].Path, c.envPath)
		if seen[path] {
			return nil, fmt.Errorf("%w: duplicate source path %q", ErrInvalidSources, path)
		}
		seen[path] = true
		paths[i] = path
	}

	set := &Set{Paths: paths}
	origin := map[string]string{} // destination name -> source path
	var dupes []string
	for i := range sources {
		listed, err := c.list(ctx, paths[i])
		if err != nil {
			return nil, err
		}
		kept, err := filter(listed, paths[i], c.exclude, &sources[i])
		if err != nil {
			return nil, err
		}
		if len(kept) == 0 {
			set.Empty = append(set.Empty, paths[i])
		}
		for _, sec := range kept {
			name := syncer.SecretName(sec.Key)
			if prev, ok := origin[name]; ok && prev != paths[i] {
				dupes = append(dupes, name)
				continue
			}
			origin[name] = paths[i]
		}
		set.Secrets = append(set.Secrets, kept...)
	}
	if len(dupes) > 0 {
		sort.Strings(dupes)
		return nil, fmt.Errorf("%w: destination names produced by more than one source: %s", ErrInvalidSources, strings.Join(dupes, ", "))
	}
	return set, nil
}

func (c *Collector) list(ctx context.Context, path string) ([]*provider.Secret, error) {
	if cached, ok := c.listed[path]; ok {
		return cached, nil
	}
	secrets, err := c.lister.List(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrList, path, err)
	}
	c.listed[path] = secrets
	return secrets, nil
}

// cleanPath defaults an empty path to the environment path and drops
// trailing slashes (keeping a bare "/").
func cleanPath(path, envPath string) string {
	if path == "" {
		path = envPath
	}
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	return path
}

// filter applies the top-level exclude list and the source's own keys or
// exclude list, matching on the env-var name the key resolves to under
// path (the same matching `skret run` and `skret env` use). It returns a
// new slice and never mutates the cached listing.
func filter(listed []*provider.Secret, path string, globalExclude []string, src *syncer.SourceSpec) ([]*provider.Secret, error) {
	drop := upperSet(globalExclude)
	for name := range upperSet(src.Exclude) {
		drop[name] = true
	}
	want := upperSet(src.Keys)

	out := make([]*provider.Secret, 0, len(listed))
	found := make(map[string]bool, len(want))
	for _, sec := range listed {
		name := exec.KeyToEnvName(sec.Key, path)
		if drop[name] {
			continue
		}
		if len(want) > 0 {
			if !want[name] {
				continue
			}
			found[name] = true
		}
		out = append(out, sec)
	}

	var missing []string
	for name := range want {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: source %q has no key(s): %s", ErrInvalidSources, path, strings.Join(missing, ", "))
	}
	return out, nil
}

func upperSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[strings.ToUpper(n)] = true
	}
	return set
}
